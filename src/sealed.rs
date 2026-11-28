//! Authenticated encryption at rest for sensitive credentials (AES-256-GCM).
//!
//! [`SealedBox`] provides a versioned, Base64 envelope (`enc:v1:<base64>`) around
//! AES-256-GCM ciphertext with an explicit nonce and optional additional
//! authenticated data (AAD). It is designed for persisting OAuth session tokens,
//! refresh tokens, and private DPoP keys in embedded databases.
//!
//! Legacy migration helpers ([`SealedBox::open`] and [`SealedBox::open_with_aad`])
//! pass through unprefixed plaintext values and fall back to empty AAD for records
//! sealed prior to AAD binding, whereas [`SealedBox::open_strict_with_aad`] and
//! [`SealedBox::open_string_strict_with_aad`] require the envelope prefix and
//! exact AAD match.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use rand::Rng;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::crypto::sha256_digest;
use crate::error::CryptoError;

/// Prefix identifying AES-256-GCM sealed payloads (`enc:v1:...`).
pub const SEALED_ENVELOPE_PREFIX: &str = "enc:v1:";

/// AES-256-GCM key plus versioned envelope helpers for encrypting data at rest.
///
/// # Memory Zeroization
/// [`SealedBox`] derives [`Zeroize`] and [`ZeroizeOnDrop`], wiping the 256-bit
/// key material from memory when dropped or explicitly zeroized.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SealedBox {
    key: [u8; 32],
}

impl std::fmt::Debug for SealedBox {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealedBox")
            .field("key", &"[REDACTED]")
            .finish()
    }
}

impl SealedBox {
    /// Creates a sealing box from a raw 256-bit key.
    #[must_use]
    pub fn new(key: [u8; 32]) -> Self {
        Self { key }
    }

    /// Generates a fresh [`SealedBox`] with a cryptographically random 256-bit key.
    ///
    /// # Examples
    /// ```
    /// use skyauth::sealed::SealedBox;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let cipher = SealedBox::generate();
    /// let sealed = cipher.seal_with_aad(b"secret", b"did:plc:alice")?;
    /// let opened = cipher.open_string_strict_with_aad(&sealed, b"did:plc:alice")?;
    /// assert_eq!(opened.as_str(), "secret");
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn generate() -> Self {
        let mut sealed = Self { key: [0u8; 32] };
        rand::rng().fill_bytes(&mut sealed.key);
        sealed
    }

    /// Derives a 256-bit key from an arbitrary secret passphrase using SHA-256.
    #[must_use]
    pub fn from_secret_passphrase(secret: &str) -> Self {
        Self {
            key: sha256_digest(secret.as_bytes()),
        }
    }

    /// Exports the 256-bit key as a 64-character lowercase hex string wrapped in [`Zeroizing`].
    ///
    /// # Examples
    /// ```
    /// use skyauth::sealed::SealedBox;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let cipher = SealedBox::generate();
    /// let hex_key = cipher.to_hex();
    /// assert_eq!(hex_key.len(), 64);
    /// let restored = SealedBox::from_hex(&hex_key)?;
    /// let sealed = cipher.seal_with_aad(b"payload", b"aad")?;
    /// assert_eq!(restored.open_string_strict_with_aad(&sealed, b"aad")?.as_str(), "payload");
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn to_hex(&self) -> Zeroizing<String> {
        const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";
        let mut out = Zeroizing::new(String::with_capacity(64));
        for &byte in &self.key {
            out.push(HEX_LOWER[(byte >> 4) as usize] as char);
            out.push(HEX_LOWER[(byte & 0x0f) as usize] as char);
        }
        out
    }

    /// Parses a 64-character hex-encoded 256-bit key.
    ///
    /// # Errors
    /// Returns [`CryptoError::InvalidKey`] if `hex` is not exactly 64 hex characters.
    pub fn from_hex(hex: &str) -> Result<Self, CryptoError> {
        let bytes = hex.as_bytes();
        if bytes.len() != 64 {
            return Err(CryptoError::InvalidKey(format!(
                "Expected a 64-character hex key, got {} characters",
                bytes.len()
            )));
        }
        let key = bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|chunk| {
                let pair = std::str::from_utf8(chunk)
                    .map_err(|e| CryptoError::InvalidKey(format!("Key is not valid UTF-8: {e}")))?;
                u8::from_str_radix(pair, 16)
                    .map_err(|e| CryptoError::InvalidKey(format!("Key is not valid hex: {e}")))
            })
            .collect::<Result<Vec<u8>, CryptoError>>()?
            .try_into()
            .map_err(|_| CryptoError::InvalidKey("Key must decode to 32 bytes".to_string()))?;
        Ok(Self { key })
    }

    /// Seals `plaintext` into an [`SEALED_ENVELOPE_PREFIX`] Base64 envelope.
    ///
    /// # Errors
    /// Returns [`CryptoError::Rng`] if nonce generation fails or
    /// [`CryptoError::Seal`] if encryption fails.
    pub fn seal(&self, plaintext: &[u8]) -> Result<String, CryptoError> {
        self.seal_with_aad(plaintext, &[])
    }

    /// Seals `plaintext` with additional authenticated data (AAD).
    ///
    /// The AAD is authenticated but not encrypted; supplying a different AAD at
    /// [`Self::open_with_aad`] time fails authentication.
    ///
    /// # Errors
    /// Returns [`CryptoError::Rng`] if nonce generation fails or
    /// [`CryptoError::Seal`] if encryption fails.
    pub fn seal_with_aad(&self, plaintext: &[u8], aad: &[u8]) -> Result<String, CryptoError> {
        let cipher = Aes256Gcm::new_from_slice(&self.key)
            .map_err(|e| CryptoError::InvalidKey(format!("Invalid AES-256-GCM key: {e}")))?;

        let mut nonce_bytes = [0u8; 12];
        rand::rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from(nonce_bytes);

        let payload = Payload {
            msg: plaintext,
            aad,
        };
        let ciphertext = cipher
            .encrypt(&nonce, payload)
            .map_err(|e| CryptoError::Seal(format!("AES-256-GCM sealing failed: {e}")))?;

        // Payload layout: 12-byte nonce || ciphertext || 16-byte tag
        let mut combined = Vec::with_capacity(12 + ciphertext.len());
        combined.extend_from_slice(&nonce_bytes);
        combined.extend_from_slice(&ciphertext);

        Ok(format!(
            "{SEALED_ENVELOPE_PREFIX}{}",
            STANDARD.encode(combined)
        ))
    }

    fn decrypt_envelope(
        &self,
        encoded: &str,
        aad: &[u8],
        allow_empty_aad_fallback: bool,
    ) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        let combined = STANDARD
            .decode(encoded)
            .map_err(|e| CryptoError::Base64Decode(format!("Sealed payload Base64 decode: {e}")))?;

        // 12-byte nonce + 16-byte tag minimum.
        if combined.len() < 28 {
            return Err(CryptoError::InvalidEnvelope(
                "Sealed payload is truncated".to_string(),
            ));
        }

        let (nonce_bytes, ciphertext) = combined.split_at(12);
        let mut nonce_arr = [0u8; 12];
        nonce_arr.copy_from_slice(nonce_bytes);
        let nonce = Nonce::from(nonce_arr);
        let cipher = Aes256Gcm::new_from_slice(&self.key)
            .map_err(|e| CryptoError::InvalidKey(format!("Invalid AES-256-GCM key: {e}")))?;

        let decrypt = |associated: &[u8]| -> Result<Zeroizing<Vec<u8>>, CryptoError> {
            cipher
                .decrypt(
                    &nonce,
                    Payload {
                        msg: ciphertext,
                        aad: associated,
                    },
                )
                .map(Zeroizing::new)
                .map_err(|_| {
                    CryptoError::Open(
                        "Authentication tag mismatch or invalid key while opening sealed payload"
                            .to_string(),
                    )
                })
        };

        match decrypt(aad) {
            Ok(plaintext) => Ok(plaintext),
            Err(err) if allow_empty_aad_fallback && !aad.is_empty() => decrypt(&[]).or(Err(err)),
            Err(err) => Err(err),
        }
    }

    /// Opens a sealed envelope, or passes through a legacy plaintext value unchanged.
    ///
    /// # Errors
    /// Returns [`CryptoError::Base64Decode`] for malformed Base64,
    /// [`CryptoError::InvalidEnvelope`] for truncated payloads, or
    /// [`CryptoError::Open`] if authentication fails.
    pub fn open(&self, raw: &str) -> Result<Vec<u8>, CryptoError> {
        self.open_with_aad(raw, &[])
    }

    /// Opens a sealed envelope with AAD, or passes through legacy plaintext unchanged.
    ///
    /// When AAD is supplied, opening first attempts the given AAD and then falls
    /// back to empty AAD for backward compatibility with records sealed before AAD
    /// was introduced.
    ///
    /// # Errors
    /// Returns [`CryptoError::Base64Decode`] for malformed Base64,
    /// [`CryptoError::InvalidEnvelope`] for truncated payloads, or
    /// [`CryptoError::Open`] if authentication fails under both AADs.
    pub fn open_with_aad(&self, raw: &str, aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let raw = raw.trim();
        let Some(encoded) = raw.strip_prefix(SEALED_ENVELOPE_PREFIX) else {
            // Legacy unencrypted payload; pass through directly.
            return Ok(raw.as_bytes().to_vec());
        };

        let mut plaintext = self.decrypt_envelope(encoded, aad, true)?;
        Ok(std::mem::take(&mut *plaintext))
    }

    /// Strictly opens a sealed envelope with exact AAD verification and returns the
    /// plaintext wrapped in [`Zeroizing`].
    ///
    /// Unlike [`Self::open_with_aad`], this method:
    /// 1. Rejects payloads missing [`SEALED_ENVELOPE_PREFIX`] with [`CryptoError::InvalidEnvelope`]
    ///    instead of passing unsealed plaintext through.
    /// 2. Does **not** fall back to empty AAD when `aad` authentication fails.
    ///
    /// # Errors
    /// Returns [`CryptoError::InvalidEnvelope`] if the [`SEALED_ENVELOPE_PREFIX`] is
    /// missing or the payload is truncated, [`CryptoError::Base64Decode`] for
    /// malformed Base64, or [`CryptoError::Open`] if authentication fails for `aad`.
    ///
    /// # Examples
    /// ```
    /// use skyauth::sealed::SealedBox;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let cipher = SealedBox::generate();
    /// let sealed = cipher.seal_with_aad(b"token-bytes", b"did:plc:alice")?;
    /// let plain = cipher.open_strict_with_aad(&sealed, b"did:plc:alice")?;
    /// assert_eq!(plain.as_slice(), b"token-bytes");
    /// assert!(cipher.open_strict_with_aad("unsealed-plaintext", b"did:plc:alice").is_err());
    /// # Ok(())
    /// # }
    /// ```
    pub fn open_strict_with_aad(
        &self,
        raw: &str,
        aad: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        let raw = raw.trim();
        let encoded = raw.strip_prefix(SEALED_ENVELOPE_PREFIX).ok_or_else(|| {
            CryptoError::InvalidEnvelope(format!(
                "Missing required sealed envelope prefix '{SEALED_ENVELOPE_PREFIX}'"
            ))
        })?;
        self.decrypt_envelope(encoded, aad, false)
    }

    /// Opens a sealed envelope and decodes the plaintext as UTF-8, or passes
    /// through a legacy plaintext string unchanged.
    ///
    /// # Errors
    /// Propagates [`Self::open`] failures, or returns [`CryptoError::Utf8`] if the
    /// decrypted bytes are not valid UTF-8.
    pub fn open_string(&self, raw: &str) -> Result<String, CryptoError> {
        self.open_string_with_aad(raw, &[])
    }

    /// Opens a sealed envelope with AAD and decodes the plaintext as UTF-8.
    ///
    /// # Errors
    /// Propagates [`Self::open_with_aad`] failures, or returns [`CryptoError::Utf8`]
    /// if the decrypted bytes are not valid UTF-8.
    pub fn open_string_with_aad(&self, raw: &str, aad: &[u8]) -> Result<String, CryptoError> {
        let bytes = self.open_with_aad(raw, aad)?;
        String::from_utf8(bytes).map_err(|e| CryptoError::Utf8(e.to_string()))
    }

    /// Strictly opens a sealed envelope with exact AAD verification and decodes
    /// the plaintext as UTF-8 wrapped in [`Zeroizing`].
    ///
    /// Rejects unsealed plaintext and empty-AAD fallback identically to
    /// [`Self::open_strict_with_aad`]. UTF-8 validation runs over the borrowed
    /// [`Zeroizing`] byte buffer before copying into a preallocated
    /// [`Zeroizing<String>`] so error paths also zeroize decrypted bytes.
    ///
    /// # Errors
    /// Propagates [`Self::open_strict_with_aad`] failures, or returns
    /// [`CryptoError::Utf8`] if the decrypted bytes are not valid UTF-8.
    ///
    /// # Examples
    /// ```
    /// use skyauth::sealed::SealedBox;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let cipher = SealedBox::generate();
    /// let sealed = cipher.seal_with_aad(b"refresh-token", b"did:plc:alice")?;
    /// let text = cipher.open_string_strict_with_aad(&sealed, b"did:plc:alice")?;
    /// assert_eq!(text.as_str(), "refresh-token");
    /// # Ok(())
    /// # }
    /// ```
    pub fn open_string_strict_with_aad(
        &self,
        raw: &str,
        aad: &[u8],
    ) -> Result<Zeroizing<String>, CryptoError> {
        let bytes = self.open_strict_with_aad(raw, aad)?;
        let text = std::str::from_utf8(&bytes).map_err(|e| CryptoError::Utf8(e.to_string()))?;
        let mut out = Zeroizing::new(String::with_capacity(text.len()));
        out.push_str(text);
        Ok(out)
    }
}
