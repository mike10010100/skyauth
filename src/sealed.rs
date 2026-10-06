//! Authenticated encryption at rest for sensitive credentials (AES-256-GCM).
//!
//! [`SealedBox`] provides a versioned, Base64 envelope (`enc:v1:<base64>`) around
//! AES-256-GCM ciphertext with an explicit nonce and optional additional
//! authenticated data (AAD). It is designed for persisting OAuth session tokens,
//! refresh tokens, and private DPoP keys in embedded databases.
//!
//! Plaintext values that do not carry the envelope prefix are passed through
//! unchanged, allowing transparent migration from legacy unencrypted records.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use rand::RngCore;

use crate::crypto::sha256_digest;
use crate::error::CryptoError;

/// Prefix identifying AES-256-GCM sealed payloads (`enc:v1:...`).
pub const SEALED_ENVELOPE_PREFIX: &str = "enc:v1:";

/// AES-256-GCM key plus versioned envelope helpers for encrypting data at rest.
#[derive(Clone)]
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

    /// Derives a 256-bit key from an arbitrary secret passphrase using SHA-256.
    #[must_use]
    pub fn from_secret_passphrase(secret: &str) -> Self {
        Self {
            key: sha256_digest(secret.as_bytes()),
        }
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
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
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

        let decrypt = |associated: &[u8]| -> Result<Vec<u8>, CryptoError> {
            cipher
                .decrypt(
                    &nonce,
                    Payload {
                        msg: ciphertext,
                        aad: associated,
                    },
                )
                .map_err(|_| {
                    CryptoError::Open(
                        "Authentication tag mismatch or invalid key while opening sealed payload"
                            .to_string(),
                    )
                })
        };

        match decrypt(aad) {
            Ok(plaintext) => Ok(plaintext),
            Err(err) if !aad.is_empty() => decrypt(&[]).or(Err(err)),
            Err(err) => Err(err),
        }
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
}
