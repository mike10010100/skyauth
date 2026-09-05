//! Decentralized Identity and Handle Resolution Engine.
//!
//! Implements AT Protocol identity primitives:
//! - **Handle Resolution**: Syntax verification, lowercase ASCII normalization,
//!   DNS TXT record resolution (`_atproto.<handle>`), and HTTPS fallback (`/.well-known/atproto-did`).
//! - **DID Resolution**: `did:plc` resolution via PLC Directory and `did:web` via `/.well-known/did.json`.
//! - **DID Document Verification**: Bidirectional handle validation against `alsoKnownAs`,
//!   `#atproto_pds` service endpoint extraction, and cryptographic verification method parsing.

use serde::{Deserialize, Serialize};
use std::sync::Arc;
use url::Url;

use crate::error::{IdentityError, SsrfError};
use crate::ssrf::{SsrfFilter, MAX_OAUTH_RESPONSE_BYTES};

/// Standard PLC directory endpoint.
pub const DEFAULT_PLC_DIRECTORY: &str = "https://plc.directory";

/// Supported AT Protocol Decentralized Identifier (DID) methods.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DidMethod {
    /// `did:plc` cryptographic identifier (default for Bluesky/ATProto).
    Plc,
    /// `did:web` web-domain-based identifier.
    Web,
}

/// A verification method containing public cryptographic keys in a DID Document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationMethod {
    /// Identifier fragment or URI (e.g. `#atproto` or `did:plc:123#atproto`).
    pub id: String,
    /// Key type (e.g. `"Multikey"`, `"EcdsaSecp256k1VerificationKey2019"`, `"EcdsaSecp256r1VerificationKey2019"`).
    #[serde(rename = "type")]
    pub key_type: String,
    /// Controller DID.
    pub controller: String,
    /// Multibase-encoded public key string.
    #[serde(default, rename = "publicKeyMultibase")]
    pub public_key_multibase: Option<String>,
}

/// A service endpoint declared in a DID Document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DidService {
    /// Service identifier (e.g. `"#atproto_pds"` or `did:plc:123#atproto_pds`).
    pub id: String,
    /// Service type (must be `"AtprotoPersonalDataServer"` for PDS).
    #[serde(rename = "type")]
    pub service_type: String,
    /// Fully qualified service endpoint URL (e.g. `"https://pds.example.com"`).
    #[serde(rename = "serviceEndpoint")]
    pub service_endpoint: String,
}

/// Canonical W3C DID Document representation for AT Protocol accounts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DidDocument {
    /// The primary Decentralized Identifier.
    pub id: String,
    /// Alternative identifiers claimed by this DID (e.g. `["at://alice.bsky.social"]`).
    #[serde(default, rename = "alsoKnownAs")]
    pub also_known_as: Vec<String>,
    /// Verification methods (public signing keys).
    #[serde(default, rename = "verificationMethod")]
    pub verification_method: Vec<VerificationMethod>,
    /// Service endpoints declared by the account.
    #[serde(default)]
    pub service: Vec<DidService>,
}

impl DidDocument {
    /// Asserts that the DID Document's `id` matches the expected queried DID.
    ///
    /// # Errors
    /// Returns [`IdentityError::DidDocumentIdMismatch`] if the identifiers do not match.
    pub fn validate_id(&self, expected_did: &str) -> Result<(), IdentityError> {
        if self.id == expected_did {
            Ok(())
        } else {
            Err(IdentityError::DidDocumentIdMismatch {
                expected: expected_did.to_string(),
                actual: self.id.clone(),
            })
        }
    }

    /// Checks whether this DID Document asserts bidirectional linkage to `handle`
    /// via its `alsoKnownAs` list (e.g. `at://<handle>`).
    #[must_use]
    pub fn matches_handle(&self, handle: &str) -> bool {
        let normalized = handle.trim().trim_start_matches('@').to_ascii_lowercase();
        let expected_uri = format!("at://{normalized}");
        self.also_known_as
            .iter()
            .any(|aka| aka.to_ascii_lowercase() == expected_uri)
    }

    /// Verifies bidirectional handle linkage against `alsoKnownAs`.
    ///
    /// # Errors
    /// Returns [`IdentityError::HandleDidMismatch`] if bidirectional linkage is missing.
    pub fn verify_handle_bidirectional(&self, handle: &str) -> Result<(), IdentityError> {
        if self.matches_handle(handle) {
            Ok(())
        } else {
            Err(IdentityError::HandleDidMismatch(handle.to_string()))
        }
    }

    /// Extracts the authoritative `#atproto_pds` Personal Data Server endpoint URL.
    ///
    /// # Errors
    /// - Returns [`IdentityError::MissingPdsEndpoint`] if no `#atproto_pds` service of type
    ///   `AtprotoPersonalDataServer` is found.
    /// - Returns [`IdentityError::InvalidPdsEndpoint`] if the service endpoint is not a valid URL.
    pub fn extract_pds_endpoint(&self) -> Result<String, IdentityError> {
        let pds_service = self.service.iter().find(|s| {
            (s.id == "#atproto_pds" || s.id.ends_with("#atproto_pds"))
                && s.service_type == "AtprotoPersonalDataServer"
        });

        match pds_service {
            Some(svc) => {
                let trimmed = svc.service_endpoint.trim().trim_end_matches('/');
                let parsed = Url::parse(trimmed)
                    .map_err(|e| IdentityError::InvalidPdsEndpoint(format!("{trimmed}: {e}")))?;
                if parsed.scheme() != "https" && parsed.scheme() != "http" {
                    return Err(IdentityError::InvalidPdsEndpoint(format!(
                        "Invalid scheme in PDS endpoint '{trimmed}'"
                    )));
                }
                Ok(trimmed.to_string())
            }
            None => Err(IdentityError::MissingPdsEndpoint(self.id.clone())),
        }
    }

    /// Extracts the primary signing key (`#atproto`) from the verification methods.
    #[must_use]
    pub fn extract_signing_key(&self) -> Option<&VerificationMethod> {
        self.verification_method
            .iter()
            .find(|vm| vm.id == "#atproto" || vm.id.ends_with("#atproto"))
    }
}

/// Resolved decentralized identity bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedIdentity {
    /// Authenticated subject DID.
    pub did: String,
    /// Verified account handle, if resolved from handle.
    pub handle: Option<String>,
    /// Full W3C DID document.
    pub did_doc: DidDocument,
    /// Extracted `#atproto_pds` personal data server endpoint URL.
    pub pds_endpoint: String,
}

/// Validates and normalizes an AT Protocol handle string.
///
/// # Rules (ATProto Handle Specification):
/// - Strips leading `@` character.
/// - Converts to lowercase ASCII.
/// - Maximum total length: 244 characters.
/// - At least two dot-separated labels (e.g. `alice.bsky.social`).
/// - Each label must be 1-63 characters, start with alphanumeric, not end with hyphen,
///   and contain only `[a-z0-9-]`.
/// - Disallowed TLDs: `.alt`, `.arpa`, `.example`, `.internal`, `.invalid`, `.local`, `.localhost`, `.onion`.
/// - Rejects IP addresses.
///
/// # Errors
/// - Returns [`IdentityError::DisallowedHandleTld`] if the TLD is disallowed.
/// - Returns [`IdentityError::InvalidHandleSyntax`] if any syntax rule is violated.
pub fn normalize_handle(raw_handle: &str) -> Result<String, IdentityError> {
    let trimmed = raw_handle.trim().trim_start_matches('@');
    let normalized = trimmed.to_ascii_lowercase();

    if normalized.is_empty() {
        return Err(IdentityError::InvalidHandleSyntax(
            "Handle cannot be empty".to_string(),
        ));
    }

    if normalized.len() > 244 {
        return Err(IdentityError::InvalidHandleSyntax(format!(
            "Handle length {} exceeds maximum allowed length of 244 characters",
            normalized.len()
        )));
    }

    // Handles must not be raw IP literals.
    if normalized.parse::<std::net::IpAddr>().is_ok()
        || normalized.starts_with('[')
        || normalized.chars().all(|c| c.is_ascii_digit() || c == '.')
    {
        return Err(IdentityError::InvalidHandleSyntax(
            "Handle cannot be an IP address".to_string(),
        ));
    }

    let labels: Vec<&str> = normalized.split('.').collect();
    if labels.len() < 2 {
        return Err(IdentityError::InvalidHandleSyntax(
            "Handle must contain at least two domain labels".to_string(),
        ));
    }

    for label in &labels {
        if label.is_empty() || label.len() > 63 {
            return Err(IdentityError::InvalidHandleSyntax(format!(
                "Domain label '{label}' length {} is outside valid range (1..=63)",
                label.len()
            )));
        }

        if label.starts_with('-') || label.ends_with('-') {
            return Err(IdentityError::InvalidHandleSyntax(format!(
                "Domain label '{label}' must not start or end with a hyphen"
            )));
        }

        let first_char = label.chars().next().unwrap_or('\0');
        if !first_char.is_ascii_alphanumeric() {
            return Err(IdentityError::InvalidHandleSyntax(format!(
                "Domain label '{label}' must start with an alphanumeric character"
            )));
        }

        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err(IdentityError::InvalidHandleSyntax(format!(
                "Domain label '{label}' contains illegal characters (only [a-z0-9-] allowed)"
            )));
        }
    }

    let tld = labels.last().copied().unwrap_or("");
    let disallowed_tlds = [
        "alt",
        "arpa",
        "example",
        "internal",
        "invalid",
        "local",
        "localhost",
        "onion",
    ];

    if disallowed_tlds.contains(&tld) {
        return Err(IdentityError::DisallowedHandleTld(tld.to_string()));
    }

    if normalized == "handle.invalid" {
        return Err(IdentityError::DisallowedHandleTld(
            "handle.invalid".to_string(),
        ));
    }

    Ok(normalized)
}

/// Validates DID syntax and determines the DID method.
///
/// # Errors
/// - Returns [`IdentityError::InvalidDidSyntax`] if the string is not a valid DID.
/// - Returns [`IdentityError::UnsupportedDidMethod`] if the method is not `plc` or `web`.
pub fn validate_did_syntax(did: &str) -> Result<DidMethod, IdentityError> {
    let trimmed = did.trim();
    if !trimmed.starts_with("did:") {
        return Err(IdentityError::InvalidDidSyntax(
            "DID must start with 'did:'".to_string(),
        ));
    }

    let parts: Vec<&str> = trimmed.split(':').collect();
    if parts.len() < 3 {
        return Err(IdentityError::InvalidDidSyntax(format!(
            "Malformed DID structure '{trimmed}'"
        )));
    }

    // Method-name grammar per the DID core spec: [a-z0-9]+ (already matched
    // implicitly by the match arms below; unknown methods are rejected).
    match parts[1] {
        "plc" => {
            // ATProto DID PLC grammar: exactly 24 lowercase alphanumeric chars
            // (base32-sorted suffix; see did:plc registry). Previously only a
            // minimum length was checked (review L2/#4), allowing traversal
            // payloads like `did:plc:x/../../admin` through URL construction.
            let hash = parts[2];
            let valid = hash.len() == 24
                && hash
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit());
            if !valid {
                return Err(IdentityError::InvalidDidSyntax(format!(
                    "did:plc identifier must be exactly 24 lowercase alphanumeric characters, got '{hash}'"
                )));
            }
            Ok(DidMethod::Plc)
        }
        "web" => {
            // did:web: the identifier is a domain optionally followed by
            // ':'-separated path segments. It must NOT contain userinfo ('@'),
            // ports, empty segments, or characters that URL parsing would
            // reinterpret (review L2: `trusted.example@evil.example` previously
            // passed and re-targeted the host during URL construction).
            let domain = parts[2];
            // did:web grammar (W3C did:web): first segment is a domain; any
            // further ':'-separated segments are URL path components. Every
            // segment must be non-empty, free of '@' (userinfo re-parsing —
            // review L2), raw ':' or '/' (structural characters), and only
            // alphanumeric/'.'/'-'/'%' characters.
            let segments: Vec<&str> = trimmed
                .strip_prefix("did:web:")
                .unwrap_or(domain)
                .split(':')
                .collect();
            let valid = !domain.is_empty()
                && !domain.contains('@')
                && segments.iter().all(|seg| {
                    !seg.is_empty()
                        && !seg.contains('@')
                        && seg
                            .chars()
                            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '%')
                });
            if !valid {
                return Err(IdentityError::InvalidDidSyntax(format!(
                    "did:web identifier '{domain}' is not a valid domain (no userinfo, ports, empty segments, or non-domain characters)"
                )));
            }
            Ok(DidMethod::Web)
        }
        unsupported => Err(IdentityError::UnsupportedDidMethod(unsupported.to_string())),
    }
}

/// Asynchronous trait for resolving DNS TXT records.
pub trait DnsTxtResolver: std::fmt::Debug + Send + Sync + 'static {
    /// Queries TXT records for `query_name` (e.g. `_atproto.alice.bsky.social`).
    fn resolve_txt<'a>(
        &'a self,
        query_name: &'a str,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Vec<String>, IdentityError>> + Send + 'a>,
    >;
}

/// Standard DNS resolver querying public DNS-over-HTTPS (DoH) endpoints.
#[derive(Debug, Clone, Default)]
pub struct StandardDnsResolver;

impl DnsTxtResolver for StandardDnsResolver {
    fn resolve_txt<'a>(
        &'a self,
        query_name: &'a str,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Vec<String>, IdentityError>> + Send + 'a>,
    > {
        Box::pin(async move {
            let doh_url =
                format!("https://cloudflare-dns.com/dns-query?name={query_name}&type=TXT");
            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(4))
                // DoH bootstrap must not be transparently routed through
                // environment proxies: a proxied resolver's answers are a
                // different trust domain (and the DoH host would be
                // proxy-resolved, bypassing the SSRF pinning model used
                // everywhere else — review H6/L5).
                .no_proxy()
                .build()
                .map_err(|e| IdentityError::Dns(e.to_string()))?;

            let resp = client
                .get(&doh_url)
                .header(reqwest::header::ACCEPT, "application/dns-json")
                .send()
                .await
                .map_err(|e| IdentityError::Dns(e.to_string()))?;

            if !resp.status().is_success() {
                return Ok(Vec::new());
            }

            #[derive(Deserialize)]
            struct DohAnswer {
                #[serde(rename = "type")]
                answer_type: u16,
                data: String,
            }

            #[derive(Deserialize)]
            struct DohResponse {
                #[serde(rename = "Answer", default)]
                answer: Vec<DohAnswer>,
            }

            let body: DohResponse = resp
                .json()
                .await
                .map_err(|e| IdentityError::Dns(e.to_string()))?;

            let records = body
                .answer
                .into_iter()
                .filter(|a| a.answer_type == 16)
                .map(|a| a.data.trim_matches('"').to_string())
                .collect();

            Ok(records)
        })
    }
}

/// Builder for constructing an [`IdentityResolver`].
#[derive(Debug, Clone)]
pub struct IdentityResolverBuilder {
    ssrf_filter: SsrfFilter,
    plc_directory_url: String,
    dns_resolver: Option<Arc<dyn DnsTxtResolver>>,
}

impl Default for IdentityResolverBuilder {
    fn default() -> Self {
        Self {
            ssrf_filter: SsrfFilter::default(),
            plc_directory_url: DEFAULT_PLC_DIRECTORY.to_string(),
            dns_resolver: None,
        }
    }
}

impl IdentityResolverBuilder {
    /// Creates a new builder with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the SSRF filter configuration.
    #[must_use]
    pub fn ssrf_filter(mut self, filter: SsrfFilter) -> Self {
        self.ssrf_filter = filter;
        self
    }

    /// Configures whether insecure HTTP and localhost connections are permitted for tests.
    #[must_use]
    pub fn allow_insecure_localhost(mut self, allow: bool) -> Self {
        self.ssrf_filter.allow_insecure_localhost = allow;
        self
    }

    /// Sets a custom PLC directory URL.
    #[must_use]
    pub fn plc_directory_url(mut self, url: impl Into<String>) -> Self {
        self.plc_directory_url = url.into();
        self
    }

    /// Sets a custom DNS TXT resolver implementation.
    #[must_use]
    pub fn dns_resolver(mut self, resolver: Arc<dyn DnsTxtResolver>) -> Self {
        self.dns_resolver = Some(resolver);
        self
    }

    /// Builds the configured [`IdentityResolver`].
    #[must_use]
    pub fn build(self) -> IdentityResolver {
        IdentityResolver {
            ssrf_filter: self.ssrf_filter,
            plc_directory_url: self.plc_directory_url,
            dns_resolver: self.dns_resolver,
        }
    }
}

/// Decentralized Identity Resolver for AT Protocol handles and DIDs.
#[derive(Debug, Clone)]
pub struct IdentityResolver {
    ssrf_filter: SsrfFilter,
    plc_directory_url: String,
    dns_resolver: Option<Arc<dyn DnsTxtResolver>>,
}

impl IdentityResolver {
    /// Creates a new `IdentityResolver` with the specified SSRF filter.
    #[must_use]
    pub fn new(ssrf_filter: SsrfFilter) -> Self {
        Self {
            ssrf_filter,
            plc_directory_url: DEFAULT_PLC_DIRECTORY.to_string(),
            dns_resolver: None,
        }
    }

    /// Creates a builder for customized resolver construction.
    #[must_use]
    pub fn builder() -> IdentityResolverBuilder {
        IdentityResolverBuilder::new()
    }

    /// Returns a reference to the active SSRF filter.
    #[must_use]
    pub const fn ssrf_filter(&self) -> &SsrfFilter {
        &self.ssrf_filter
    }

    /// Resolves an AT Protocol handle to its DID via DNS TXT query (`_atproto.<handle>`).
    ///
    /// # Returns
    /// - `Ok(Some(did))` if a valid unambiguous DID TXT record is found.
    /// - `Ok(None)` if no DID record exists (triggers HTTPS fallback).
    ///
    /// # Errors
    /// - Returns [`IdentityError::AmbiguousHandleResolution`] if multiple conflicting DIDs exist.
    pub async fn resolve_handle_dns(&self, handle: &str) -> Result<Option<String>, IdentityError> {
        let normalized = normalize_handle(handle)?;
        let query_name = format!("_atproto.{normalized}");

        let records = if let Some(ref resolver) = self.dns_resolver {
            resolver.resolve_txt(&query_name).await?
        } else {
            StandardDnsResolver.resolve_txt(&query_name).await?
        };

        let dids: Vec<String> = records
            .into_iter()
            .filter(|r| r.starts_with("did="))
            .map(|r| r.strip_prefix("did=").unwrap_or("").to_string())
            .filter(|d| !d.is_empty())
            .collect();

        if dids.is_empty() {
            return Ok(None);
        }

        let first_did = &dids[0];
        validate_did_syntax(first_did)?;

        for did in &dids[1..] {
            if did != first_did {
                return Err(IdentityError::AmbiguousHandleResolution(normalized));
            }
        }

        Ok(Some(first_did.clone()))
    }

    /// Resolves an AT Protocol handle to its DID via HTTPS fallback (`/.well-known/atproto-did`).
    ///
    /// # Errors
    /// Returns [`IdentityError::HandleResolutionFailed`] if HTTP request fails or response is not a valid DID.
    pub async fn resolve_handle_https(&self, handle: &str) -> Result<String, IdentityError> {
        let normalized = normalize_handle(handle)?;
        let scheme = if self.ssrf_filter.allow_insecure_localhost
            && (normalized == "localhost" || normalized.starts_with("localhost:"))
        {
            "http"
        } else {
            "https"
        };

        let url = format!("{scheme}://{normalized}/.well-known/atproto-did");
        let bytes = self
            .ssrf_filter
            .safe_get(&url, 2048)
            .await
            .map_err(|_| IdentityError::HandleResolutionFailed(normalized.clone()))?;

        let text = std::str::from_utf8(&bytes)
            .map_err(|_| IdentityError::HandleResolutionFailed(normalized.clone()))?
            .trim()
            .to_string();

        validate_did_syntax(&text)?;
        Ok(text)
    }

    /// Resolves a handle to its DID using ATProto precedence rules:
    /// 1. Tries DNS TXT `_atproto.<handle>`.
    /// 2. If absent, falls back to HTTPS `https://<handle>/.well-known/atproto-did`.
    pub async fn resolve_handle(&self, handle: &str) -> Result<String, IdentityError> {
        let normalized = normalize_handle(handle)?;

        match self.resolve_handle_dns(&normalized).await {
            Ok(Some(did)) => Ok(did),
            Ok(None) | Err(IdentityError::Dns(_)) => self.resolve_handle_https(&normalized).await,
            Err(e) => Err(e),
        }
    }

    /// Resolves a `did:plc` Decentralized Identifier via the PLC Directory.
    pub async fn resolve_did_plc(&self, did: &str) -> Result<DidDocument, IdentityError> {
        validate_did_syntax(did)?;
        let url = format!("{}/{}", self.plc_directory_url.trim_end_matches('/'), did);

        let doc: DidDocument = self
            .ssrf_filter
            .safe_get_json(&url, MAX_OAUTH_RESPONSE_BYTES)
            .await
            .map_err(|e| match e {
                SsrfError::HttpStatus(404, _) => IdentityError::DidNotFound(did.to_string()),
                SsrfError::Json(err) => IdentityError::MalformedDidDocument(err),
                other => IdentityError::Ssrf(other),
            })?;

        doc.validate_id(did)?;
        Ok(doc)
    }

    /// Resolves a `did:web` Decentralized Identifier via HTTPS `/.well-known/did.json`.
    pub async fn resolve_did_web(&self, did: &str) -> Result<DidDocument, IdentityError> {
        validate_did_syntax(did)?;

        let stripped = did
            .strip_prefix("did:web:")
            .ok_or_else(|| IdentityError::InvalidDidSyntax(did.to_string()))?;

        let parts: Vec<&str> = stripped.split(':').collect();
        let domain_encoded = parts[0];
        let domain = domain_encoded.replace("%3A", ":").replace("%3a", ":");

        let scheme = if self.ssrf_filter.allow_insecure_localhost
            && (domain.starts_with("localhost") || domain.starts_with("127.0.0.1"))
        {
            "http"
        } else {
            "https"
        };

        let url = if parts.len() == 1 {
            format!("{scheme}://{domain}/.well-known/did.json")
        } else {
            let path_parts = &parts[1..];
            let path = path_parts.join("/");
            format!("{scheme}://{domain}/{path}/did.json")
        };

        let doc: DidDocument = self
            .ssrf_filter
            .safe_get_json(&url, MAX_OAUTH_RESPONSE_BYTES)
            .await
            .map_err(|e| match e {
                SsrfError::HttpStatus(404, _) => IdentityError::DidNotFound(did.to_string()),
                SsrfError::Json(err) => IdentityError::MalformedDidDocument(err),
                other => IdentityError::Ssrf(other),
            })?;

        doc.validate_id(did)?;
        Ok(doc)
    }

    /// Resolves any supported DID (`did:plc` or `did:web`) to its DID Document.
    pub async fn resolve_did(&self, did: &str) -> Result<DidDocument, IdentityError> {
        match validate_did_syntax(did)? {
            DidMethod::Plc => self.resolve_did_plc(did).await,
            DidMethod::Web => self.resolve_did_web(did).await,
        }
    }

    /// Resolves a user identifier (handle or DID), verifies bidirectional handle linkage,
    /// and extracts the authoritative PDS endpoint.
    pub async fn resolve_ident(
        &self,
        handle_or_did: &str,
    ) -> Result<ResolvedIdentity, IdentityError> {
        let trimmed = handle_or_did.trim();
        if trimmed.starts_with("did:") {
            let did = trimmed.to_string();
            let doc = self.resolve_did(&did).await?;
            let pds_endpoint = doc.extract_pds_endpoint()?;
            Ok(ResolvedIdentity {
                did,
                handle: None,
                did_doc: doc,
                pds_endpoint,
            })
        } else {
            let handle = normalize_handle(trimmed)?;
            let did = self.resolve_handle(&handle).await?;
            let doc = self.resolve_did(&did).await?;
            doc.verify_handle_bidirectional(&handle)?;
            let pds_endpoint = doc.extract_pds_endpoint()?;
            Ok(ResolvedIdentity {
                did,
                handle: Some(handle),
                did_doc: doc,
                pds_endpoint,
            })
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]
mod tests {
    use super::*;

    #[test]
    fn test_handle_normalization_valid() {
        assert_eq!(
            normalize_handle("@alice.bsky.social").unwrap(),
            "alice.bsky.social"
        );
        assert_eq!(
            normalize_handle("ALICE.BSKY.SOCIAL").unwrap(),
            "alice.bsky.social"
        );
        assert_eq!(
            normalize_handle("my-domain.co.uk").unwrap(),
            "my-domain.co.uk"
        );
    }

    #[test]
    fn test_handle_disallowed_tlds() {
        assert!(matches!(
            normalize_handle("alice.local"),
            Err(IdentityError::DisallowedHandleTld(_))
        ));
        assert!(matches!(
            normalize_handle("alice.onion"),
            Err(IdentityError::DisallowedHandleTld(_))
        ));
        assert!(matches!(
            normalize_handle("alice.localhost"),
            Err(IdentityError::DisallowedHandleTld(_))
        ));
        assert!(matches!(
            normalize_handle("alice.invalid"),
            Err(IdentityError::DisallowedHandleTld(_))
        ));
        assert!(matches!(
            normalize_handle("handle.invalid"),
            Err(IdentityError::DisallowedHandleTld(_))
        ));
    }

    #[test]
    fn test_handle_syntax_violations() {
        assert!(matches!(
            normalize_handle("localhost"),
            Err(IdentityError::InvalidHandleSyntax(_))
        ));
        assert!(matches!(
            normalize_handle("-alice.bsky.social"),
            Err(IdentityError::InvalidHandleSyntax(_))
        ));
        assert!(matches!(
            normalize_handle("alice-.bsky.social"),
            Err(IdentityError::InvalidHandleSyntax(_))
        ));
        assert!(matches!(
            normalize_handle("127.0.0.1"),
            Err(IdentityError::InvalidHandleSyntax(_))
        ));
    }

    #[test]
    fn test_did_syntax_validation() {
        assert_eq!(
            validate_did_syntax("did:plc:ewvi7nxzyoun6zhxrhs64oiz").unwrap(),
            DidMethod::Plc
        );
        assert_eq!(
            validate_did_syntax("did:web:auth.example.com").unwrap(),
            DidMethod::Web
        );
        assert!(matches!(
            validate_did_syntax("did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH"),
            Err(IdentityError::UnsupportedDidMethod(_))
        ));
        assert!(matches!(
            validate_did_syntax("not-a-did"),
            Err(IdentityError::InvalidDidSyntax(_))
        ));
    }

    #[test]
    fn test_did_document_bidirectional_verification() {
        let doc = DidDocument {
            id: "did:plc:123".to_string(),
            also_known_as: vec!["at://alice.bsky.social".to_string()],
            verification_method: vec![],
            service: vec![DidService {
                id: "#atproto_pds".to_string(),
                service_type: "AtprotoPersonalDataServer".to_string(),
                service_endpoint: "https://pds.example.com".to_string(),
            }],
        };

        assert!(doc.verify_handle_bidirectional("alice.bsky.social").is_ok());
        assert!(doc
            .verify_handle_bidirectional("@alice.bsky.social")
            .is_ok());
        assert!(doc.verify_handle_bidirectional("ALICE.BSKY.SOCIAL").is_ok());
        assert!(doc.verify_handle_bidirectional("bob.bsky.social").is_err());
    }

    #[test]
    fn test_did_document_pds_extraction() {
        let doc = DidDocument {
            id: "did:plc:123".to_string(),
            also_known_as: vec![],
            verification_method: vec![],
            service: vec![
                DidService {
                    id: "#other".to_string(),
                    service_type: "OtherType".to_string(),
                    service_endpoint: "https://other.com".to_string(),
                },
                DidService {
                    id: "#atproto_pds".to_string(),
                    service_type: "AtprotoPersonalDataServer".to_string(),
                    service_endpoint: "https://pds.example.com/".to_string(),
                },
            ],
        };

        assert_eq!(
            doc.extract_pds_endpoint().unwrap(),
            "https://pds.example.com"
        );
    }
}
