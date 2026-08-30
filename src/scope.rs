//! AT Protocol OAuth scope parsing and validation.

use std::collections::{BTreeMap, BTreeSet};

use crate::error::ScopeError;

/// A validated AT Protocol OAuth scope set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeSet {
    raw: String,
    items: Vec<ScopeItem>,
}

impl ScopeSet {
    /// Parses a space-separated scope set and requires the `atproto` scope.
    ///
    /// # Errors
    ///
    /// Returns [`ScopeError`] when the set or any permission is invalid.
    pub fn parse(value: &str) -> Result<Self, ScopeError> {
        if value.is_empty() || value.trim() != value || value.contains("  ") {
            return Err(ScopeError::InvalidSet);
        }

        let mut items = Vec::new();
        let mut seen = BTreeSet::new();
        for raw_item in value.split(' ') {
            if !seen.insert(raw_item) {
                return Err(ScopeError::Duplicate(raw_item.to_string()));
            }
            items.push(ScopeItem::parse(raw_item)?);
        }
        if !items.iter().any(|item| matches!(item, ScopeItem::Atproto)) {
            return Err(ScopeError::MissingAtproto);
        }

        Ok(Self {
            raw: value.to_string(),
            items,
        })
    }

    /// Returns the exact scope string supplied by the issuer or caller.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.raw
    }

    /// Returns the parsed scope items.
    #[must_use]
    pub fn items(&self) -> &[ScopeItem] {
        &self.items
    }

    /// Returns whether every item in this set appears in `maximum`.
    #[must_use]
    pub fn is_subset_of(&self, maximum: &Self) -> bool {
        self.items.iter().all(|item| maximum.items.contains(item))
    }
}

/// A validated scope item.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum ScopeItem {
    /// Mandatory AT Protocol account scope.
    Atproto,
    /// Transitional interoperable scope.
    Transitional(String),
    /// Granular permission scope.
    Permission(PermissionScope),
}

impl ScopeItem {
    fn parse(value: &str) -> Result<Self, ScopeError> {
        validate_raw_ascii(value)?;
        if value == "atproto" {
            return Ok(Self::Atproto);
        }
        if let Some(name) = value.strip_prefix("transition:") {
            if name.is_empty() || name.contains(['?', '&', '=']) {
                return Err(ScopeError::InvalidPermission(value.to_string()));
            }
            return Ok(Self::Transitional(value.to_string()));
        }
        Ok(Self::Permission(PermissionScope::parse(value)?))
    }
}

/// A validated granular AT Protocol permission.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct PermissionScope {
    resource: PermissionResource,
    positional: Option<String>,
    parameters: BTreeMap<String, Vec<String>>,
}

impl PermissionScope {
    /// Parses one granular permission scope.
    ///
    /// # Errors
    ///
    /// Returns [`ScopeError`] for invalid syntax or semantics.
    pub fn parse(value: &str) -> Result<Self, ScopeError> {
        validate_raw_ascii(value)?;
        let (head, query) = match value.split_once('?') {
            Some((head, query)) if !query.contains('?') => (head, Some(query)),
            Some(_) => return Err(ScopeError::InvalidPermission(value.to_string())),
            None => (value, None),
        };
        let (resource_name, positional) = match head.split_once(':') {
            Some((resource, positional)) if !positional.is_empty() => {
                (resource, Some(decode_component(positional)?))
            }
            Some(_) => return Err(ScopeError::InvalidPermission(value.to_string())),
            None => (head, None),
        };
        let resource = PermissionResource::parse(resource_name)?;
        let parameters = parse_parameters(query)?;
        let permission = Self {
            resource,
            positional,
            parameters,
        };
        permission.validate()?;
        Ok(permission)
    }

    /// Returns the permission resource.
    #[must_use]
    pub const fn resource(&self) -> PermissionResource {
        self.resource
    }

    /// Returns the decoded positional value, when present.
    #[must_use]
    pub fn positional(&self) -> Option<&str> {
        self.positional.as_deref()
    }

    /// Returns decoded parameter values for `name`.
    #[must_use]
    pub fn parameter(&self, name: &str) -> Option<&[String]> {
        self.parameters.get(name).map(Vec::as_slice)
    }

    fn validate(&self) -> Result<(), ScopeError> {
        let allowed = match self.resource {
            PermissionResource::Repo => &["collection", "action"][..],
            PermissionResource::Rpc => &["lxm", "aud"][..],
            PermissionResource::Blob => &["accept"][..],
            PermissionResource::Account => &["attr", "action"][..],
            PermissionResource::Identity => &["attr"][..],
            PermissionResource::Include => &["aud"][..],
        };
        if self
            .parameters
            .keys()
            .any(|name| !allowed.contains(&name.as_str()))
        {
            return Err(ScopeError::UnknownParameter);
        }

        match self.resource {
            PermissionResource::Repo => {
                let collections = self.positional_or_many("collection")?;
                validate_nsid_or_wildcards(&collections)?;
                validate_many(&self.parameters, "action", &["create", "update", "delete"])?;
            }
            PermissionResource::Rpc => {
                let methods = self.positional_or_many("lxm")?;
                validate_nsid_or_wildcards(&methods)?;
                let audience = exactly_one(&self.parameters, "aud")?;
                if audience != "*" && !valid_did_service_reference(audience) {
                    return Err(ScopeError::InvalidPermission(audience.to_string()));
                }
                if methods.iter().any(|method| method == "*") && audience == "*" {
                    return Err(ScopeError::UnboundedRpc);
                }
            }
            PermissionResource::Blob => {
                let accepts = self.positional_or_many("accept")?;
                if accepts.iter().any(|value| !valid_mime_pattern(value)) {
                    return Err(ScopeError::InvalidPermission(accepts.join(",")));
                }
            }
            PermissionResource::Account => {
                let attribute = self.positional_or_one("attr")?;
                if !matches!(attribute, "email" | "repo") {
                    return Err(ScopeError::InvalidPermission(attribute.to_string()));
                }
                validate_single_optional(&self.parameters, "action", &["read", "manage"])?;
            }
            PermissionResource::Identity => {
                let attribute = self.positional_or_one("attr")?;
                if !matches!(attribute, "handle" | "*") {
                    return Err(ScopeError::InvalidPermission(attribute.to_string()));
                }
            }
            PermissionResource::Include => {
                let set = self
                    .positional
                    .as_deref()
                    .ok_or(ScopeError::MissingParameter("permission-set"))?;
                if !valid_nsid(set) {
                    return Err(ScopeError::InvalidPermission(set.to_string()));
                }
                if self.parameters.contains_key("aud") {
                    let audience = exactly_one(&self.parameters, "aud")?;
                    if audience != "*" && !valid_did_service_reference(audience) {
                        return Err(ScopeError::InvalidPermission(audience.to_string()));
                    }
                }
            }
        }
        Ok(())
    }

    fn positional_or_many(&self, name: &'static str) -> Result<Vec<String>, ScopeError> {
        match (&self.positional, self.parameters.get(name)) {
            (Some(value), None) => Ok(vec![value.clone()]),
            (None, Some(values)) if !values.is_empty() => Ok(values.clone()),
            (Some(_), Some(_)) => Err(ScopeError::ConflictingPositional(name)),
            _ => Err(ScopeError::MissingParameter(name)),
        }
    }

    fn positional_or_one(&self, name: &'static str) -> Result<&str, ScopeError> {
        match (&self.positional, self.parameters.get(name)) {
            (Some(value), None) => Ok(value),
            (None, Some(values)) if values.len() == 1 => Ok(&values[0]),
            (Some(_), Some(_)) => Err(ScopeError::ConflictingPositional(name)),
            (None, Some(_)) => Err(ScopeError::Duplicate(name.to_string())),
            _ => Err(ScopeError::MissingParameter(name)),
        }
    }
}

/// A permission resource defined by the AT Protocol profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PermissionResource {
    /// Repository records.
    Repo,
    /// Remote procedure calls.
    Rpc,
    /// Blob uploads.
    Blob,
    /// Account configuration.
    Account,
    /// DID and handle configuration.
    Identity,
    /// Lexicon permission-set inclusion.
    Include,
}

impl PermissionResource {
    fn parse(value: &str) -> Result<Self, ScopeError> {
        match value {
            "repo" => Ok(Self::Repo),
            "rpc" => Ok(Self::Rpc),
            "blob" => Ok(Self::Blob),
            "account" => Ok(Self::Account),
            "identity" => Ok(Self::Identity),
            "include" => Ok(Self::Include),
            _ => Err(ScopeError::UnknownResource(value.to_string())),
        }
    }
}

/// Parses percent-encoded scope parameters into a duplicate-aware map.
fn parse_parameters(query: Option<&str>) -> Result<BTreeMap<String, Vec<String>>, ScopeError> {
    let mut parameters = BTreeMap::<String, Vec<String>>::new();
    let Some(query) = query else {
        return Ok(parameters);
    };
    if query.is_empty() {
        return Ok(parameters);
    }
    for pair in query.split('&') {
        let (raw_name, raw_value) = pair
            .split_once('=')
            .ok_or_else(|| ScopeError::InvalidPermission(pair.to_string()))?;
        let name = decode_component(raw_name)?;
        let value = decode_component(raw_value)?;
        if name.is_empty() || value.is_empty() {
            return Err(ScopeError::InvalidPermission(pair.to_string()));
        }
        let values = parameters.entry(name).or_default();
        if values.iter().any(|existing| existing == &value) {
            return Err(ScopeError::Duplicate(value));
        }
        values.push(value);
    }
    Ok(parameters)
}

/// Decodes one percent-encoded ASCII scope component.
fn decode_component(value: &str) -> Result<String, ScopeError> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len() {
                return Err(ScopeError::InvalidEncoding);
            }
            let high = hex_value(bytes[index + 1]).ok_or(ScopeError::InvalidEncoding)?;
            let low = hex_value(bytes[index + 2]).ok_or(ScopeError::InvalidEncoding)?;
            decoded.push((high << 4) | low);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    if decoded.iter().any(|byte| !(0x21..=0x7e).contains(byte)) {
        return Err(ScopeError::InvalidEncoding);
    }
    String::from_utf8(decoded).map_err(|_| ScopeError::InvalidEncoding)
}

const fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Rejects non-ASCII, control, and whitespace bytes in a raw scope item.
fn validate_raw_ascii(value: &str) -> Result<(), ScopeError> {
    if value.is_empty() || value.bytes().any(|byte| !(0x21..=0x7e).contains(&byte)) {
        Err(ScopeError::InvalidEncoding)
    } else {
        Ok(())
    }
}

/// Validates NSID parameters with the profile's permitted wildcard forms.
fn validate_nsid_or_wildcards(values: &[String]) -> Result<(), ScopeError> {
    if values
        .iter()
        .any(|value| value != "*" && !valid_nsid(value))
    {
        Err(ScopeError::InvalidPermission(values.join(",")))
    } else {
        Ok(())
    }
}

/// Checks the complete AT Protocol NSID syntax used by permission scopes.
fn valid_nsid(value: &str) -> bool {
    if !value.is_ascii() || value.len() > 317 {
        return false;
    }
    let segments = value.split('.').collect::<Vec<_>>();
    if segments.len() < 3 {
        return false;
    }
    let Some((name, authority)) = segments.split_last() else {
        return false;
    };
    let authority_length = authority
        .iter()
        .map(|segment| segment.len())
        .sum::<usize>()
        .saturating_add(authority.len().saturating_sub(1));
    authority_length <= 253
        && authority.first().is_some_and(|segment| {
            segment
                .as_bytes()
                .first()
                .is_some_and(|byte| !byte.is_ascii_digit())
        })
        && authority.iter().all(|part| {
            !part.is_empty()
                && part.len() <= 63
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                && !part.starts_with('-')
                && !part.ends_with('-')
        })
        && !name.is_empty()
        && name.len() <= 63
        && name.as_bytes().first().is_some_and(u8::is_ascii_alphabetic)
        && name.bytes().all(|byte| byte.is_ascii_alphanumeric())
}

/// Checks a DID URL service reference used by account permissions.
fn valid_did_service_reference(value: &str) -> bool {
    let Some((did, fragment)) = value.split_once('#') else {
        return false;
    };
    !fragment.is_empty()
        && !fragment.contains('#')
        && (did.starts_with("did:plc:") || did.starts_with("did:web:"))
        && did.len() > 8
}

/// Checks an exact or subtype-wildcard MIME pattern.
fn valid_mime_pattern(value: &str) -> bool {
    let Some((kind, subtype)) = value.split_once('/') else {
        return false;
    };
    !kind.is_empty()
        && !subtype.is_empty()
        && !subtype.contains('/')
        && (kind == "*" || kind.bytes().all(valid_mime_byte))
        && (subtype == "*" || subtype.bytes().all(valid_mime_byte))
}

const fn valid_mime_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#' | b'$' | b'&' | b'-' | b'^' | b'_' | b'.' | b'+'
        )
}

/// Extracts exactly one value for a required parameter.
fn exactly_one<'a>(
    parameters: &'a BTreeMap<String, Vec<String>>,
    name: &'static str,
) -> Result<&'a str, ScopeError> {
    match parameters.get(name) {
        Some(values) if values.len() == 1 => Ok(&values[0]),
        Some(_) => Err(ScopeError::Duplicate(name.to_string())),
        None => Err(ScopeError::MissingParameter(name)),
    }
}

/// Validates a required multi-valued parameter with a supplied predicate.
fn validate_many(
    parameters: &BTreeMap<String, Vec<String>>,
    name: &'static str,
    allowed: &[&str],
) -> Result<(), ScopeError> {
    if parameters.get(name).is_some_and(|values| {
        values
            .iter()
            .any(|value| !allowed.contains(&value.as_str()))
    }) {
        Err(ScopeError::InvalidPermission(name.to_string()))
    } else {
        Ok(())
    }
}

/// Validates an optional parameter that may appear at most once.
fn validate_single_optional(
    parameters: &BTreeMap<String, Vec<String>>,
    name: &'static str,
    allowed: &[&str],
) -> Result<(), ScopeError> {
    match parameters.get(name) {
        Some(values) if values.len() != 1 => Err(ScopeError::Duplicate(name.to_string())),
        Some(values) if !allowed.contains(&values[0].as_str()) => {
            Err(ScopeError::InvalidPermission(name.to_string()))
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]
mod tests {
    use super::*;

    #[test]
    fn parses_current_permission_examples() {
        let set = ScopeSet::parse(
            "atproto repo:app.example.profile?action=create&action=delete rpc?lxm=*&aud=did:web:api.example.com%23svc_appview blob?accept=video/*&accept=text/html account:repo?action=manage identity:handle include:app.example.authFull?aud=did:web:api.example.com%23svc_chat",
        )
        .unwrap();
        assert_eq!(set.items().len(), 7);
    }

    #[test]
    fn rejects_conflicts_unknowns_and_unbounded_rpc() {
        for invalid in [
            "atproto repo:app.example.post?collection=app.example.other",
            "atproto repo:app.example.post?unknown=x",
            "atproto rpc:*?aud=*",
            "atproto account:email?action=delete",
            "atproto include:app.example.set?aud=did:web:example.com",
        ] {
            assert!(ScopeSet::parse(invalid).is_err(), "accepted {invalid}");
        }
    }

    #[test]
    fn preserves_partial_grant_and_subset_semantics() {
        let requested = ScopeSet::parse(
            "atproto repo:app.example.post repo:app.example.like transition:generic",
        )
        .unwrap();
        let granted = ScopeSet::parse("atproto repo:app.example.post").unwrap();
        assert!(granted.is_subset_of(&requested));
        assert!(!requested.is_subset_of(&granted));
        assert_eq!(granted.as_str(), "atproto repo:app.example.post");
    }

    #[test]
    fn rejects_invalid_nsid_authority_and_name_segments() {
        for scope in [
            "atproto repo:com.example.3",
            "atproto repo:com.example.foo-bar",
            "atproto repo:1.example.foo",
        ] {
            assert!(
                ScopeSet::parse(scope).is_err(),
                "accepted invalid scope: {scope}"
            );
        }
        assert!(ScopeSet::parse("atproto repo:com.example.fooBar2").is_ok());
    }
}
