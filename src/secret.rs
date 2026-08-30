//! Internal zeroizing secret storage.

use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub(crate) struct SecretString(Zeroizing<String>);

impl SecretString {
    pub(crate) fn new(value: impl Into<String>) -> Self {
        Self(Zeroizing::new(value.into()))
    }

    pub(crate) fn expose(&self) -> &str {
        self.0.as_str()
    }
}

impl Clone for SecretString {
    fn clone(&self) -> Self {
        Self::new(self.expose())
    }
}

impl std::fmt::Debug for SecretString {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("[REDACTED]")
    }
}

impl PartialEq for SecretString {
    fn eq(&self, other: &Self) -> bool {
        self.0.len() == other.0.len() && bool::from(self.0.as_bytes().ct_eq(other.0.as_bytes()))
    }
}

impl Eq for SecretString {}

impl<'de> serde::Deserialize<'de> for SecretString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        String::deserialize(deserializer).map(Self::new)
    }
}
