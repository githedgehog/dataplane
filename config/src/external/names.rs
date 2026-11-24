// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Gateway and gateway group identifying types and constraints

use crate::ConfigError;
use std::fmt::Display;

const MAX_NAME_LEN: usize = 64;

// validate the name of a gateway or a gateway group
fn validate_name(name: &str) -> Result<(), ConfigError> {
    if name.is_empty() {
        return Err(ConfigError::NoName);
    }
    if name.len() > MAX_NAME_LEN {
        return Err(ConfigError::NameTooLong(name.to_owned(), MAX_NAME_LEN));
    }
    Ok(())
}

/// The type to name a gateway
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct GatewayName(String);
impl GatewayName {
    /// # Errors
    /// Fails if the name is empty or longer than `MAX_NAME_LEN`.
    pub fn new(name: &str) -> Result<Self, ConfigError> {
        validate_name(name)?;
        Ok(Self(name.to_owned()))
    }
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Display for GatewayName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.pad(&self.0)
    }
}

/// The type to name a gateway group
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct GroupName(String);
impl GroupName {
    /// # Errors
    /// Fails if the name is empty or longer than `MAX_NAME_LEN`.
    pub fn new(name: &str) -> Result<Self, ConfigError> {
        validate_name(name)?;
        Ok(Self(name.to_owned()))
    }

    /// The group named "default" (this is mostly for tests)
    #[must_use]
    pub fn default_group() -> Self {
        Self("default".to_owned())
    }
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Display for GroupName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.pad(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::{GatewayName, MAX_NAME_LEN};
    use crate::ConfigError;

    #[test]
    fn name_validation() {
        assert_eq!(GatewayName::new(""), Err(ConfigError::NoName));
        assert!(GatewayName::new(&"x".repeat(MAX_NAME_LEN)).is_ok());
        let long = "x".repeat(MAX_NAME_LEN + 1);
        assert_eq!(
            GatewayName::new(&long),
            Err(ConfigError::NameTooLong(long, MAX_NAME_LEN))
        );
    }
}
