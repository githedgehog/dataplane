// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Gateway and gateway group identifying types and constraints

use crate::ConfigError;
use std::fmt::Display;

const MAX_NAME_LEN: usize = 64;

// validate the name of a gateway or a gateway group
fn validate_id(name: &str) -> Result<(), ConfigError> {
    if name.is_empty() {
        return Err(ConfigError::NoName);
    }
    if name.len() > MAX_NAME_LEN {
        return Err(ConfigError::NameTooLong(name.to_owned(), MAX_NAME_LEN));
    }
    Ok(())
}

/// The type to identify a gateway
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct GatewayId(String);
impl GatewayId {
    /// # Errors
    /// Fails if the name is empty or longer than `MAX_NAME_LEN`.
    pub fn new(name: &str) -> Result<Self, ConfigError> {
        validate_id(name)?;
        Ok(Self(name.to_owned()))
    }
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Display for GatewayId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.pad(&self.0)
    }
}

/// The type to identify a gateway group
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct GroupId(String);
impl GroupId {
    /// # Errors
    /// Fails if the name is empty or longer than `MAX_NAME_LEN`.
    pub fn new(name: &str) -> Result<Self, ConfigError> {
        validate_id(name)?;
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

impl Display for GroupId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.pad(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::{GatewayId, MAX_NAME_LEN};
    use crate::ConfigError;

    #[test]
    fn name_validation() {
        assert_eq!(GatewayId::new(""), Err(ConfigError::NoName));
        assert!(GatewayId::new(&"x".repeat(MAX_NAME_LEN)).is_ok());
        let long = "x".repeat(MAX_NAME_LEN + 1);
        assert_eq!(
            GatewayId::new(&long),
            Err(ConfigError::NameTooLong(long, MAX_NAME_LEN))
        );
    }
}
