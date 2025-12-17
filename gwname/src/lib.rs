// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Gateway name global setting

#![deny(clippy::all, clippy::pedantic)]

use std::sync::OnceLock;

/// Name of a gateway
static GATEWAY_NAME: OnceLock<String> = OnceLock::new();

/// Set the name of a gateway so that it is accessible from all dataplane modules.
/// The name of a gateway should be set only once from the cmd line.
///
/// # Errors
///
/// This function will fail if the gateway name has already been set AND differs from the one provided.
pub fn set_gw_name(name: &str) -> Result<(), String> {
    match GATEWAY_NAME.set(name.to_owned()) {
        Ok(()) => Ok(()),
        Err(s) => {
            if name == get_gw_name().unwrap_or_else(|| unreachable!()) {
                Ok(())
            } else {
                Err(s)
            }
        }
    }
}

/// Return the name of this gateway, if set.
#[must_use]
pub fn get_gw_name() -> Option<&'static str> {
    GATEWAY_NAME.get().map(String::as_str)
}
