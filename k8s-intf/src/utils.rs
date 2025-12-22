// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Utils to build the gateway CRD `GatewayAgentSpec` from JSON / YAML text files.

use crate::gateway_agent_crd::GatewayAgentSpec;
use serde_yaml_ng;
use std::fs;
use std::path::Path;

/// Read the file at `path` and deserialize it from YAML into a `GatewayAgentSpec` object.
fn load_crd_from_yaml(path: &str) -> Result<GatewayAgentSpec, String> {
    let yaml = fs::read_to_string(path)
        .map_err(|e| format!("Failed to read CRD from YAML file ({path}): {e}"))?;
    let crd: GatewayAgentSpec = serde_yaml_ng::from_str(&yaml)
        .map_err(|e| format!("Failed to deserialize CRD from YAML file ({path}): {e}"))?;
    Ok(crd)
}

/// Read the file at `path` and deserialize it from JSON into a `GatewayAgentSpec` object.
fn load_crd_from_json(path: &str) -> Result<GatewayAgentSpec, String> {
    let json = fs::read_to_string(path)
        .map_err(|e| format!("Failed to read CRD from JSON file ({path}): {e}"))?;
    let crd: GatewayAgentSpec = serde_json::from_str(&json)
        .map_err(|e| format!("Failed to deserialize CRD from JSON file ({path}): {e}"))?;
    Ok(crd)
}

/// Read the file at `path` and deserialize into a `GatewayAgentSpec` object.
/// The file is assumed to contain a gateway spec CRD in JSON or YAML.
///
/// # Errors
/// This function may fail if the file does not exist or cannot be opened / read, or if the contents
/// cannot be deserialized.
pub fn load_crd_from_file(path: &str) -> Result<GatewayAgentSpec, String> {
    let ext = Path::new(path).extension();
    match ext {
        Some(ext) if ext.eq_ignore_ascii_case("yaml") || ext.eq_ignore_ascii_case("yml") => {
            load_crd_from_yaml(path)
        }
        Some(ext) if ext.eq_ignore_ascii_case("json") => load_crd_from_json(path),
        Some(ext) => Err(format!("Unsupported file extension {}", ext.display())),
        None => Err("Missing file extension".to_string()),
    }
}
