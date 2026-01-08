// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Utils to build the gateway CRD `GatewayAgentSpec` from JSON / YAML text files.

use crate::gateway_agent_crd::GatewayAgentSpec;
use serde::Serialize;
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

/// Serialize an object as JSON and store it in the file at path `path`.
/// This function will create the file if it does not exist.
///
/// # Errors
/// This function may fail if the object cannot be serialized or if the
/// full directory path does not exist.
pub fn save_as_json<T: Serialize>(path: &str, object: &T) -> Result<(), String> {
    let json =
        serde_json::to_string(object).map_err(|e| format!("Failed to serialize as JSON: {e}"))?;
    fs::write(path, json).map_err(|e| format!("Failed to write json file at {path}: {e}"))
}

/// Serialize an object as YAML and store it in the file at path `path`.
/// This function will create the file if it does not exist.
///
/// # Errors
/// This function may fail if the object cannot be serialized or if the
/// full directory path does not exist.
pub fn save_as_yaml<T: Serialize>(path: &str, object: &T) -> Result<(), String> {
    let yaml = serde_yaml_ng::to_string(object)
        .map_err(|e| format!("Failed to serialize as YAML: {e}"))?;
    fs::write(path, yaml).map_err(|e| format!("Failed to write YAML file at {path}: {e}"))
}

/// Serialize an object as JSON and YAML and store both in separate files
/// with extensions .json and .yaml added to the indicated filename in `path`.
/// The files will be created if they do not exist.
///
/// # Errors
/// This function may fail if the object cannot be serialized or if the
/// full directory path does not exist.
pub fn save<T: Serialize>(path: &str, object: &T) -> Result<(), String> {
    let p = Path::new(path);
    let yaml_file = p.with_added_extension("yaml");
    let json_file = p.with_added_extension("json");
    save_as_yaml(yaml_file.to_str().unwrap_or_else(|| unreachable!()), object)?;
    save_as_json(json_file.to_str().unwrap_or_else(|| unreachable!()), object)?;
    Ok(())
}
