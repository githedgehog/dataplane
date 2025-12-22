// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

pub mod sample;

use crate::gateway_agent_crd::GatewayAgentSpec;
use crate::samplegen::sample::Sample;

use serde_json::to_string_pretty;
use std::fs;
use std::path::PathBuf;

/// Generate sample json and yaml files in the indicated path
///
/// # Errors
/// On error, this function returns a string describing what went wrong.
pub fn generate_samples(path: &str, filename: &str) -> Result<(), String> {
    let crd = GatewayAgentSpec::sample();
    let json = to_string_pretty(&crd)
        .map_err(|e| format!("Failed to serialize CRD as pretty-JSON: {e}"))?;
    let yaml = serde_yaml_ng::to_string(&crd)
        .map_err(|e| format!("Failed to serialize CRD as YAML: {e}"))?;

    let output_dir = PathBuf::from(path);
    fs::create_dir_all(&output_dir)
        .map_err(|e| format!("Failed to create output directory: {e}"))?;

    let mut jsonfile = PathBuf::from(path).join(filename);
    jsonfile.set_extension("json");
    fs::write(&jsonfile, json).map_err(|e| format!("Failed to write sample JSON file: {e}"))?;

    let mut yamlfile = PathBuf::from(path).join(filename);
    yamlfile.set_extension("yaml");
    fs::write(&yamlfile, yaml).map_err(|e| format!("Failed to write sample YAML file: {e}"))?;

    Ok(())
}

#[cfg(test)]
mod test {
    use crate::gateway_agent_crd::GatewayAgentSpec;
    use crate::samplegen::sample::Sample;
    use serde_json::to_string_pretty;

    // This basically tests that sample can be built
    #[test]
    fn test_samples() {
        let crd = GatewayAgentSpec::sample();
        println!("\n CRD in Rust:\n");
        println!("{crd:#?}");

        let json = to_string_pretty(&crd).unwrap();
        println!("\n CRD in JSON:\n");
        println!("{json}");

        let yaml = serde_yaml_ng::to_string(&crd).unwrap();
        println!("\n CRD in YAML:\n");
        println!("{yaml}");
    }
}
