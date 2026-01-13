// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use std::env;
use std::fs;
use std::path::PathBuf;

fn workspace_root() -> PathBuf {
    PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set"))
        .ancestors()
        .nth(1)
        .expect("Workspace root not found")
        .to_path_buf()
}

#[derive(Default)]
struct EnvConfig {
    version: Option<String>,
    url: Option<String>,
    local_path: Option<String>,
}

fn read_env_config() -> EnvConfig {
    let env_file_path = workspace_root().join("scripts").join("k8s-crd.env");
    let env_file =
        dotenvy::from_path_iter(env_file_path).expect("Failed to read scripts/k8s-crd.env");

    let mut config = EnvConfig::default();
    env_file.filter_map(Result::ok).for_each(|(key, value)| {
        match key.as_str() {
            "K8S_GATEWAY_AGENT_REF" => {
                if !value.is_empty() {
                    config.version = Some(value);
                }
            }
            "K8S_GATEWAY_AGENT_CRD_URL" => {
                if !value.is_empty() {
                    config.url = Some(value);
                }
            }
            "K8S_GATEWAY_AGENT_CRD_PATH" => {
                if !value.is_empty() {
                    config.local_path = Some(value);
                }
            }
            _ => { /* ignore undeclared variables */ }
        }
    });

    // don't set version if we'll build from local crd spec
    if config.local_path.is_some() {
        config.version.take();
    }

    config
}

fn fetch_crd(url: &str) -> String {
    println!("cargo:note=Fetching CRD from: {url}");
    ureq::get(url)
        .call()
        .expect("Failed to fetch agent CRD from url")
        .body_mut()
        .read_to_string()
        .expect("Failed to read response body")
}

fn fetch_crd_from_file(path: &str) -> String {
    println!("cargo:note=Fetching CRD from file at {path}");
    match fs::read_to_string(path) {
        Ok(crd) => crd,
        Err(e) => panic!("Failed to read CRD from {path}: {e}"),
    }
}

const LICENSE_PREAMBLE: &str = "// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

";

/// Fixup the types in the generated Rust code
///
/// This is gross, but needed.  OpenAPI v3 does not have any unsigned types
/// and so go types like uint32 in go become i32, this rewrites the known fields
/// from i32 to u32 in the generated file.
///
/// By rewriting the types, serde_json used by kube-rs should parse the
/// json correctly.
fn fixup_types(raw: String) -> String {
    raw.replace("asn: Option<i32>", "asn: Option<u32>")
        // This should get both vtep_mtu and plain mtu
        .replace("mtu: Option<i32>", "mtu: Option<u32>")
        .replace("vni: Option<i32>", "vni: Option<u32>")
        .replace("workers: Option<i64>", "workers: Option<u8>") // Gateway Go code says this is a u8
        .replace(
            "idle_timeout: Option<String>",
            "idle_timeout: Option<std::time::Duration>",
        )
        .replace("b: Option<i64>", "b: Option<u64>")
        .replace("d: Option<i64>", "d: Option<u64>")
        .replace("p: Option<i64>", "p: Option<u64>")
        .replace("priority: Option<i32>", "priority: Option<u32>")
        .replace("priority: i32", "priority: u32")
}

fn gen_version_const(version: &Option<String>) -> String {
    let version = version
        .as_ref()
        .map(|v| format!("Some(\"{v}\")"))
        .unwrap_or("None".to_string());

    format!("pub const GW_API_VERSION: Option<&str> = {version};\n\n")
}

fn generate_rust_for_crd(crd_content: &str, version: &Option<String>) -> String {
    // Run kopium with stdin input
    let mut child = std::process::Command::new("kopium")
        .args(["-D", "PartialEq", "-Af", "-"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("Failed to spawn kopium process");

    // Write CRD content to stdin
    use std::io::Write;
    if let Some(stdin) = child.stdin.as_mut() {
        stdin
            .write_all(crd_content.as_bytes())
            .expect("Failed to write CRD content to stdin");
    }

    // Wait for the process to complete and get output
    let output = child
        .wait_with_output()
        .expect("Failed to wait for kopium process");

    if !output.status.success() {
        panic!("kopium failed: {}", String::from_utf8_lossy(&output.stderr));
    }

    let raw = String::from_utf8(output.stdout).expect("Failed to convert kopium output to string");

    LICENSE_PREAMBLE.to_string() + gen_version_const(version).as_str() + &fixup_types(raw)
}

const GENERATED_OUTPUT_DIR: &str = "src/generated";
const KOPIUM_OUTPUT_FILE: &str = "gateway_agent_crd.rs";

fn kopium_output_path() -> PathBuf {
    PathBuf::from(GENERATED_OUTPUT_DIR).join(KOPIUM_OUTPUT_FILE)
}

fn code_needs_regen(new_code: &str) -> bool {
    if !fs::exists(kopium_output_path()).expect("Failed to check if output file exists") {
        return true;
    }

    let old_code = fs::read_to_string(kopium_output_path());

    if let Ok(old_code) = old_code {
        return old_code != new_code;
    }

    true
}

fn main() {
    // get config from env file
    let config = read_env_config();

    // get CRD spec from local path or URL
    let crd_spec = if let Some(agent_crd_file) = config.local_path {
        fetch_crd_from_file(&agent_crd_file)
    } else if let Some(agent_crd_url) = config.url {
        fetch_crd(&agent_crd_url)
    } else {
        panic!("No CRD path or URL is set in env file");
    };

    // CRD spec can't be empty
    if crd_spec.is_empty() {
        panic!("Empty CRD specification");
    }

    // generate rust types from the read crd_spec
    let agent_generated_code = generate_rust_for_crd(&crd_spec, &config.version);
    if !code_needs_regen(&agent_generated_code) {
        println!("cargo:note=No changes to code generated from CRD");
        return;
    }

    // Write the generated code
    let output_dir = PathBuf::from(GENERATED_OUTPUT_DIR);
    fs::create_dir_all(&output_dir).expect("Failed to create output directory");

    let output_file = kopium_output_path();
    fs::write(&output_file, agent_generated_code)
        .expect("Failed to write generated agent CRD code");

    println!(
        "cargo:note=Generated gateway agent CRD types written to {:?}",
        output_file
    );
}
