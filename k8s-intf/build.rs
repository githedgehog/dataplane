// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use std::fs;
use std::path::PathBuf;

fn get_agent_crd_url() -> String {
    println!("cargo:rerun-if-changed=scripts/k8s-crd.env");

    let env_file = dotenvy::from_filename_iter("scripts/k8s-crd.env")
        .expect("Failed to read scripts/k8s-crd.env");

    env_file
        .filter_map(Result::ok)
        .find_map(|(key, value)| {
            if key == "K8S_GATEWAY_AGENT_CRD_URL" {
                Some(value)
            } else {
                None
            }
        })
        .expect("K8S_GATEWAY_AGENT_CRD_URL not found in scripts/k8s-crd.env")
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
}

fn generate_rust_for_crd(crd_content: &str) -> String {
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

    LICENSE_PREAMBLE.to_string() + &fixup_types(raw)
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
    let agent_crd_url = get_agent_crd_url();
    let agent_crd_contents = fetch_crd(&agent_crd_url);
    let agent_generated_code = generate_rust_for_crd(&agent_crd_contents);

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
