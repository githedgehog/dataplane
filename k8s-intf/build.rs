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

fn generate_rust_for_crd(crd_content: &str) -> String {
    // Run kopium with stdin input
    let mut child = std::process::Command::new("kopium")
        .args(["-Af", "-"])
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

    String::from_utf8(output.stdout).expect("Failed to convert kopium output to string")
}

fn main() {
    let agent_crd_url = get_agent_crd_url();
    let agent_crd_contents = fetch_crd(&agent_crd_url);
    let agent_generated_code = generate_rust_for_crd(&agent_crd_contents);

    // Write the generated code
    let output_dir = PathBuf::from("src/generated");
    fs::create_dir_all(&output_dir).expect("Failed to create output directory");

    let output_file = output_dir.join("gateway_agent_crd.rs");
    fs::write(
        &output_file,
        LICENSE_PREAMBLE.to_string() + &agent_generated_code,
    )
    .expect("Failed to write generated agent CRD code");

    println!(
        "cargo:note=Generated gateway agent CRD types written to {:?}",
        output_file
    );
}
