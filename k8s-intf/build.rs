// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use std::fs;
use std::io::Read;
use std::path::PathBuf;

/// Fixup the types in the generated Rust code
///
/// This is gross, but needed.  OpenAPI v3 does not have any unsigned types
/// and so go types like uint32 in go become i32, this rewrites the known fields
/// from i32 to u32 in the generated file.
///
/// By rewriting the types, serde_json used by kube-rs should parse the
/// json correctly.
///
/// TODO: replace this with a proc macro as the text replacement is likely fragile
fn fixup_types(raw: String) -> String {
    raw.replace("asn: Option<i32>", "asn: Option<u32>")
        // This should get both vtep_mtu and plain mtu
        .replace("mtu: Option<i32>", "mtu: Option<u32>")
        .replace("vni: Option<i32>", "vni: Option<u32>")
        .replace("workers: Option<i64>", "workers: Option<u8>") // Gateway Go code says this is a u8
        .replace(
            "idle_timeout: Option<String>",
            "idle_timeout: Option<kube_core::duration::Duration>",
        )
        .replace("b: Option<i64>", "b: Option<u64>")
        .replace("d: Option<i64>", "d: Option<u64>")
        .replace("p: Option<i64>", "p: Option<u64>")
        .replace("priority: Option<i32>", "priority: Option<u32>")
        .replace("priority: i32", "priority: u32")
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

    fixup_types(raw)
}

const KOPIUM_OUTPUT_FILE: &str = "generated.rs";

fn kopium_output_path() -> PathBuf {
    PathBuf::from(std::env::var("OUT_DIR").unwrap()).join(KOPIUM_OUTPUT_FILE)
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
    let agent_crd_contents = {
        let agent_crd_path =
            PathBuf::from(std::env::var("GW_CRD_PATH").expect("GW_CRD_PATH var unset"))
                .join("gwint.githedgehog.com_gatewayagents.yaml");
        let mut agent_crd_file = std::fs::OpenOptions::new()
            .read(true)
            .write(false)
            .open(&agent_crd_path)
            .unwrap_or_else(|e| {
                panic!(
                    "failed to open {path}: {e}",
                    path = agent_crd_path.to_str().expect("non unicode crd path")
                )
            });
        let mut contents = String::with_capacity(
            agent_crd_file
                .metadata()
                .expect("unable to get crd metadata")
                .len() as usize,
        );
        agent_crd_file
            .read_to_string(&mut contents)
            .unwrap_or_else(|e| panic!("unable to read crd data into string: {e}"));
        contents
    };
    let agent_generated_code = generate_rust_for_crd(&agent_crd_contents);

    if !code_needs_regen(&agent_generated_code) {
        println!("cargo:note=No changes to code generated from CRD");
        return;
    }

    let output_file = kopium_output_path();
    fs::write(&output_file, agent_generated_code)
        .expect("Failed to write generated agent CRD code");

    let sysroot = dpdk_sysroot_helper::get_sysroot();

    let rerun_if_changed = ["build.rs", sysroot.as_str()];
    for file in rerun_if_changed {
        println!("cargo:rerun-if-changed={file}");
    }

    println!(
        "cargo:note=Generated gateway agent CRD types written to {:?}",
        output_file
    );
}
