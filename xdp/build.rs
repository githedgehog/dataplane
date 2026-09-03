// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Puts the compiled XDP program where `src/program.rs` can include it.
//!
//! The eBPF object is not built here: it needs a nightly toolchain and
//! bpf-linker, which the rest of the build does not. Build it beforehand with
//! `just build-ebpf`, or point `DATAPLANE_XDP_EBPF` at one.

fn main() {
    println!("cargo::rerun-if-changed=build.rs");
    #[cfg(feature = "runtime")]
    embed_ebpf();
}

/// Copy the eBPF object into `OUT_DIR` under the name `program.rs` includes.
#[cfg(feature = "runtime")]
fn embed_ebpf() {
    use std::path::PathBuf;

    println!("cargo::rerun-if-env-changed=DATAPLANE_XDP_EBPF");

    #[allow(clippy::expect_used)] // cargo always sets these
    let out_dir = PathBuf::from(std::env::var_os("OUT_DIR").expect("OUT_DIR is set by cargo"));
    #[allow(clippy::expect_used)] // cargo always sets these
    let manifest_dir = PathBuf::from(
        std::env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is set by cargo"),
    );
    let workspace_root = manifest_dir.parent().unwrap_or(&manifest_dir).to_path_buf();

    // `just build-ebpf` leaves the object in the workspace target
    // directory, under the BPF target and the profile it was built with.
    let candidates = [
        std::env::var_os("DATAPLANE_XDP_EBPF").map(PathBuf::from),
        Some(workspace_root.join("target/bpfel-unknown-none/release/dataplane-xdp-ebpf")),
        Some(workspace_root.join("target/bpfel-unknown-none/debug/dataplane-xdp-ebpf")),
    ];

    let destination = out_dir.join("dataplane-xdp-ebpf");
    for candidate in candidates.iter().flatten() {
        if !candidate.is_file() {
            continue;
        }
        println!("cargo::rerun-if-changed={}", candidate.display());
        if let Err(e) = std::fs::copy(candidate, &destination) {
            println!(
                "cargo::error=could not copy the XDP program from {}: {e}",
                candidate.display()
            );
        }
        return;
    }

    println!(
        "cargo::error=no XDP program found. Build one with `just build-ebpf`, or set \
         DATAPLANE_XDP_EBPF to the path of one. Looked in {}",
        candidates
            .iter()
            .flatten()
            .map(|c| c.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    );
}
