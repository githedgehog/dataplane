// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Detects whether `#![feature(thread_spawn_hook)]` is available.
//!
//! The hook is what lets a driven clock be inherited by the threads a test spawns, which is what
//! makes the check in `virtual_time` precise rather than process-wide. It needs an unstable feature,
//! and the workspace's dev shell and nix build both set `RUSTC_BOOTSTRAP=1` -- but a build without
//! it must degrade rather than fail, so this asks the compiler instead of assuming.
//!
//! A probe compile rather than a channel check: the answer wanted is "does this exact toolchain
//! accept this exact feature", and a toolchain predating the feature would pass a channel check and
//! then fail the real build.

use std::process::Command;
use std::{env, fs, path::PathBuf};

fn main() {
    println!("cargo::rerun-if-env-changed=RUSTC_BOOTSTRAP");
    println!("cargo::rustc-check-cfg=cfg(has_spawn_hook)");

    let out = PathBuf::from(env::var_os("OUT_DIR").expect("cargo sets OUT_DIR"));
    let probe = out.join("spawn_hook_probe.rs");
    if fs::write(
        &probe,
        "#![feature(thread_spawn_hook)]\n\
         pub fn probe() { std::thread::add_spawn_hook(|_| || {}); }\n",
    )
    .is_err()
    {
        return;
    }

    let rustc = env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let accepted = Command::new(rustc)
        .args(["--crate-type=lib", "--emit=metadata", "-o"])
        .arg(out.join("spawn_hook_probe.rmeta"))
        .arg(&probe)
        .status()
        .is_ok_and(|status| status.success());

    if accepted {
        println!("cargo::rustc-cfg=has_spawn_hook");
    } else {
        println!(
            "cargo::warning=thread_spawn_hook is unavailable, so a test that drives the clock \
             cannot check the threads it spawns. Set RUSTC_BOOTSTRAP=1 (the dev shell does)."
        );
    }
}
