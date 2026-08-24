// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

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
