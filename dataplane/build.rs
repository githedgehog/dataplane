// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Build script that detects which `-Zsanitizer=<kind>` (if any) is active and
//! re-exports it as an ordinary `cfg`.
//!
//! We cannot read the built-in `cfg(sanitize = "...")` from source without the
//! unstable `cfg_sanitize` feature, and gating the whole binary on a nightly
//! feature would break a plain `cargo build` on stable. Sniffing the rustflags
//! here keeps the crate stable-buildable while still letting `src/sanitizer.rs`
//! compile in the matching runtime hooks (e.g. baked-in `ThreadSanitizer`
//! suppressions) for -- and only for -- the relevant sanitizer build.

fn main() {
    #[cfg(feature = "dpdk")]
    dpdk_sysroot_helper::use_sysroot();

    const SANITIZERS: [(&str, &str); 2] = [
        ("sanitizer=thread", "sanitize_thread"),
        ("sanitizer=address", "sanitize_address"),
    ];

    // Declare every cfg we might set so the crate's `unexpected_cfgs` lint stays
    // quiet even in the builds where we don't set it.
    for (_, cfg) in SANITIZERS {
        println!("cargo::rustc-check-cfg=cfg({cfg})");
    }

    // Build scripts receive the effective rustflags via `CARGO_ENCODED_RUSTFLAGS`
    // (unit-separated); fall back to the plain `RUSTFLAGS` string.
    let rustflags = std::env::var("CARGO_ENCODED_RUSTFLAGS")
        .map(|encoded| encoded.replace('\x1f', " "))
        .or_else(|_| std::env::var("RUSTFLAGS"))
        .unwrap_or_default();

    for (token, cfg) in SANITIZERS {
        if rustflags.contains(token) {
            println!("cargo::rustc-cfg={cfg}");
        }
    }

    println!("cargo::rerun-if-env-changed=CARGO_ENCODED_RUSTFLAGS");
    println!("cargo::rerun-if-env-changed=RUSTFLAGS");
}
