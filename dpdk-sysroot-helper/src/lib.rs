// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use std::env;
use std::path::Path;

// from https://stackoverflow.com/questions/73595435/how-to-get-profile-from-cargo-toml-in-build-rs-or-at-runtime
#[must_use]
pub fn get_profile_name() -> String {
    // The profile name is always the 3rd last part of the path (with 1 based indexing).
    // e.g., /code/core/target/cli/build/my-build-info-9f91ba6f99d7a061/out
    env::var("OUT_DIR")
        .unwrap()
        .split(std::path::MAIN_SEPARATOR)
        .nth_back(3)
        .expect("failed to get profile name")
        .to_string()
}

#[must_use]
pub fn get_target_name() -> String {
    // The target name is always the 4th last part of the path (with 1 based indexing).
    // e.g., /code/core/target/cli/build/my-build-info-9f91ba6f99d7a061/out
    env::var("OUT_DIR")
        .unwrap()
        .split(std::path::MAIN_SEPARATOR)
        .nth_back(4)
        .expect("failed to get target name")
        .to_string()
}

#[must_use]
pub fn get_sysroot() -> String {
    let sysroot_env = env::var("SYSROOT").expect("SYSROOT not set");
    let sysroot_path = Path::new(&sysroot_env);
    if sysroot_path.exists() {
        sysroot_env
    } else {
        panic!("sysroot not found at {sysroot_env}")
    }
}

pub fn use_sysroot() {
    let sysroot = get_sysroot();
    println!("cargo:rustc-link-search=all={sysroot}/lib");
    println!("cargo:rustc-link-arg=--sysroot={sysroot}");
}
