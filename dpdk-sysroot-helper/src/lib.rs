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
pub fn get_project_root() -> String {
    env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set")
}

#[must_use]
pub fn get_compile_env() -> String {
    env::var("COMPILE_ENV").expect("COMPILE_ENV not set")
}

#[must_use]
pub fn get_sysroot() -> String {
    let compile_env = env::var("COMPILE_ENV").expect("COMPILE_ENV not set");
    let sysroot_env = format!("{compile_env}/sysroot");
    let target = get_target_name();
    let profile = get_profile_name();
    let expected_sysroot = format!("{sysroot_env}/{target}/{profile}");
    let expected_sysroot_path = Path::new(&expected_sysroot);
    if expected_sysroot_path.exists() {
        expected_sysroot
    } else {
        panic!("sysroot not found at {expected_sysroot}")
    }
}
