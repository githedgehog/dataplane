use std::env;
use std::path::Path;

// from https://stackoverflow.com/questions/73595435/how-to-get-profile-from-cargo-toml-in-build-rs-or-at-runtime
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

pub fn get_project_root() -> String {
    env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set")
}

pub fn get_compile_env() -> String {
    env::var("COMPILE_ENV").expect("COMPILE_ENV not set")
}

pub fn get_sysroot() -> String {
    let sysroot_env = env::var("SYSROOT").expect("sysroot env not set");
    let target = get_target_name();
    let profile = get_profile_name();
    let expected_sysroot = format!("{sysroot_env}/{target}/{profile}");
    let expected_sysroot_path = Path::new(&expected_sysroot);
    match expected_sysroot_path.exists() {
        true => expected_sysroot,
        false => {
            let fallback_sysroot = format!("/sysroot/{target}/{profile}");
            let fallback_sysroot_path = Path::new(&fallback_sysroot);
            match fallback_sysroot_path.exists() {
                true => fallback_sysroot,
                false => {
                    panic!("sysroot not found at {expected_sysroot} or {fallback_sysroot}")
                }
            }
        }
    }
}
