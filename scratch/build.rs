// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

fn main() {
    let sysroot = dpdk_sysroot_helper::get_sysroot();
    let project_root = dpdk_sysroot_helper::get_project_root();
    let rerun_if_changed = ["build.rs".to_string(), format!("{project_root}/../sysroot")];
    for file in &rerun_if_changed {
        println!("cargo:rerun-if-changed={file}");
    }
    println!("cargo:rustc-link-search=native={sysroot}/lib");
    println!("cargo:rustc-link-arg=--sysroot={sysroot}");
}
