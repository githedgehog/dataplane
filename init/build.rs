// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

fn main() {
    let sysroot = dpdk_sysroot_helper::get_sysroot();
    println!("cargo:rustc-link-search=all={sysroot}/lib");
    println!("cargo:rustc-link-arg=--sysroot={sysroot}");
}
