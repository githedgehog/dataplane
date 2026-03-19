// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

fn main() {
    #[cfg(feature = "dpdk")]
    dpdk_sysroot_helper::use_sysroot();
}
