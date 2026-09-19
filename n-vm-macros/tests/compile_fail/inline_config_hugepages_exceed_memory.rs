// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

// The compile-time half of `the_builder_checks_what_it_builds`: a
// contradictory configuration must still fail the build, which is the property
// a non-const builder would have cost.
#[n_vm::test]
fn inline_config_hugepages_exceed_memory() {
    #[n_vm::config]
    const _: _ = n_vm::VmConfigBuilder::default()
        .guest_hugepages(n_vm::GuestHugePageConfig::Allocate {
            size: n_vm::GuestHugePageSize::Huge1G,
            count: 2,
        })
        .build();
}

fn main() {}
