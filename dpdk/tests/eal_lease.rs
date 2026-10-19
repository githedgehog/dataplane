// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! An ACL context that outlives its EAL keeps the EAL from being cleaned up under it.
//!
//! This needs an EAL of its own that it can drop, so it runs in its own process.

use core::num::NonZero;

use dataplane_dpdk::acl::{
    AclBuildConfig, AclContext, AclCreateError, AclCreateParams, FieldDef, FieldSize, FieldType,
};
use dataplane_dpdk::eal::{self, EalLease, EalNotRunning};
use dataplane_dpdk::socket::SocketId;

const NUM_FIELDS: usize = 2;

fn new_context(name: &str) -> Result<AclContext<NUM_FIELDS>, AclCreateError> {
    let params =
        AclCreateParams::<NUM_FIELDS>::new(name, SocketId::ANY, NonZero::new(16).unwrap()).unwrap();
    let fields = [
        FieldDef::new(FieldType::Bitmask, FieldSize::One, 0, 0, 0),
        FieldDef::new(FieldType::Mask, FieldSize::Four, 1, 1, 4),
    ];
    AclContext::new(params, AclBuildConfig::new(1, fields, 0).unwrap())
}

#[test]
fn an_acl_context_outliving_the_eal_blocks_cleanup() {
    assert_eq!(EalLease::acquire().err(), Some(EalNotRunning));
    assert!(matches!(
        new_context("before_eal"),
        Err(AclCreateError::EalNotRunning(EalNotRunning))
    ));

    let cpus = eal::main_lcore_arg();
    let eal = eal::init([
        "--no-huge",
        "--no-pci",
        "--in-memory",
        "--no-telemetry",
        "--no-shconf",
        "--iova-mode=va",
        "--lcores",
        &cpus,
    ]);
    let context = new_context("outlives_eal").unwrap();

    // The context holds a lease, so this skips `rte_eal_cleanup` instead of freeing its memory.
    drop(eal);
    assert!(matches!(
        new_context("after_eal"),
        Err(AclCreateError::EalNotRunning(EalNotRunning))
    ));

    // `rte_acl_free` on memory that cleanup had released would fault here (or under ASan).
    drop(context);
}
