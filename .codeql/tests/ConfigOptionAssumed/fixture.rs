// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![allow(unused)]

pub struct CfgVrf { pub vni: Option<u32>, pub vpc_id: Option<String>, pub tableid: Option<u32>, pub mtu: Option<u16> }

fn shapes(v: &CfgVrf) -> Option<u32> {
    let a = v.vni.expect("vni not set"); // BAD
    let b = v.vni.unwrap(); // BAD
    let c = v.vpc_id.as_ref().unwrap(); // BAD: through as_ref
    let d = v.tableid.unwrap_or_else(|| unreachable!()); // BAD
    match &v.vpc_id {
        None => panic!("no vpc_id"), // BAD
        Some(id) => {}
    }
    match v.tableid {
        None => unreachable!(), // BAD
        Some(t) => {}
    }
    let Some(t) = v.tableid else { unreachable!() }; // BAD

    let m = v.mtu.unwrap_or(1500); // OK: a default
    if let Some(m) = v.mtu {} // OK
    let x = v.mtu.map(u32::from); // OK
    let y = v.vni?; // OK: propagated
    match v.mtu {
        None => {} // OK: handled
        Some(m) => {}
    }
    Some(0)
}
