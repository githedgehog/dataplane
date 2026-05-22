// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![cfg(test)]

use concurrency::concurrency_mode;

// This module does not contain tests, but helpers to build the context (VpcTable, allocator) used
// by tests in other modules. These helpers are not to be used outside of tests.
mod context {
    use crate::stateful::allocator_writer::StatefulNatConfig;
    use crate::stateful::apalloc::alloc::IpAllocator;
    use crate::stateful::apalloc::{NatAllocator, PoolTable, PoolTableKey};
    use config::external::overlay::vpc::{Peering, ValidatedVpcTable, Vpc, VpcTable};
    use config::external::overlay::vpcpeering::{VpcExpose, VpcManifest};
    use net::ip::NextHeader;
    use net::packet::VpcDiscriminant;
    use net::udp::UdpPort;
    use net::vxlan::Vni;
    use net::{IpProtoKey, UdpProtoKey};
    use std::net::{IpAddr, Ipv4Addr};
    use std::str::FromStr;

    #[allow(unused)]
    pub fn addr_v4(ip: &str) -> Ipv4Addr {
        Ipv4Addr::from_str(ip).unwrap()
    }
    #[allow(unused)]
    pub fn addr_v4_bits(ip: &str) -> u32 {
        addr_v4(ip).to_bits()
    }
    #[allow(unused)]
    pub fn ipaddr(ip: &str) -> IpAddr {
        IpAddr::from_str(ip).unwrap()
    }

    pub fn vni1() -> Vni {
        Vni::new_checked(100).unwrap()
    }
    pub fn vni2() -> Vni {
        Vni::new_checked(200).unwrap()
    }
    pub fn vpcd1() -> VpcDiscriminant {
        VpcDiscriminant::from_vni(vni1())
    }
    pub fn vpcd2() -> VpcDiscriminant {
        VpcDiscriminant::from_vni(vni2())
    }

    #[allow(unused)]
    pub fn udp_proto_key(src_port: u16, dst_port: u16) -> IpProtoKey {
        IpProtoKey::Udp(UdpProtoKey {
            src_port: UdpPort::new_checked(src_port).unwrap(),
            dst_port: UdpPort::new_checked(dst_port).unwrap(),
        })
    }

    pub fn get_ip_allocator_v4(
        pool: &mut PoolTable<Ipv4Addr, Ipv4Addr>,
        dst_vpcd: VpcDiscriminant,
        protocol: NextHeader,
        src_ip: Ipv4Addr,
    ) -> &IpAllocator<Ipv4Addr> {
        pool.get(&PoolTableKey::new(
            protocol,
            dst_vpcd,
            src_ip,
            Ipv4Addr::from_str("255.255.255.255").unwrap(),
        ))
        .unwrap()
    }

    fn build_context() -> ValidatedVpcTable {
        // Exposes and manifests
        let expose1 = VpcExpose::empty()
            .make_stateful_nat(None)
            .unwrap()
            .ip("1.1.0.0/16".into())
            .ip("1.2.0.0/15".into())
            .as_range("10.1.0.0/30".into())
            .unwrap()
            .not_as("10.1.0.3/32".into())
            .unwrap();
        let expose2 = VpcExpose::empty().ip("2.0.0.0/16".into());

        let manifest1 = VpcManifest::with_exposes("VPC-1", vec![expose1, expose2]);

        let expose3 = VpcExpose::empty()
            .ip("3.0.0.0/24".into())
            .ip("3.0.2.0/24".into());
        let expose4 = VpcExpose::empty().ip("4.0.0.0/16".into());

        let manifest2 = VpcManifest::with_exposes("VPC-2", vec![expose3, expose4]);

        // Peerings
        let peering1 = Peering {
            name: "test_peering1".into(),
            local: manifest1.clone(),
            remote: manifest2.clone(),
            remote_id: "12345".try_into().unwrap(),
            gwgroup: None,
        };
        let peering2 = Peering {
            name: "test_peering2".into(),
            local: manifest2,
            remote: manifest1,
            remote_id: "67890".try_into().unwrap(),
            gwgroup: None,
        };

        // VPC-1
        let mut vpc1 = Vpc::new("VPC-1", "67890", vni1().as_u32()).unwrap();
        vpc1.peerings.push(peering1.clone());

        // VPC-2
        let mut vpc2 = Vpc::new("VPC-2", "12345", vni2().as_u32()).unwrap();
        vpc2.peerings.push(peering2.clone());

        // VPC table
        let mut vpctable = VpcTable::new();
        vpctable.add(vpc1).unwrap();
        vpctable.add(vpc2).unwrap();

        vpctable.validate().unwrap()
    }

    pub fn build_allocator() -> NatAllocator {
        let vpc_table = build_context();
        let config = StatefulNatConfig::new(&vpc_table, 1);
        NatAllocator::new(config)
    }
}

mod tests {
    use super::context::*;
    use concurrency::sync::Arc;
    use concurrency::thread;
    use net::ip::NextHeader;

    // do not mark as a test
    #[allow(dead_code)] // used by shuttle tests
    pub(super) fn concurrent_allocations() {
        let allocator = build_allocator();
        let allocator_arc = Arc::new(allocator);
        let allocator1 = allocator_arc.clone();
        let allocator2 = allocator_arc.clone();
        let allocator3 = allocator_arc.clone();

        let mut handles = vec![];

        handles.push(thread::spawn(move || {
            let _allocation1 = allocator1
                .allocate_v4(vpcd2(), addr_v4("1.1.0.0"), NextHeader::TCP)
                .unwrap();
        }));
        handles.push(thread::spawn(move || {
            let _allocation2 = allocator2
                .allocate_v4(vpcd2(), addr_v4("1.1.0.0"), NextHeader::TCP)
                .unwrap();
        }));
        handles.push(thread::spawn(move || {
            let _allocation3 = allocator3
                .allocate_v4(vpcd2(), addr_v4("1.1.0.0"), NextHeader::TCP)
                .unwrap();
        }));

        let _results: Vec<()> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();

        // All allocations got out of scope and dropped when the threads terminated.

        let mut allocator_again = Arc::try_unwrap(allocator_arc).unwrap();
        let (bitmap, in_use) = get_ip_allocator_v4(
            &mut allocator_again.pools_src44,
            vpcd2(),
            NextHeader::TCP,
            addr_v4("1.1.0.0"),
        )
        .get_pool_clone_for_tests();
        assert_eq!(bitmap.len(), 3); // 3 IP addresses available to NAT 1.1.0.0
        assert!(in_use.front().unwrap().upgrade().is_none()); // Weak references in list no longer resolve
    }
}

#[concurrency_mode(std)]
mod std_tests {
    use super::context::*;
    use crate::stateful::apalloc::PoolTableKey;
    use net::ip::NextHeader;

    #[test]
    fn test_build_allocator() {
        let allocator = build_allocator();

        /*
        println!("{allocator:?}");
        for table in [allocator.pools_src44, allocator.pools_dst44] {
            println!("{:?}", table.0.keys());
        }
        for table in [allocator.pools_src66, allocator.pools_dst66] {
            println!("{:?}", table.0.keys());
        }
        */

        assert!(
            allocator
                .pools_src44
                .0
                .keys()
                .all(|k| k.dst_id == vpcd2() || k.dst_id == vpcd1())
        );
        // One entry for each ".ip()" from the VPCExpose objects,
        // after exclusion ranges have been applied
        assert_eq!(
            allocator
                .pools_src44
                .0
                .keys()
                .filter(|k| k.protocol == NextHeader::TCP)
                .count(),
            2
        );
        assert_eq!(
            allocator
                .pools_src44
                .0
                .keys()
                .filter(|k| k.protocol == NextHeader::UDP)
                .count(),
            2
        );

        assert_eq!(allocator.pools_src66.0.len(), 0);

        let ip_allocator = allocator
            .pools_src44
            .get(&PoolTableKey::new(
                NextHeader::TCP,
                vpcd2(),
                addr_v4("1.1.0.0"),
                addr_v4("255.255.255.255"),
            ))
            .unwrap();
        let (bitmap, in_use) = ip_allocator.get_pool_clone_for_tests();

        assert!(bitmap.contains_range(addr_v4_bits("10.1.0.0")..=addr_v4_bits("10.1.0.2")));
        assert_eq!(bitmap.len(), 3);
        assert_eq!(in_use.len(), 0);
    }

    // Allocate IP addresses and ports for running NAT on a tuple from a simple packet. Ensure that
    // the expected IPs are allocated, and then that the allocator frees them when the allocated
    // objects are dropped.
    #[test]
    fn test_allocate() {
        let mut allocator = build_allocator();
        let (bitmap, in_use) = get_ip_allocator_v4(
            &mut allocator.pools_src44,
            vpcd2(),
            NextHeader::TCP,
            addr_v4("1.1.0.0"),
        )
        .get_pool_clone_for_tests();
        assert_eq!(bitmap.len(), 3); // 3 IP addresses available to NAT 1.1.0.0
        assert_eq!(in_use.len(), 0); // None allocated yet

        let alloc_result = allocator
            .allocate_v4(vpcd2(), addr_v4("1.1.0.0"), NextHeader::TCP)
            .unwrap();
        println!("{alloc_result}");

        assert_eq!(alloc_result.allocation.ip(), addr_v4("10.1.0.0"));

        let (bitmap, in_use) = get_ip_allocator_v4(
            &mut allocator.pools_src44,
            vpcd2(),
            NextHeader::TCP,
            addr_v4("1.1.0.0"),
        )
        .get_pool_clone_for_tests();
        assert_eq!(bitmap.len(), 2); // 2 free IP addresses left to NAT 1.1.0.0
        assert_eq!(in_use.len(), 1); // 1 allocated, in use

        drop(alloc_result);
        println!("Dropped allocation");

        let (bitmap, in_use) = get_ip_allocator_v4(
            &mut allocator.pools_src44,
            vpcd2(),
            NextHeader::TCP,
            addr_v4("1.1.0.0"),
        )
        .get_pool_clone_for_tests();
        assert_eq!(bitmap.len(), 3); // 3 IP addresses available to NAT 1.1.0.0
        assert_eq!(in_use.len(), 1); // One weak reference still in the list
        assert!(in_use.front().unwrap().upgrade().is_none()); // But it no longer resolves
    }

    #[test]
    // Allocate an IP for a TCP packet, then for a UDP packet.
    fn test_tcp_udp() {
        let mut allocator = build_allocator();
        let (bitmap, in_use) = get_ip_allocator_v4(
            &mut allocator.pools_src44,
            vpcd2(),
            NextHeader::TCP,
            addr_v4("1.1.0.0"),
        )
        .get_pool_clone_for_tests();
        assert_eq!(bitmap.len(), 3); // 3 IP addresses available to NAT 1.1.0.0 (TCP)
        assert_eq!(in_use.len(), 0); // None allocated yet

        let (bitmap, in_use) = get_ip_allocator_v4(
            &mut allocator.pools_src44,
            vpcd2(),
            NextHeader::UDP,
            addr_v4("1.1.0.0"),
        )
        .get_pool_clone_for_tests();
        assert_eq!(bitmap.len(), 3); // 3 free IP addresses left to NAT 1.1.0.0 (UDP)
        assert_eq!(in_use.len(), 0); // None allocated yet

        // Allocate for TCP
        let tcp_allocation = allocator
            .allocate_v4(vpcd2(), addr_v4("1.1.0.0"), NextHeader::TCP)
            .unwrap();
        println!("{tcp_allocation}");

        // Check number of allocated IPs for TCP after we have allocated for TCP
        let (bitmap, in_use) = get_ip_allocator_v4(
            &mut allocator.pools_src44,
            vpcd2(),
            NextHeader::TCP,
            addr_v4("1.1.0.0"),
        )
        .get_pool_clone_for_tests();
        assert_eq!(bitmap.len(), 2); // 2 free IP addresses left to NAT 1.1.0.0 (TCP)
        assert_eq!(in_use.len(), 1); // 1 allocated, in use

        // Check number of allocated IPs for UDP after we have allocated for TCP
        let (bitmap, in_use) = get_ip_allocator_v4(
            &mut allocator.pools_src44,
            vpcd2(),
            NextHeader::UDP,
            addr_v4("1.1.0.0"),
        )
        .get_pool_clone_for_tests();
        assert_eq!(bitmap.len(), 3); // 3 free IP addresses left to NAT 1.1.0.0 (UDP)
        assert_eq!(in_use.len(), 0); // None allocated yet

        // Allocate for UDP
        let udp_allocation = allocator
            .allocate_v4(vpcd2(), addr_v4("1.1.0.0"), NextHeader::UDP)
            .unwrap();
        println!("{udp_allocation}");

        // Check number of allocated IPs for TCP after we have allocated for UDP
        let (bitmap, in_use) = get_ip_allocator_v4(
            &mut allocator.pools_src44,
            vpcd2(),
            NextHeader::TCP,
            addr_v4("1.1.0.0"),
        )
        .get_pool_clone_for_tests();
        assert_eq!(bitmap.len(), 2); // 2 free IP addresses left to NAT 1.1.0.0 (TCP)
        assert_eq!(in_use.len(), 1); // 1 allocated, in use

        // Check number of allocated IPs for UDP after we have allocated for UDP
        let (bitmap, in_use) = get_ip_allocator_v4(
            &mut allocator.pools_src44,
            vpcd2(),
            NextHeader::UDP,
            addr_v4("1.1.0.0"),
        )
        .get_pool_clone_for_tests();
        assert_eq!(bitmap.len(), 2); // 2 free IP addresses left to NAT 1.1.0.0 (UDP)
        assert_eq!(in_use.len(), 1); // 1 allocated, in use
    }
}

/// Multi-backend concurrency tests for the NAT allocator.  Each
/// `#[concurrency::test]` runs once on the default backend (real OS threads
/// + parking_lot), under `loom::model` on `--features loom`, and through
/// shuttle's PortfolioRunner (Random + PCT, plus DFS on `--features
/// shuttle_dfs`) on `--features shuttle`.  `concurrency::stress` configures
/// a 4 MiB shuttle stack so the allocator's per-block atomic arrays fit
/// even under shuttle's instrumented primitives (each `AtomicBool` runs
/// ~100 bytes there).
mod concurrency_tests {
    use super::context::*;
    use super::tests;
    use concurrency::sync::Arc;
    use concurrency::thread;
    use net::ip::NextHeader;

    /// Two threads allocating against distinct source IPs.  Control test:
    /// the allocator should service independent IPs without interference.
    #[concurrency::test]
    fn test_concurrent_allocations_two_ips() {
        let allocator = build_allocator();
        let allocator1 = Arc::new(allocator);
        let allocator2 = allocator1.clone();

        let t1 = thread::spawn(move || {
            let _allocation1 = allocator1
                .allocate_v4(vpcd2(), addr_v4("1.1.0.0"), NextHeader::TCP)
                .unwrap();
        });
        let t2 = thread::spawn(move || {
            let _allocation2 = allocator2
                .allocate_v4(vpcd2(), addr_v4("1.2.0.0"), NextHeader::TCP)
                .unwrap();
        });
        t1.join().unwrap();
        t2.join().unwrap();
    }

    /// Three threads contending for the same source IP (1.1.0.0).  Heavier
    /// exercise of the allocator's per-pool locking.  Body lives in the
    /// sibling `tests::concurrent_allocations` helper so the shape stays
    /// shared with anything else that wants to drive the same scenario.
    #[concurrency::test]
    fn test_concurrent_allocations_three_workers() {
        tests::concurrent_allocations();
    }

    /// Smoke test that the model checker actually catches a race: the
    /// spawned thread writes 1 to the mutex, the main thread asserts the
    /// value is 0.  Under shuttle's Random + PCT portfolio (or loom's
    /// exhaustive search) the racy interleaving is reachable, so the
    /// assertion panics and `#[should_panic]` is satisfied.  Under the
    /// default backend a single one-shot run is non-deterministic, so the
    /// test is gated to the model-checker backends only.
    #[cfg(any(feature = "loom", feature = "shuttle"))]
    #[concurrency::test]
    #[should_panic(expected = "assertion `left == right` failed")]
    fn test_ensure_shuttle_works() {
        use concurrency::sync::Mutex;
        let lock = Arc::new(Mutex::new(0u64));
        let lock2 = lock.clone();

        thread::spawn(move || {
            *lock.lock() = 1;
        });

        assert_eq!(0, *lock2.lock());
    }
}
