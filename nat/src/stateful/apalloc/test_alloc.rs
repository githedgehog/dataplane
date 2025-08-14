// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use concurrency::concurrency_mode;

// This module does not contain tests, but helpers to build the context (VpcTable, allocator) used
// by tests in other modules. These helpers are not to be used outside of tests.
#[cfg(test)]
mod context {
    use crate::stateful::allocator::AllocationResult;
    use crate::stateful::apalloc::alloc::IpAllocator;
    use crate::stateful::apalloc::port_alloc::AllocatedPort;
    use crate::stateful::apalloc::setup::build_nat_allocator;
    use crate::stateful::apalloc::{NatDefaultAllocator, NatIpWithBitmap, PoolTable, PoolTableKey};
    use config::ConfigError;
    use config::external::overlay::vpc::{Peering, Vpc, VpcTable};
    use config::external::overlay::vpcpeering::{VpcExpose, VpcManifest};
    use net::ip::NextHeader;
    use net::vxlan::Vni;
    use std::net::Ipv4Addr;
    use std::str::FromStr;

    pub fn addr_v4(ip: &str) -> Ipv4Addr {
        Ipv4Addr::from_str(ip).unwrap()
    }
    pub fn addr_v4_bits(ip: &str) -> u32 {
        addr_v4(ip).to_bits()
    }

    pub fn vni1() -> Vni {
        Vni::new_checked(100).unwrap()
    }
    pub fn vni2() -> Vni {
        Vni::new_checked(200).unwrap()
    }

    pub fn print_allocation<I: NatIpWithBitmap>(allocation: &AllocationResult<AllocatedPort<I>>) {
        let format_ip_port = |ip_port: &Option<AllocatedPort<I>>| {
            if let Some(ip_port) = ip_port {
                format!("{:?}:{:?}", ip_port.ip(), ip_port.port().as_u16())
            } else {
                "<none>".to_string()
            }
        };
        println!("src: {}", format_ip_port(&allocation.src));
        println!("dst: {}", format_ip_port(&allocation.dst));
        println!("return_src: {}", format_ip_port(&allocation.return_src));
        println!("return_dst: {}", format_ip_port(&allocation.return_dst));
    }

    pub fn get_ip_allocator_v4(
        pool: &mut PoolTable<Ipv4Addr, Ipv4Addr>,
        src_vni: Vni,
        dst_vni: Vni,
        protocol: NextHeader,
        src_ip: Ipv4Addr,
    ) -> &IpAllocator<Ipv4Addr> {
        pool.get(&PoolTableKey::new(
            protocol,
            src_vni,
            dst_vni,
            src_ip,
            Ipv4Addr::from_str("255.255.255.255").unwrap(),
        ))
        .unwrap()
    }

    fn build_context() -> VpcTable {
        // Exposes and manifests
        let expose1 = VpcExpose::empty()
            .ip("1.1.0.0/16".into())
            .ip("1.2.0.0/16".into())
            .ip("1.3.0.0/16".into())
            .as_range("10.1.0.0/30".into())
            .not_as("10.1.0.3/32".into());
        let expose2 = VpcExpose::empty()
            .ip("2.0.0.0/16".into())
            .as_range("10.2.0.0/29".into());

        let manifest1 = VpcManifest {
            name: "VPC-1".into(),
            exposes: vec![expose1, expose2],
        };

        let expose3 = VpcExpose::empty()
            .ip("3.0.0.0/24".into())
            .ip("3.0.1.0/24".into())
            .as_range("10.3.0.0/30".into());
        let expose4 = VpcExpose::empty()
            .ip("4.0.0.0/16".into())
            .as_range("10.4.0.0/31".into())
            .as_range("10.4.1.0/30".into());

        let manifest2 = VpcManifest {
            name: "VPC-2".into(),
            exposes: vec![expose3, expose4],
        };

        // Peerings
        let peering1 = Peering {
            name: "test_peering1".into(),
            local: manifest1.clone(),
            remote: manifest2.clone(),
            remote_id: "12345".try_into().unwrap(),
        };
        let peering2 = Peering {
            name: "test_peering2".into(),
            local: manifest2,
            remote: manifest1,
            remote_id: "67890".try_into().unwrap(),
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

        vpctable
    }

    pub fn build_allocator() -> Result<NatDefaultAllocator, ConfigError> {
        let vpc_table = build_context();
        build_nat_allocator(&vpc_table)
    }
}

#[cfg(test)]
mod tests {
    use super::context::*;
    use crate::stateful::NatTuple;
    use crate::stateful::allocator::NatAllocator;
    use crate::stateful::apalloc::PoolTableKey;
    use concurrency::concurrency_mode;
    use net::ip::NextHeader;

    #[test]
    fn test_build_allocator() {
        let allocator = build_allocator().unwrap();

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
                .all(|k| (k.src_id == vni1() && k.dst_id == vni2())
                    || (k.src_id == vni2() && k.dst_id == vni1()))
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
            7
        );
        assert_eq!(
            allocator
                .pools_src44
                .0
                .keys()
                .filter(|k| k.protocol == NextHeader::UDP)
                .count(),
            7
        );

        assert!(
            allocator
                .pools_dst44
                .0
                .keys()
                .all(|k| (k.src_id == vni1() && k.dst_id == vni2())
                    || (k.src_id == vni2() && k.dst_id == vni1()))
        );
        // One entry for each ".as_range()" from the VPCExpose objects,
        // after exclusion ranges have been applied
        assert_eq!(
            allocator
                .pools_dst44
                .0
                .keys()
                .filter(|k| k.protocol == NextHeader::TCP)
                .count(),
            6
        );
        assert_eq!(
            allocator
                .pools_dst44
                .0
                .keys()
                .filter(|k| k.protocol == NextHeader::UDP)
                .count(),
            6
        );

        assert_eq!(allocator.pools_src66.0.len(), 0);
        assert_eq!(allocator.pools_dst66.0.len(), 0);

        let ip_allocator = allocator
            .pools_src44
            .get(&PoolTableKey::new(
                NextHeader::TCP,
                vni1(),
                vni2(),
                addr_v4("1.1.0.0"),
                addr_v4("255.255.255.255"),
            ))
            .unwrap();
        let (bitmap, in_use) = ip_allocator.get_pool_clone_for_tests();

        assert!(bitmap.contains_range(addr_v4_bits("10.1.0.0")..=addr_v4_bits("10.1.0.2")));
        assert_eq!(bitmap.len(), 3);
        assert_eq!(in_use.len(), 0);

        let ip_allocator = allocator
            .pools_dst44
            .get(&PoolTableKey::new(
                NextHeader::TCP,
                vni1(),
                vni2(),
                addr_v4("10.3.0.0"),
                addr_v4("255.255.255.255"),
            ))
            .unwrap();
        let (bitmap, in_use) = ip_allocator.get_pool_clone_for_tests();

        assert!(bitmap.contains_range(addr_v4_bits("3.0.0.0")..=addr_v4_bits("3.0.1.255")));
        assert_eq!(bitmap.len(), 512);
        assert_eq!(in_use.len(), 0);
    }

    // Allocate IP addresses and ports for running NAT on a tuple from a simple packet. Ensure that
    // the expected IPs are allocated, and then that the allocator frees them when the allocated
    // objects are dropped.
    #[test]
    fn test_allocate() {
        let tuple = NatTuple::new(
            addr_v4("1.1.0.0"),
            addr_v4("10.3.0.2"),
            Some(1234),
            Some(5678),
            NextHeader::TCP,
            vni1(),
            vni2(),
        );

        let mut allocator = build_allocator().unwrap();
        let (bitmap, in_use) = get_ip_allocator_v4(
            &mut allocator.pools_src44,
            vni1(),
            vni2(),
            NextHeader::TCP,
            addr_v4("1.1.0.0"),
        )
        .get_pool_clone_for_tests();
        assert_eq!(bitmap.len(), 3); // 3 IP addresses available to NAT 1.1.0.0
        assert_eq!(in_use.len(), 0); // None allocated yet

        let allocation = allocator.allocate_v4(&tuple).unwrap();
        print_allocation(&allocation);

        assert!(allocation.src.is_some());
        assert!(allocation.dst.is_some());
        assert!(allocation.return_src.is_some());
        assert!(allocation.return_dst.is_some());

        assert_eq!(allocation.src.as_ref().unwrap().ip(), addr_v4("10.1.0.0"));
        assert_eq!(allocation.dst.as_ref().unwrap().ip(), addr_v4("3.0.0.0"));
        assert_eq!(
            allocation.return_src.as_ref().unwrap().ip(),
            addr_v4("10.3.0.2")
        );
        assert_eq!(
            allocation.return_src.as_ref().unwrap().port().as_u16(),
            5678
        );
        assert_eq!(
            allocation.return_dst.as_ref().unwrap().ip(),
            addr_v4("1.1.0.0")
        );
        assert_eq!(
            allocation.return_dst.as_ref().unwrap().port().as_u16(),
            1234
        );

        let (bitmap, in_use) = get_ip_allocator_v4(
            &mut allocator.pools_src44,
            vni1(),
            vni2(),
            NextHeader::TCP,
            addr_v4("1.1.0.0"),
        )
        .get_pool_clone_for_tests();
        assert_eq!(bitmap.len(), 2); // 2 free IP addresses left to NAT 1.1.0.0
        assert_eq!(in_use.len(), 1); // 1 allocated, in use

        drop(allocation);
        println!("Dropped allocation");

        let (bitmap, in_use) = get_ip_allocator_v4(
            &mut allocator.pools_src44,
            vni1(),
            vni2(),
            NextHeader::TCP,
            addr_v4("1.1.0.0"),
        )
        .get_pool_clone_for_tests();
        assert_eq!(bitmap.len(), 3); // 3 IP addresses available to NAT 1.1.0.0
        assert_eq!(in_use.len(), 1); // One weak reference still in the list
        assert!(in_use.front().unwrap().upgrade().is_none()); // But it no longer resolves
    }

    #[concurrency_mode(std)]
    use std::{sync::Arc, thread};

    #[concurrency_mode(shuttle)]
    use shuttle::sync::{Arc, Mutex};

    #[concurrency_mode(loom)]
    use loom::sync::{Arc, Mutex};

    // This test is NOT a shuttle test. It validates that a basic example with threads works with or
    // without shuttle components (depending on how we compile), as a control test in case shuttle
    // tests do not work. For example, it helped understand that memory usage for Atomics is
    // different in shuttle than in std, and that just testing simple allocations as we do here was
    // not broken - we just needed to increase stack memory for shuttle's runner.
    #[concurrency_mode(std)]
    #[test]
    fn test_concurrent_allocations_without_shuttle() {
        let tuple1 = NatTuple::new(
            addr_v4("1.1.0.0"),
            addr_v4("10.3.0.2"),
            Some(1111),
            Some(1112),
            NextHeader::TCP,
            vni1(),
            vni2(),
        );
        let tuple2 = NatTuple::new(
            addr_v4("2.0.1.3"),
            addr_v4("10.4.1.1"),
            Some(2222),
            Some(2223),
            NextHeader::TCP,
            vni1(),
            vni2(),
        );

        let allocator = build_allocator().unwrap();
        let allocator1 = Arc::new(allocator);
        let allocator2 = allocator1.clone();

        thread::spawn(move || {
            let _allocation1 = allocator1.allocate_v4(&tuple1).unwrap();
        });
        thread::spawn(move || {
            let _allocation2 = allocator2.allocate_v4(&tuple2).unwrap();
        });
    }
}

#[concurrency_mode(shuttle)]
mod tests_shuttle {
    use super::context::*;
    use crate::stateful::NatTuple;
    use crate::stateful::allocator::NatAllocator;
    use concurrency::concurrency_mode;
    use net::ip::NextHeader;
    use shuttle::sync::{Arc, Mutex};
    use shuttle::thread;

    #[should_panic(expected = "assertion `left == right` failed")]
    #[test]
    fn test_ensure_shuttle_works() {
        shuttle::check_random(
            || {
                let lock = Arc::new(Mutex::new(0u64));
                let lock2 = lock.clone();

                thread::spawn(move || {
                    *lock.lock().unwrap() = 1;
                });

                assert_eq!(0, *lock2.lock().unwrap());
            },
            100,
        );
    }
}
