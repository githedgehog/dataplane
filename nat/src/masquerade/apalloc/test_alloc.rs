// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![cfg(test)]

use concurrency::concurrency_mode;

// This module does not contain tests, but helpers to build the context (VpcTable, allocator) used
// by tests in other modules. These helpers are not to be used outside of tests.
mod context {
    use crate::masquerade::allocator_writer::MasqueradeConfig;
    use crate::masquerade::apalloc::alloc::{IpAllocator, PoolSet};
    use crate::masquerade::apalloc::{NatAllocator, PoolTable, PoolTableKey};
    use config::external::overlay::vpc::{Peering, ValidatedVpcTable, Vpc, VpcTable};
    use config::external::overlay::vpcpeering::{VpcExpose, VpcManifest};
    use lpm::prefix::{L4Protocol, PortRange, PrefixWithOptionalPorts};
    use net::ip::NextHeader;
    use net::packet::VpcDiscriminant;
    use net::udp::UdpPort;
    use net::vxlan::Vni;
    use net::{IpProtoKey, UdpProtoKey};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::str::FromStr;

    #[allow(dead_code)]
    pub fn addr_v4(ip: &str) -> Ipv4Addr {
        Ipv4Addr::from_str(ip).unwrap()
    }
    #[allow(dead_code)]
    pub fn addr_v4_bits(ip: &str) -> u32 {
        addr_v4(ip).to_bits()
    }
    #[allow(dead_code)]
    pub fn ipaddr(ip: &str) -> IpAddr {
        IpAddr::from_str(ip).unwrap()
    }

    pub fn vni1() -> Vni {
        Vni::new_checked(100).unwrap()
    }
    pub fn vni2() -> Vni {
        Vni::new_checked(200).unwrap()
    }
    #[allow(dead_code)]
    pub fn vni3() -> Vni {
        Vni::new_checked(300).unwrap()
    }
    pub fn vpcd1() -> VpcDiscriminant {
        VpcDiscriminant::from_vni(vni1())
    }
    pub fn vpcd2() -> VpcDiscriminant {
        VpcDiscriminant::from_vni(vni2())
    }
    #[allow(dead_code)]
    pub fn vpcd3() -> VpcDiscriminant {
        VpcDiscriminant::from_vni(vni3())
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
        src_vpcd: VpcDiscriminant,
        dst_vpcd: VpcDiscriminant,
        protocol: NextHeader,
        src_ip: Ipv4Addr,
    ) -> &IpAllocator<Ipv4Addr> {
        let pool_set = pool
            .get(&PoolTableKey::new(
                protocol,
                src_vpcd,
                dst_vpcd,
                src_ip,
                Ipv4Addr::from_str("255.255.255.255").unwrap(),
            ))
            .unwrap();
        sole_region(pool_set)
    }

    // The public ranges in most of these fixtures do not overlap, so each expose owns exactly one
    // region and the tests can look straight at its allocator.
    pub fn sole_region(pool_set: &PoolSet<Ipv4Addr>) -> &IpAllocator<Ipv4Addr> {
        let mut regions = pool_set.regions();
        let region = regions.next().expect("expose has no region");
        assert!(
            regions.next().is_none(),
            "expose was cut into more than one region"
        );
        region.allocator()
    }

    fn build_context() -> ValidatedVpcTable {
        // Exposes and manifests
        let expose1 = VpcExpose::empty()
            .make_masquerade(None)
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

        // VPC-1 and VPC-2
        let mut vpc1 = Vpc::new("VPC-1", "67890", vni1().as_u32()).unwrap();
        let mut vpc2 = Vpc::new("VPC-2", "12345", vni2().as_u32()).unwrap();

        // Peerings
        let peering1 = Peering {
            name: "test_peering1".into(),
            local: manifest1.clone(),
            remote: manifest2.clone(),
            remote_id: "12345".try_into().unwrap(),
            remote_vni: vpc2.vni,
            gwgroup: "default".into(),
            acl: None,
        };
        let peering2 = Peering {
            name: "test_peering2".into(),
            local: manifest2,
            remote: manifest1,
            remote_id: "67890".try_into().unwrap(),
            remote_vni: vpc1.vni,
            gwgroup: "default".into(),
            acl: None,
        };

        vpc1.peerings.push(peering1.clone());
        vpc2.peerings.push(peering2.clone());

        // VPC table
        let mut vpctable = VpcTable::new();
        vpctable.add(vpc1).unwrap();
        vpctable.add(vpc2).unwrap();

        vpctable.validate().unwrap()
    }

    pub fn build_allocator() -> NatAllocator {
        let vpc_table = build_context();
        let config = MasqueradeConfig::new(&vpc_table);
        NatAllocator::new(config, 1)
    }

    #[allow(dead_code)]
    fn prefix_with_ports(prefix: &str, start: u16, end: u16) -> PrefixWithOptionalPorts {
        PrefixWithOptionalPorts::new(prefix.into(), Some(PortRange::new(start, end).unwrap()))
    }

    // Masquerade onto one public address, with a forwarding rule on port 8080 of it for one protocol
    // only. VPC-1 masquerades towards VPC-2.
    #[allow(dead_code)]
    fn build_context_port_forward_for(protocol: L4Protocol) -> ValidatedVpcTable {
        let masquerade = VpcExpose::empty()
            .make_masquerade(None)
            .unwrap()
            .ip("1.1.0.0/16".into())
            .as_range("10.1.0.0/32".into())
            .unwrap();
        let forward = VpcExpose::empty()
            .make_port_forwarding(None, Some(protocol))
            .unwrap()
            .ip(prefix_with_ports("1.1.0.5/32", 8080, 8080))
            .as_range(prefix_with_ports("10.1.0.0/32", 8080, 8080))
            .unwrap();
        let local = VpcManifest::with_exposes("VPC-1", vec![masquerade, forward]);
        let remote =
            VpcManifest::with_exposes("VPC-2", vec![VpcExpose::empty().ip("3.0.0.0/24".into())]);

        let mut vpc1 = Vpc::new("VPC-1", "67890", vni1().as_u32()).unwrap();
        let vpc2 = Vpc::new("VPC-2", "12345", vni2().as_u32()).unwrap();
        vpc1.peerings.push(Peering {
            name: "port_forward_peering".into(),
            local,
            remote,
            remote_id: "12345".try_into().unwrap(),
            remote_vni: vpc2.vni,
            gwgroup: "default".into(),
            acl: None,
        });

        let mut vpctable = VpcTable::new();
        vpctable.add(vpc1).unwrap();
        vpctable.add(vpc2).unwrap();
        vpctable.validate().unwrap()
    }

    #[allow(dead_code)]
    pub fn build_allocator_port_forward_for(protocol: L4Protocol) -> NatAllocator {
        let vpc_table = build_context_port_forward_for(protocol);
        NatAllocator::new(MasqueradeConfig::new(&vpc_table).set_randomize(false), 1)
    }

    // Two VPCs masquerade onto one public range toward the same peer.
    #[allow(dead_code)]
    fn build_context_shared_public_range() -> ValidatedVpcTable {
        let masquerade_manifest = |name: &str, private: &str| {
            VpcManifest::with_exposes(
                name,
                vec![
                    VpcExpose::empty()
                        .make_masquerade(None)
                        .unwrap()
                        .ip(private.into())
                        .as_range("10.1.0.0/30".into())
                        .unwrap(),
                ],
            )
        };
        let remote =
            VpcManifest::with_exposes("VPC-3", vec![VpcExpose::empty().ip("3.0.0.0/24".into())]);

        let mut vpc1 = Vpc::new("VPC-1", "67890", vni1().as_u32()).unwrap();
        let mut vpc2 = Vpc::new("VPC-2", "12345", vni2().as_u32()).unwrap();
        let vpc3 = Vpc::new("VPC-3", "11111", vni3().as_u32()).unwrap();

        vpc1.peerings.push(Peering {
            name: "shared_peering1".into(),
            local: masquerade_manifest("VPC-1", "1.1.0.0/16"),
            remote: remote.clone(),
            remote_id: "11111".try_into().unwrap(),
            remote_vni: vpc3.vni,
            gwgroup: "default".into(),
            acl: None,
        });
        vpc2.peerings.push(Peering {
            name: "shared_peering2".into(),
            local: masquerade_manifest("VPC-2", "2.1.0.0/16"),
            remote,
            remote_id: "11111".try_into().unwrap(),
            remote_vni: vpc3.vni,
            gwgroup: "default".into(),
            acl: None,
        });

        let mut vpctable = VpcTable::new();
        vpctable.add(vpc1).unwrap();
        vpctable.add(vpc2).unwrap();
        vpctable.add(vpc3).unwrap();

        vpctable.validate().unwrap()
    }

    #[allow(dead_code)]
    pub fn build_allocator_shared_public_range() -> NatAllocator {
        let vpc_table = build_context_shared_public_range();
        // Without randomization the first port block picked is deterministic, so two pools that
        // wrongly believe they each own the whole public range collide on their first allocation.
        let config = MasqueradeConfig::new(&vpc_table).set_randomize(false);
        NatAllocator::new(config, 1)
    }

    // Two VPCs using the *same* private prefix, each peering with the same destination VPC and
    // masquerading onto a public range of its own. Tenants reusing private address space is
    // ordinary, and is much of what NAT is for, so both are entitled to their own pool.
    #[allow(dead_code)]
    fn build_context_overlapping_private_prefixes() -> ValidatedVpcTable {
        let masquerade_manifest = |name: &str, public: &str| {
            VpcManifest::with_exposes(
                name,
                vec![
                    VpcExpose::empty()
                        .make_masquerade(None)
                        .unwrap()
                        .ip("192.168.0.0/16".into())
                        .as_range(public.into())
                        .unwrap(),
                ],
            )
        };
        let remote =
            VpcManifest::with_exposes("VPC-3", vec![VpcExpose::empty().ip("3.0.0.0/24".into())]);

        let mut vpc1 = Vpc::new("VPC-1", "67890", vni1().as_u32()).unwrap();
        let mut vpc2 = Vpc::new("VPC-2", "12345", vni2().as_u32()).unwrap();
        let vpc3 = Vpc::new("VPC-3", "11111", vni3().as_u32()).unwrap();

        vpc1.peerings.push(Peering {
            name: "overlapping_peering1".into(),
            local: masquerade_manifest("VPC-1", "10.1.0.0/30"),
            remote: remote.clone(),
            remote_id: "11111".try_into().unwrap(),
            remote_vni: vpc3.vni,
            gwgroup: "default".into(),
            acl: None,
        });
        vpc2.peerings.push(Peering {
            name: "overlapping_peering2".into(),
            local: masquerade_manifest("VPC-2", "10.2.0.0/30"),
            remote,
            remote_id: "11111".try_into().unwrap(),
            remote_vni: vpc3.vni,
            gwgroup: "default".into(),
            acl: None,
        });

        let mut vpctable = VpcTable::new();
        vpctable.add(vpc1).unwrap();
        vpctable.add(vpc2).unwrap();
        vpctable.add(vpc3).unwrap();

        vpctable.validate().unwrap()
    }

    #[allow(dead_code)]
    pub fn build_allocator_overlapping_private_prefixes() -> NatAllocator {
        let vpc_table = build_context_overlapping_private_prefixes();
        let config = MasqueradeConfig::new(&vpc_table).set_randomize(false);
        NatAllocator::new(config, 1)
    }

    // Two VPCs peering with the same destination VPC, masquerading onto public ranges that overlap
    // *partially*: VPC-1 takes 10.1.0.0/30 (.0 through .3) and VPC-2 takes 10.1.0.2/31 (.2 and
    // .3). Neither range contains the other, so no single range identifies the shared space.
    #[allow(dead_code)]
    fn build_context_partial_overlap() -> ValidatedVpcTable {
        let masquerade_manifest = |name: &str, private: &str, public: &str| {
            VpcManifest::with_exposes(
                name,
                vec![
                    VpcExpose::empty()
                        .make_masquerade(None)
                        .unwrap()
                        .ip(private.into())
                        .as_range(public.into())
                        .unwrap(),
                ],
            )
        };
        let remote =
            VpcManifest::with_exposes("VPC-3", vec![VpcExpose::empty().ip("3.0.0.0/24".into())]);

        let mut vpc1 = Vpc::new("VPC-1", "67890", vni1().as_u32()).unwrap();
        let mut vpc2 = Vpc::new("VPC-2", "12345", vni2().as_u32()).unwrap();
        let vpc3 = Vpc::new("VPC-3", "11111", vni3().as_u32()).unwrap();

        vpc1.peerings.push(Peering {
            name: "partial_peering1".into(),
            local: masquerade_manifest("VPC-1", "1.1.0.0/16", "10.1.0.0/30"),
            remote: remote.clone(),
            remote_id: "11111".try_into().unwrap(),
            remote_vni: vpc3.vni,
            gwgroup: "default".into(),
            acl: None,
        });
        vpc2.peerings.push(Peering {
            name: "partial_peering2".into(),
            local: masquerade_manifest("VPC-2", "2.1.0.0/16", "10.1.0.2/31"),
            remote,
            remote_id: "11111".try_into().unwrap(),
            remote_vni: vpc3.vni,
            gwgroup: "default".into(),
            acl: None,
        });

        let mut vpctable = VpcTable::new();
        vpctable.add(vpc1).unwrap();
        vpctable.add(vpc2).unwrap();
        vpctable.add(vpc3).unwrap();

        vpctable.validate().unwrap()
    }

    #[allow(dead_code)]
    pub fn build_allocator_partial_overlap() -> NatAllocator {
        let vpc_table = build_context_partial_overlap();
        let config = MasqueradeConfig::new(&vpc_table).set_randomize(false);
        NatAllocator::new(config, 1)
    }

    #[allow(dead_code)]
    fn build_context_v6() -> ValidatedVpcTable {
        let masquerade = VpcExpose::empty()
            .make_masquerade(None)
            .unwrap()
            .ip("2001:db8:1::/64".into())
            .as_range("2001:db8:ffff::/112".into())
            .unwrap();
        let remote = VpcManifest::with_exposes(
            "VPC-2",
            vec![VpcExpose::empty().ip("2001:db8:2::/64".into())],
        );

        let mut vpc1 = Vpc::new("VPC-1", "67890", vni1().as_u32()).unwrap();
        let vpc2 = Vpc::new("VPC-2", "12345", vni2().as_u32()).unwrap();
        vpc1.peerings.push(Peering {
            name: "v6_peering".into(),
            local: VpcManifest::with_exposes("VPC-1", vec![masquerade]),
            remote,
            remote_id: "12345".try_into().unwrap(),
            remote_vni: vpc2.vni,
            gwgroup: "default".into(),
            acl: None,
        });

        let mut vpctable = VpcTable::new();
        vpctable.add(vpc1).unwrap();
        vpctable.add(vpc2).unwrap();
        vpctable.validate().unwrap()
    }

    #[allow(dead_code)]
    pub fn build_allocator_v6() -> NatAllocator {
        let config = MasqueradeConfig::new(&build_context_v6()).set_randomize(false);
        NatAllocator::new(config, 1)
    }

    #[allow(dead_code)]
    pub fn addr_v6(ip: &str) -> Ipv6Addr {
        Ipv6Addr::from_str(ip).unwrap()
    }

    #[allow(dead_code)]
    pub fn get_pool_set_v4(
        pool: &PoolTable<Ipv4Addr, Ipv4Addr>,
        src_vpcd: VpcDiscriminant,
        dst_vpcd: VpcDiscriminant,
        protocol: NextHeader,
        src_ip: Ipv4Addr,
    ) -> &PoolSet<Ipv4Addr> {
        pool.get(&PoolTableKey::new(
            protocol,
            src_vpcd,
            dst_vpcd,
            src_ip,
            Ipv4Addr::from_str("255.255.255.255").unwrap(),
        ))
        .unwrap()
    }
}

mod tests {
    use super::context::*;
    use concurrency::sync::Arc;
    use concurrency::thread;
    use net::ip::NextHeader;

    #[allow(dead_code)]
    pub(super) fn concurrent_allocations() {
        let allocator = build_allocator();
        let allocator_arc = Arc::new(allocator);
        let allocator1 = allocator_arc.clone();
        let allocator2 = allocator_arc.clone();
        let allocator3 = allocator_arc.clone();

        let mut handles = vec![];

        handles.push(thread::spawn(move || {
            let _allocation1 = allocator1
                .allocate_v4(vpcd1(), vpcd2(), addr_v4("1.1.0.0"), NextHeader::TCP)
                .unwrap();
        }));
        handles.push(thread::spawn(move || {
            let _allocation2 = allocator2
                .allocate_v4(vpcd1(), vpcd2(), addr_v4("1.1.0.0"), NextHeader::TCP)
                .unwrap();
        }));
        handles.push(thread::spawn(move || {
            let _allocation3 = allocator3
                .allocate_v4(vpcd1(), vpcd2(), addr_v4("1.1.0.0"), NextHeader::TCP)
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
            vpcd1(),
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
    use crate::NatPort;
    use crate::masquerade::allocation::AllocatorError;
    use crate::masquerade::apalloc::alloc::{IpAllocator, NatPool, PoolRegion};
    use crate::masquerade::apalloc::region::AddrInterval;
    use crate::masquerade::apalloc::reserved::ReservedPorts;
    use crate::masquerade::apalloc::{AnyReservation, PoolTableKey};
    use lpm::prefix::{L4Protocol, PortRange, PrefixPortsSet, PrefixWithOptionalPorts};
    use net::ip::NextHeader;
    use std::net::{IpAddr, Ipv4Addr};
    use std::num::NonZero;

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
                .all(|k| k.dst_vpcd == vpcd2() || k.dst_vpcd == vpcd1())
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

        let pool_set = allocator
            .pools_src44
            .get(&PoolTableKey::new(
                NextHeader::TCP,
                vpcd1(),
                vpcd2(),
                addr_v4("1.1.0.0"),
                addr_v4("255.255.255.255"),
            ))
            .unwrap();
        let (bitmap, in_use) = sole_region(pool_set).get_pool_clone_for_tests();

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
            vpcd1(),
            vpcd2(),
            NextHeader::TCP,
            addr_v4("1.1.0.0"),
        )
        .get_pool_clone_for_tests();
        assert_eq!(bitmap.len(), 3); // 3 IP addresses available to NAT 1.1.0.0
        assert_eq!(in_use.len(), 0); // None allocated yet

        let alloc_result = allocator
            .allocate_v4(vpcd1(), vpcd2(), addr_v4("1.1.0.0"), NextHeader::TCP)
            .unwrap();
        println!("{alloc_result}");

        assert_eq!(alloc_result.allocation.ip(), addr_v4("10.1.0.0"));

        let (bitmap, in_use) = get_ip_allocator_v4(
            &mut allocator.pools_src44,
            vpcd1(),
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
            vpcd1(),
            vpcd2(),
            NextHeader::TCP,
            addr_v4("1.1.0.0"),
        )
        .get_pool_clone_for_tests();
        assert_eq!(bitmap.len(), 3); // 3 IP addresses available to NAT 1.1.0.0
        assert_eq!(in_use.len(), 1); // One weak reference still in the list
        assert!(in_use.front().unwrap().upgrade().is_none()); // But it no longer resolves
    }

    // Allocate an IP for a TCP packet, then for a UDP packet.
    #[test]
    fn test_tcp_udp() {
        let mut allocator = build_allocator();
        let (bitmap, in_use) = get_ip_allocator_v4(
            &mut allocator.pools_src44,
            vpcd1(),
            vpcd2(),
            NextHeader::TCP,
            addr_v4("1.1.0.0"),
        )
        .get_pool_clone_for_tests();
        assert_eq!(bitmap.len(), 3); // 3 IP addresses available to NAT 1.1.0.0 (TCP)
        assert_eq!(in_use.len(), 0); // None allocated yet

        let (bitmap, in_use) = get_ip_allocator_v4(
            &mut allocator.pools_src44,
            vpcd1(),
            vpcd2(),
            NextHeader::UDP,
            addr_v4("1.1.0.0"),
        )
        .get_pool_clone_for_tests();
        assert_eq!(bitmap.len(), 3); // 3 free IP addresses left to NAT 1.1.0.0 (UDP)
        assert_eq!(in_use.len(), 0); // None allocated yet

        // Allocate for TCP
        let tcp_allocation = allocator
            .allocate_v4(vpcd1(), vpcd2(), addr_v4("1.1.0.0"), NextHeader::TCP)
            .unwrap();
        println!("{tcp_allocation}");

        // Check number of allocated IPs for TCP after we have allocated for TCP
        let (bitmap, in_use) = get_ip_allocator_v4(
            &mut allocator.pools_src44,
            vpcd1(),
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
            vpcd1(),
            vpcd2(),
            NextHeader::UDP,
            addr_v4("1.1.0.0"),
        )
        .get_pool_clone_for_tests();
        assert_eq!(bitmap.len(), 3); // 3 free IP addresses left to NAT 1.1.0.0 (UDP)
        assert_eq!(in_use.len(), 0); // None allocated yet

        // Allocate for UDP
        let udp_allocation = allocator
            .allocate_v4(vpcd1(), vpcd2(), addr_v4("1.1.0.0"), NextHeader::UDP)
            .unwrap();
        println!("{udp_allocation}");

        // Check number of allocated IPs for TCP after we have allocated for UDP
        let (bitmap, in_use) = get_ip_allocator_v4(
            &mut allocator.pools_src44,
            vpcd1(),
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
            vpcd1(),
            vpcd2(),
            NextHeader::UDP,
            addr_v4("1.1.0.0"),
        )
        .get_pool_clone_for_tests();
        assert_eq!(bitmap.len(), 2); // 2 free IP addresses left to NAT 1.1.0.0 (UDP)
        assert_eq!(in_use.len(), 1); // 1 allocated, in use
    }

    // Two VPCs masquerading onto the same public range towards the same destination VPC describe
    // one pool, not two, and must therefore share a single allocator. Allocating for a source in
    // each VPC in turn may not yield the same public address and port twice.
    #[test]
    fn test_shared_public_range_is_allocated_once() {
        let allocator = build_allocator_shared_public_range();

        let alloc_a = allocator
            .allocate_v4(vpcd1(), vpcd3(), addr_v4("1.1.0.1"), NextHeader::TCP)
            .unwrap();
        let alloc_b = allocator
            .allocate_v4(vpcd2(), vpcd3(), addr_v4("2.1.0.1"), NextHeader::TCP)
            .unwrap();

        assert_ne!(
            (alloc_a.allocation.ip(), alloc_a.allocation.port().as_u16()),
            (alloc_b.allocation.ip(), alloc_b.allocation.port().as_u16()),
            "the same public address and port was handed out to two different flows"
        );

        // Sharing the pool means the second allocation reuses the address the first one took,
        // and simply draws the next port from it.
        assert_eq!(alloc_a.allocation.ip(), alloc_b.allocation.ip());
    }

    // Sharing a pool must not collapse the private-side lookups: each private prefix keeps its own
    // entry, since that is how the first packet of a flow finds its pool.
    #[test]
    fn test_shared_public_range_keeps_both_private_entries() {
        let allocator = build_allocator_shared_public_range();

        let tcp_entries = allocator
            .pools_src44
            .0
            .keys()
            .filter(|k| k.protocol == NextHeader::TCP && k.dst_vpcd == vpcd3())
            .count();
        assert_eq!(tcp_entries, 2);

        for (src_vpcd, src) in [(vpcd1(), "1.1.0.1"), (vpcd2(), "2.1.0.1")] {
            assert!(
                allocator
                    .pools_src44
                    .get(&PoolTableKey::new(
                        NextHeader::TCP,
                        src_vpcd,
                        vpcd3(),
                        addr_v4(src),
                        addr_v4("255.255.255.255"),
                    ))
                    .is_some(),
                "no pool found for private source {src}"
            );
        }
    }

    // Two VPCs may use the same private address space, so a private prefix on its own does not
    // identify a pool. Each VPC has to be masqueraded onto the public range its own expose
    // declares, rather than whichever expose happened to be registered last.
    #[test]
    fn test_overlapping_private_prefixes_use_their_own_pool() {
        let allocator = build_allocator_overlapping_private_prefixes();

        let from_vpc1 = allocator
            .allocate_v4(vpcd1(), vpcd3(), addr_v4("192.168.0.1"), NextHeader::TCP)
            .unwrap();
        let from_vpc2 = allocator
            .allocate_v4(vpcd2(), vpcd3(), addr_v4("192.168.0.1"), NextHeader::TCP)
            .unwrap();

        assert_eq!(
            from_vpc1.allocation.ip(),
            addr_v4("10.1.0.0"),
            "traffic from VPC-1 was not masqueraded onto the range VPC-1 exposes"
        );
        assert_eq!(
            from_vpc2.allocation.ip(),
            addr_v4("10.2.0.0"),
            "traffic from VPC-2 was not masqueraded onto the range VPC-2 exposes"
        );
    }

    // Partially overlapping public ranges are cut so that the shared part becomes a region of its
    // own. VPC-1 keeps an exclusive region for the half only it claims, plus the shared one;
    // VPC-2 only ever sees the shared one.
    #[test]
    fn test_partial_overlap_is_cut_into_regions() {
        let allocator = build_allocator_partial_overlap();

        let for_vpc1 = get_pool_set_v4(
            &allocator.pools_src44,
            vpcd1(),
            vpcd3(),
            NextHeader::TCP,
            addr_v4("1.1.0.1"),
        );
        let vpc1_ranges: Vec<_> = for_vpc1.regions().map(PoolRegion::range).collect();
        assert_eq!(vpc1_ranges.len(), 2, "VPC-1 should own two regions");
        // The exclusive region is offered first.
        assert_eq!(vpc1_ranges[0].start, u128::from(addr_v4_bits("10.1.0.0")));
        assert_eq!(vpc1_ranges[0].end, u128::from(addr_v4_bits("10.1.0.1")));
        assert_eq!(vpc1_ranges[1].start, u128::from(addr_v4_bits("10.1.0.2")));
        assert_eq!(vpc1_ranges[1].end, u128::from(addr_v4_bits("10.1.0.3")));

        let for_vpc2 = get_pool_set_v4(
            &allocator.pools_src44,
            vpcd2(),
            vpcd3(),
            NextHeader::TCP,
            addr_v4("2.1.0.1"),
        );
        let vpc2_ranges: Vec<_> = for_vpc2.regions().map(PoolRegion::range).collect();
        assert_eq!(
            vpc2_ranges.len(),
            1,
            "VPC-2 should only own the shared region"
        );
        assert_eq!(vpc2_ranges[0].start, u128::from(addr_v4_bits("10.1.0.2")));
        assert_eq!(vpc2_ranges[0].end, u128::from(addr_v4_bits("10.1.0.3")));
    }

    // The shared region is one allocator, not a copy per VPC: an address VPC-2 takes from it is no
    // longer free in the view VPC-1 has of that same region. This is what stops the two from
    // handing out the same public address and port.
    #[test]
    fn test_partial_overlap_shares_one_allocator_for_the_shared_region() {
        let allocator = build_allocator_partial_overlap();

        let taken = allocator
            .allocate_v4(vpcd2(), vpcd3(), addr_v4("2.1.0.1"), NextHeader::TCP)
            .unwrap();
        // VPC-2 can only allocate from the shared region.
        assert_eq!(taken.allocation.ip(), addr_v4("10.1.0.2"));

        let for_vpc1 = get_pool_set_v4(
            &allocator.pools_src44,
            vpcd1(),
            vpcd3(),
            NextHeader::TCP,
            addr_v4("1.1.0.1"),
        );
        let shared = for_vpc1.regions().nth(1).expect("no shared region");
        let (bitmap, in_use) = shared.allocator().get_pool_clone_for_tests();
        assert!(
            !bitmap.contains(addr_v4_bits("10.1.0.2")),
            "VPC-1 still sees an address VPC-2 has taken from the shared region"
        );
        assert_eq!(in_use.len(), 1);
    }

    // Allocation prefers space a VPC has to itself, so the shared region stays available for the
    // VPC that has nowhere else to go.
    #[test]
    fn test_partial_overlap_prefers_exclusive_space() {
        let allocator = build_allocator_partial_overlap();

        let from_vpc1 = allocator
            .allocate_v4(vpcd1(), vpcd3(), addr_v4("1.1.0.1"), NextHeader::TCP)
            .unwrap();
        assert_eq!(
            from_vpc1.allocation.ip(),
            addr_v4("10.1.0.0"),
            "VPC-1 should have drawn from the region it does not share"
        );

        let from_vpc2 = allocator
            .allocate_v4(vpcd2(), vpcd3(), addr_v4("2.1.0.1"), NextHeader::TCP)
            .unwrap();
        assert_ne!(
            (
                from_vpc1.allocation.ip(),
                from_vpc1.allocation.port().as_u16()
            ),
            (
                from_vpc2.allocation.ip(),
                from_vpc2.allocation.port().as_u16()
            ),
        );
    }

    // Whichever region it draws from, a VPC may only ever be given an address its own expose
    // declares.
    #[test]
    fn test_partial_overlap_never_allocates_outside_the_configured_range() {
        let allocator = build_allocator_partial_overlap();

        let mut held = Vec::new();
        for _ in 0..16 {
            let allocation = allocator
                .allocate_v4(vpcd2(), vpcd3(), addr_v4("2.1.0.1"), NextHeader::TCP)
                .unwrap();
            let ip = allocation.allocation.ip();
            assert!(
                ip == addr_v4("10.1.0.2") || ip == addr_v4("10.1.0.3"),
                "VPC-2 was given {ip}, which is outside the range it exposes"
            );
            held.push(allocation);
        }
    }

    #[test]
    fn test_masquerade_v6_allocates_within_the_public_range() {
        let allocator = build_allocator_v6();
        assert!(allocator.pools_src44.0.is_empty());
        assert!(!allocator.pools_src66.0.is_empty());

        let mut held = Vec::new();
        let mut seen = std::collections::BTreeSet::new();
        for step in 0..8 {
            let allocation = allocator
                .allocate(
                    vpcd1(),
                    vpcd2(),
                    IpAddr::V6(addr_v6("2001:db8:1::1")),
                    NextHeader::TCP,
                )
                .expect("the v6 pool has room");
            let IpAddr::V6(ip) = allocation.allocation.ip() else {
                panic!("an IPv6 source received an IPv4 translation");
            };
            let port = allocation.allocation.port().as_u16();

            assert_eq!(
                ip.segments()[0..7],
                addr_v6("2001:db8:ffff::").segments()[0..7]
            );
            if step == 0 {
                assert_eq!(ip, addr_v6("2001:db8:ffff::"));
            }
            assert!(port >= 1024);
            assert!(seen.insert((ip, port)), "{ip}:{port} was handed out twice");
            held.push(allocation);
        }
    }

    #[test]
    fn test_masquerade_v6_reserves_a_carried_address() {
        let allocator = build_allocator_v6();
        let allocation = allocator
            .allocate(
                vpcd1(),
                vpcd2(),
                IpAddr::V6(addr_v6("2001:db8:1::1")),
                NextHeader::TCP,
            )
            .expect("the v6 pool has room");
        let held = allocation.allocation.ip();
        let port = allocation.allocation.port();

        let next = build_allocator_v6();
        let carried = next
            .reserve_port(
                NextHeader::TCP,
                vpcd1(),
                vpcd2(),
                AnyReservation::new(IpAddr::V6(addr_v6("2001:db8:1::1")), held)
                    .expect("a v6 private source and a v6 allocation"),
                port,
            )
            .expect("the next config still serves the tuple");
        assert_eq!((carried.ip(), carried.port()), (held, port));

        let fresh = next
            .allocate(
                vpcd1(),
                vpcd2(),
                IpAddr::V6(addr_v6("2001:db8:1::2")),
                NextHeader::TCP,
            )
            .expect("the v6 pool has room");
        assert_ne!(
            (fresh.allocation.ip(), fresh.allocation.port()),
            (held, port)
        );
    }

    // Both VPCs keep their own entry, rather than the second overwriting the first.
    #[test]
    fn test_overlapping_private_prefixes_keep_separate_entries() {
        let allocator = build_allocator_overlapping_private_prefixes();

        let tcp_entries = allocator
            .pools_src44
            .0
            .keys()
            .filter(|k| k.protocol == NextHeader::TCP && k.dst_vpcd == vpcd3())
            .count();
        assert_eq!(tcp_entries, 2);
    }

    ///////////////////////////////////////////////////////////////////////////
    // Ports claimed by port forwarding
    ///////////////////////////////////////////////////////////////////////////

    // A pool over one public address, claiming the whole 1024-1279 block and the single port 1400,
    // built the way `build_region_allocators` builds one.
    fn allocator_with_claims() -> (IpAllocator<Ipv4Addr>, Ipv4Addr) {
        let address = addr_v4("10.1.0.0");
        let bits = u128::from(addr_v4_bits("10.1.0.0"));
        let claims = PrefixPortsSet::from([
            PrefixWithOptionalPorts::new(
                "10.1.0.0/32".into(),
                Some(PortRange::new(1024, 1279).unwrap()),
            ),
            PrefixWithOptionalPorts::new(
                "10.1.0.0/32".into(),
                Some(PortRange::new(1400, 1400).unwrap()),
            ),
        ]);
        let pool = NatPool::for_range(
            AddrInterval::new(bits, bits),
            ReservedPorts::from_set(&claims),
            true,
        );
        (IpAllocator::new(pool, false), address)
    }

    #[test]
    fn a_v6_subnet_sized_pool_can_be_printed() {
        let base = u128::from_be_bytes(
            "2001:db8::"
                .parse::<std::net::Ipv6Addr>()
                .unwrap_or_else(|_| unreachable!())
                .octets(),
        );
        let pool = NatPool::<std::net::Ipv6Addr>::for_range(
            AddrInterval::new(base, base + u128::from(u64::MAX)),
            ReservedPorts::default(),
            true,
        );
        let allocator = IpAllocator::new(pool, false);

        let shown = allocator.to_string();
        assert!(
            shown.contains("IP ranges in pool:"),
            "the pool did not render its ranges: {shown}"
        );
        let ranges: Vec<&str> = shown.lines().filter(|line| line.contains(" .. ")).collect();
        assert_eq!(
            ranges.len(),
            1,
            "a pool with nothing allocated should print exactly one range: {shown}"
        );
        assert!(
            ranges[0].contains("[2001:db8:: .. 2001:db8::ffff:ffff]"),
            "the range should span the bitmap's 2^32 offsets: {shown}"
        );
    }

    #[test]
    fn claimed_ports_are_never_allocated() {
        let (allocator, _) = allocator_with_claims();

        // Enough to walk past the claimed block and all the way through the next one, which holds
        // the single claimed port.
        let held: Vec<_> = (0..512)
            .map(|_| allocator.allocate(false).expect("the pool has room"))
            .collect();
        let ports: Vec<u16> = held.iter().map(|port| port.port().as_u16()).collect();

        assert!(
            ports.iter().all(|&port| !(1024..=1279).contains(&port)),
            "a fully claimed block was handed out"
        );
        assert!(!ports.contains(&1400), "a claimed port was handed out");
        // The claimed block is skipped rather than partially used: allocation starts after it.
        assert_eq!(ports[0], 1280);
        // Its neighbour is used, minus the one port claimed inside it.
        assert!(ports.contains(&1399) && ports.contains(&1401));
    }

    #[test]
    fn a_reservation_refuses_a_pair_the_allocator_has_no_arm_for() {
        let v4 = ipaddr("1.1.0.1");
        let v6 = IpAddr::V6(addr_v6("2001:db8:1::1"));

        for (private, public) in [(v4, v6), (v6, v4)] {
            assert!(
                matches!(
                    AnyReservation::new(private, public),
                    Err(AllocatorError::InternalIssue(_))
                ),
                "{private} paired with {public} names no pool"
            );
        }

        for private in [ipaddr("255.255.255.255"), ipaddr("224.0.0.1")] {
            assert!(
                matches!(
                    AnyReservation::new(private, v4),
                    Err(AllocatorError::InternalIssue(_))
                ),
                "{private} is not a source address"
            );
        }

        assert!(AnyReservation::new(v4, v4).is_ok());
        assert!(AnyReservation::new(v6, v6).is_ok());
    }

    /// A forwarding rule claims tuples of the protocol it forwards. The address's other protocols
    /// have their own port space, which no flow of the forwarded protocol can collide with.
    #[test]
    fn a_claim_is_confined_to_the_protocol_it_forwards() {
        let port = NatPort::new_port(NonZero::new(8080).unwrap());
        let public = ipaddr("10.1.0.0");
        let private = ipaddr("1.1.0.1");
        let reservation = AnyReservation::new(private, public).expect("a v4 pair, unicast source");

        for (forwarded, claimed, untouched) in [
            (L4Protocol::Tcp, NextHeader::TCP, NextHeader::UDP),
            (L4Protocol::Udp, NextHeader::UDP, NextHeader::TCP),
        ] {
            let allocator = build_allocator_port_forward_for(forwarded);
            assert!(
                matches!(
                    allocator.reserve_port(claimed, vpcd1(), vpcd2(), reservation, port),
                    Err(AllocatorError::Denied)
                ),
                "a {forwarded:?} rule must claim the {claimed} tuple"
            );
            allocator
                .reserve_port(untouched, vpcd1(), vpcd2(), reservation, port)
                .unwrap_or_else(|e| {
                    panic!("a {forwarded:?} rule must claim nothing from {untouched}: {e}")
                });
        }
    }

    #[test]
    fn claimed_ports_cannot_be_reserved() {
        let (allocator, address) = allocator_with_claims();

        for claimed in [1024, 1279, 1400] {
            let port = NatPort::new_port(NonZero::new(claimed).unwrap());
            assert!(
                matches!(
                    allocator.reserve(address, port),
                    Err(AllocatorError::Denied)
                ),
                "reserving claimed port {claimed} must be denied"
            );
        }

        // A port outside every claim is still reservable on the same address.
        let free = NatPort::new_port(NonZero::new(5000).unwrap());
        allocator
            .reserve(address, free)
            .expect("an unclaimed port is reservable");
    }
}

// Loom's Weak shim keeps allocator liveness entries alive forever.
#[cfg(not(feature = "loom"))]
mod concurrency_tests {
    use super::context::*;
    use super::tests;
    use concurrency::sync::Arc;
    use concurrency::thread;
    use net::ip::NextHeader;

    #[concurrency::test]
    fn test_concurrent_allocations_two_ips() {
        let allocator = build_allocator();
        let allocator1 = Arc::new(allocator);
        let allocator2 = allocator1.clone();

        let t1 = thread::spawn(move || {
            let _allocation1 = allocator1
                .allocate_v4(vpcd1(), vpcd2(), addr_v4("1.1.0.0"), NextHeader::TCP)
                .unwrap();
        });
        let t2 = thread::spawn(move || {
            let _allocation2 = allocator2
                .allocate_v4(vpcd1(), vpcd2(), addr_v4("1.2.0.0"), NextHeader::TCP)
                .unwrap();
        });
        t1.join().unwrap();
        t2.join().unwrap();
    }

    #[concurrency::test]
    fn test_concurrent_allocations_three_workers() {
        tests::concurrent_allocations();
    }

    // One-shot std execution is nondeterministic; model checkers make the race reachable.
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
