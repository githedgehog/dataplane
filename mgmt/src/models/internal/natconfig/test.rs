// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! NAT configuration tests .. and actual NAT function

#[cfg(test)]
mod tests {
    use crate::models::external::overlay::vpc::Peering;
    use crate::models::external::overlay::vpcpeering::{VpcExpose, VpcManifest};
    use crate::models::internal::natconfig::table_extend;

    use pipeline::NetworkFunction;

    use nat::NatDirection;
    use nat::StatelessNat;
    use nat::stateless::config::tables::{NatTables, PerVniTable};

    use net::headers::TryIpv4;
    use net::packet::test_utils::build_test_ipv4_packet;
    use net::vxlan::Vni;
    use std::net::{IpAddr, Ipv4Addr};
    use std::str::FromStr;

    fn addr_v4(s: &str) -> IpAddr {
        IpAddr::V4(Ipv4Addr::from_str(s).expect("Invalid IPv4 address"))
    }

    fn vni_100() -> Vni {
        Vni::new_checked(100).expect("Failed to create VNI")
    }

    fn build_context() -> NatTables {
        // Build VpcExpose objects
        //
        //     expose:
        //       - ips:
        //         - cidr: 1.1.0.0/16
        //         - cidr: 1.2.0.0/16 # <- 1.2.3.4 will match here
        //         - not: 1.1.5.0/24  # to account for when computing the offset
        //         - not: 1.1.3.0/24  # to account for when computing the offset
        //         - not: 1.1.1.0/24  # to account for when computing the offset
        //         - not: 1.2.2.0/24  # to account for when computing the offset
        //         as:
        //         - cidr: 2.2.0.0/16
        //         - cidr: 2.1.0.0/16 # <- corresp. target range, initially
        //                            # (prefixes in BTreeSet are sorted)
        //                            # offset for 2.1.255.4, before applying exlusions
        //                            # final offset is for 2.2.0.4 after accounting for the one
        //                            # relevant exclusion prefix
        //         - not: 2.1.8.0/24  # to account for when fetching the address in range
        //         - not: 2.2.10.0/24
        //         - not: 2.2.1.0/24  # ignored, offset too low
        //         - not: 2.2.2.0/24  # ignored, offset too low
        //       - ips:
        //         - cidr: 3.0.0.0/16
        //         as:
        //         - cidr: 4.0.0.0/16
        let expose1 = VpcExpose::empty()
            .ip("1.1.0.0/16".into())
            .not("1.1.5.0/24".into())
            .not("1.1.3.0/24".into())
            .not("1.1.1.0/24".into())
            .ip("1.2.0.0/16".into())
            .not("1.2.2.0/24".into())
            .as_range("2.2.0.0/16".into())
            .not_as("2.1.8.0/24".into())
            .not_as("2.2.10.0/24".into())
            .not_as("2.2.1.0/24".into())
            .not_as("2.2.2.0/24".into())
            .as_range("2.1.0.0/16".into());
        let expose2 = VpcExpose::empty()
            .ip("3.0.0.0/16".into())
            .as_range("4.0.0.0/16".into());

        let manifest1 = VpcManifest {
            name: "VPC-1".into(),
            exposes: vec![expose1, expose2],
        };

        //     expose:
        //       - ips:
        //         - cidr: 8.0.0.0/17
        //         - cidr: 9.0.0.0/17
        //         - not: 8.0.0.0/24
        //         as:
        //         - cidr: 3.0.0.0/16
        //         - not: 3.0.1.0/24
        //       - ips:
        //         - cidr: 10.0.0.0/16 # <- corresponding target range
        //         - not: 10.0.1.0/24  # to account for when fetching the address in range
        //         - not: 10.0.2.0/24  # to account for when fetching the address in range
        //         as:
        //         - cidr: 1.1.0.0/17
        //         - cidr: 1.2.0.0/17  # <- 1.2.3.4 will match here
        //         - not: 1.2.0.0/24   # to account for when computing the offset
        //         - not: 1.2.8.0/24
        let expose3 = VpcExpose::empty()
            .ip("8.0.0.0/17".into())
            .not("8.0.0.0/24".into())
            .ip("9.0.0.0/17".into())
            .as_range("3.0.0.0/16".into())
            .not_as("3.0.1.0/24".into());
        let expose4 = VpcExpose::empty()
            .ip("10.0.0.0/16".into())
            .not("10.0.1.0/24".into())
            .not("10.0.2.0/24".into())
            .as_range("1.1.0.0/17".into())
            .as_range("1.2.0.0/17".into())
            .not_as("1.2.0.0/24".into())
            .not_as("1.2.8.0/24".into());

        let manifest2 = VpcManifest {
            name: "VPC-2".into(),
            exposes: vec![expose3, expose4],
        };

        let peering: Peering = Peering {
            name: "test_peering".into(),
            local: manifest1,
            remote: manifest2,
            remote_id: "12345".try_into().expect("Failed to create VPC ID"),
        };

        let mut vni_table = PerVniTable::new();
        table_extend::add_peering(&mut vni_table, &peering).expect("Failed to build NAT tables");

        let vni = vni_100();
        let mut nat_table = NatTables::new();
        nat_table.add_table(vni, vni_table);

        nat_table
    }

    #[test]
    fn test_dst_nat_stateless_44() {
        let nat_tables = build_context();
        let mut nat = StatelessNat::new(NatDirection::DstNat);
        nat.update_tables(nat_tables);

        let packets = vec![build_test_ipv4_packet(u8::MAX).unwrap()]
            .into_iter()
            .map(|mut packet| {
                packet.get_meta_mut().src_vni = Some(vni_100());
                packet
            });

        let packets_out: Vec<_> = nat.process(packets).collect();

        assert_eq!(packets_out.len(), 1);

        let hdr0_out = &packets_out[0]
            .try_ipv4()
            .expect("Failed to get IPv4 header");
        println!("L3 header: {hdr0_out:?}");
        assert_eq!(hdr0_out.destination(), addr_v4("10.0.132.4"));
    }

    #[test]
    fn test_src_nat_stateless_44() {
        let nat_tables = build_context();
        let mut nat = StatelessNat::new(NatDirection::SrcNat);
        nat.update_tables(nat_tables);

        let packets = vec![build_test_ipv4_packet(u8::MAX).unwrap()]
            .into_iter()
            .map(|mut packet| {
                packet.get_meta_mut().src_vni = Some(vni_100());
                packet
            });

        let packets_out: Vec<_> = nat.process(packets).collect();

        assert_eq!(packets_out.len(), 1);

        let hdr0_out = &packets_out[0]
            .try_ipv4()
            .expect("Failed to get IPv4 header");
        println!("L3 header: {hdr0_out:?}");
        assert_eq!(hdr0_out.source().inner(), addr_v4("2.2.0.4"));
    }
}
