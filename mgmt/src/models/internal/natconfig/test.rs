// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! NAT configuration tests .. and actual NAT function

#[cfg(test)]
mod tests {
    use crate::models::external::overlay::vpc::Peering;
    use crate::models::external::overlay::vpcpeering::{VpcExpose, VpcManifest};
    use crate::models::internal::natconfig::table_extend;
    use nat::StatelessNat;
    use nat::stateless::config::tables::{NatTables, PerVniTable};
    use net::buffer::PacketBufferMut;
    use net::headers::{TryHeadersMut, TryIpv4, TryIpv4Mut};
    use net::packet::Packet;
    use net::packet::test_utils::build_test_ipv4_packet;
    use net::vxlan::Vni;
    use pipeline::NetworkFunction;
    use std::net::{IpAddr, Ipv4Addr};
    use std::str::FromStr;

    fn vni(vni: u32) -> Vni {
        Vni::new_checked(vni).expect("Failed to create VNI")
    }

    fn get_src_ip_v4<Buf: PacketBufferMut>(packet: &Packet<Buf>) -> Ipv4Addr {
        packet
            .get_headers()
            .try_ipv4()
            .expect("Failed to get IPv4 header")
            .source()
            .inner()
    }

    fn get_dst_ip_v4<Buf: PacketBufferMut>(packet: &Packet<Buf>) -> Ipv4Addr {
        packet
            .get_headers()
            .try_ipv4()
            .expect("Failed to get IPv4 header")
            .destination()
    }

    fn set_addresses_v4<Buf: PacketBufferMut>(
        packet: &mut Packet<Buf>,
        src_addr: Ipv4Addr,
        dst_addr: Ipv4Addr,
    ) -> &Packet<Buf> {
        let hdr = packet
            .headers_mut()
            .try_ipv4_mut()
            .expect("Failed to get IPv4 header");
        hdr.set_source(src_addr.try_into().expect("Invalid Unicast IPv4 address"));
        hdr.set_destination(dst_addr);
        packet
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
        //         - cidr: 5.5.0.0/17
        //         - cidr: 5.6.0.0/17  # <- 5.6.7.8 will match here
        //         - not: 5.6.0.0/24   # to account for when computing the offset
        //         - not: 5.6.8.0/24
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
            .as_range("5.5.0.0/17".into())
            .as_range("5.6.0.0/17".into())
            .not_as("5.6.0.0/24".into())
            .not_as("5.6.8.0/24".into());

        let manifest2 = VpcManifest {
            name: "VPC-2".into(),
            exposes: vec![expose3, expose4],
        };

        let peering1 = Peering {
            name: "test_peering1".into(),
            local: manifest1.clone(),
            remote: manifest2.clone(),
            remote_id: "12345".try_into().expect("Failed to create VPC ID"),
        };
        let peering2 = Peering {
            name: "test_peering2".into(),
            local: manifest2,
            remote: manifest1,
            remote_id: "67890".try_into().expect("Failed to create VPC ID"),
        };

        let mut nat_table = NatTables::new();

        let mut vni_table1 = PerVniTable::new();
        table_extend::add_peering(&mut vni_table1, &peering1).expect("Failed to build NAT tables");
        let mut vni_table2 = PerVniTable::new();
        table_extend::add_peering(&mut vni_table2, &peering2).expect("Failed to build NAT tables");

        nat_table.add_table(vni(100), vni_table1);
        nat_table.add_table(vni(200), vni_table2);

        nat_table
    }

    #[test]
    fn test_dst_nat_stateless_44() {
        const TARGET_SRC_IP: Ipv4Addr = Ipv4Addr::new(2, 2, 0, 4);
        const TARGET_DST_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 136, 8);

        let nat_tables = build_context();
        let mut nat = StatelessNat::new();
        nat.update_tables(nat_tables);

        let mut packet = build_test_ipv4_packet(u8::MAX).unwrap();
        let mut packet_reply = packet.clone();
        packet.get_meta_mut().src_vni = Some(vni(100));
        packet_reply.get_meta_mut().src_vni = Some(vni(200));

        let orig_src_ip = get_src_ip_v4(&packet);
        let orig_dst_ip = get_dst_ip_v4(&packet);

        // Check request. We expect:
        //
        // {orig_src_ip, orig_dst_ip} -> {orig_src_ip, TARGET_DST_IP}
        let packets_out: Vec<_> = nat.process(vec![packet].into_iter()).collect();
        assert_eq!(packets_out.len(), 1);

        let hdr_out = &packets_out[0]
            .try_ipv4()
            .expect("Failed to get IPv4 header");
        println!("L3 header: {hdr_out:?}");
        assert_eq!(hdr_out.source().inner(), TARGET_SRC_IP);
        assert_eq!(hdr_out.destination(), TARGET_DST_IP);

        // Check that reply gets reverse source NAT. We expect:
        //
        // {TARGET_DST_IP, orig_src_ip} -> {orig_dst_ip, orig_src_ip}
        set_addresses_v4(&mut packet_reply, TARGET_DST_IP, TARGET_SRC_IP);

        let packets_out_reply: Vec<_> = nat.process(vec![packet_reply].into_iter()).collect();
        assert_eq!(packets_out_reply.len(), 1);

        let hdr_out_reply = &packets_out_reply[0]
            .try_ipv4()
            .expect("Failed to get IPv4 header");
        println!("L3 header: {hdr_out_reply:?}");
        assert_eq!(hdr_out_reply.source().inner(), orig_dst_ip);
        assert_eq!(hdr_out_reply.destination(), orig_src_ip);
    }
}
