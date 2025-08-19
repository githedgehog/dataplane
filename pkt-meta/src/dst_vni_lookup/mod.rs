// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use left_right::{Absorb, ReadGuard, ReadHandle, WriteHandle, new_from_empty};
use std::collections::HashMap;
use tracing::{debug, error, warn};

use lpm::trie::IpPrefixTrie;
use net::buffer::PacketBufferMut;
use net::headers::{TryHeaders, TryIp};
use net::packet::{DoneReason, Packet, VpcDiscriminant};
use net::vxlan::Vni;
use pipeline::NetworkFunction;

pub mod setup;

#[derive(thiserror::Error, Debug, Clone)]
pub enum DstVniLookupError {
    #[error("Error building dst_vni_lookup table: {0}")]
    BuildError(String),
}

#[derive(Debug, Clone)]
pub struct VniTables {
    tables_by_vni: HashMap<Vni, VniTable>,
}

impl VniTables {
    #[must_use]
    pub fn new() -> Self {
        Self {
            tables_by_vni: HashMap::new(),
        }
    }
}

impl Default for VniTables {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
enum VniTablesChange {
    UpdateVniTables(VniTables),
}

impl Absorb<VniTablesChange> for VniTables {
    fn absorb_first(&mut self, change: &mut VniTablesChange, _: &Self) {
        match change {
            VniTablesChange::UpdateVniTables(vni_tables) => {
                *self = vni_tables.clone();
            }
        }
    }
    fn drop_first(self: Box<Self>) {}
    fn sync_with(&mut self, first: &Self) {
        *self = first.clone();
    }
}

#[derive(Debug)]
pub struct VniTablesReader(ReadHandle<VniTables>);
impl VniTablesReader {
    fn enter(&self) -> Option<ReadGuard<'_, VniTables>> {
        self.0.enter()
    }
}

#[derive(Debug)]
pub struct VniTablesWriter(WriteHandle<VniTables, VniTablesChange>);
impl VniTablesWriter {
    #[must_use]
    #[allow(clippy::new_without_default)]
    pub fn new() -> VniTablesWriter {
        let (w, _r) = new_from_empty::<VniTables, VniTablesChange>(VniTables::new());
        VniTablesWriter(w)
    }
    #[must_use]
    pub fn get_reader(&self) -> VniTablesReader {
        VniTablesReader(self.0.clone())
    }
    pub fn update_vni_tables(&mut self, vni_tables: VniTables) {
        self.0.append(VniTablesChange::UpdateVniTables(vni_tables));
        self.0.publish();
        debug!("Updated tables for Destination VNI Lookup");
    }
}

#[derive(Debug, Clone)]
struct VniTable {
    dst_vnis: IpPrefixTrie<Vni>,
}

impl VniTable {
    fn new() -> Self {
        Self {
            dst_vnis: IpPrefixTrie::new(),
        }
    }
}

impl Default for VniTable {
    fn default() -> Self {
        Self::new()
    }
}

pub struct DstVniLookup {
    name: String,
    tablesr: VniTablesReader,
}

impl DstVniLookup {
    pub fn new(name: &str, tablesr: VniTablesReader) -> Self {
        Self {
            name: name.to_string(),
            tablesr,
        }
    }

    fn process_packet<Buf: PacketBufferMut>(
        &self,
        tablesr: &ReadGuard<'_, VniTables>,
        packet: &mut Packet<Buf>,
    ) {
        if packet.meta.dst_vpcd.is_some() {
            debug!("{}: Packet already has dst_vpcd, skipping", self.name);
            return;
        }
        let Some(net) = packet.headers().try_ip() else {
            warn!("{}: No Ip headers, so no dst_vpcd to lookup", self.name);
            return;
        };
        if let Some(VpcDiscriminant::VNI(src_vni)) = packet.meta.src_vpcd {
            let vni_table = tablesr.tables_by_vni.get(&src_vni);
            if let Some(vni_table) = vni_table {
                let dst_vni = vni_table.dst_vnis.lookup(net.dst_addr());
                if let Some((prefix, dst_vni)) = dst_vni {
                    debug!(
                        "{}: Tagging packet with dst_vni {dst_vni} using {prefix} using table for src_vni {src_vni}",
                        self.name
                    );
                    packet.meta.dst_vpcd = Some(VpcDiscriminant::VNI(*dst_vni));
                } else {
                    debug!(
                        "{}: no dst_vni found for {} in src_vni {src_vni}, marking packet as unroutable",
                        self.name,
                        net.dst_addr()
                    );
                    packet.done(DoneReason::Unroutable);
                }
            } else {
                debug!(
                    "{}: no vni table found for src_vni {src_vni} (dst_addr={})",
                    self.name,
                    net.dst_addr()
                );
                packet.done(DoneReason::Unroutable);
            }
        }
    }
}

impl<Buf: PacketBufferMut> NetworkFunction<Buf> for DstVniLookup {
    #[allow(clippy::if_not_else)]
    fn process<'a, Input: Iterator<Item = Packet<Buf>> + 'a>(
        &'a mut self,
        input: Input,
    ) -> impl Iterator<Item = Packet<Buf>> + 'a {
        input.filter_map(|mut packet| {
            if let Some(tablesr) = &self.tablesr.enter() {
                if !packet.is_done() {
                    // FIXME: ideally, we'd `enter` once for the whole batch. However,
                    // this requires boxing the closures, which may be worse than
                    // calling `enter` per packet? ... if not uglier

                    self.process_packet(tablesr, &mut packet);
                }
            } else {
                error!("{}: failed to read vni tables", self.name);
                packet.done(DoneReason::InternalFailure);
            }
            packet.enforce()
        })
    }
}

#[cfg(test)]
mod test {
    use super::{DstVniLookup, VniTable, VniTables, VniTablesWriter};
    use lpm::prefix::Prefix;
    use net::buffer::TestBuffer;
    use net::headers::{Net, TryHeadersMut, TryIpMut};
    use net::ipv4::addr::UnicastIpv4Addr;
    use net::ipv6::addr::UnicastIpv6Addr;
    use net::packet::test_utils::{build_test_ipv4_packet, build_test_ipv6_packet};
    use net::packet::{DoneReason, Packet, VpcDiscriminant};
    use net::vxlan::Vni;
    use pipeline::NetworkFunction;
    use std::net::IpAddr;

    fn set_dst_addr(packet: &mut Packet<TestBuffer>, addr: IpAddr) {
        let net = packet.headers_mut().try_ip_mut().unwrap();
        match net {
            Net::Ipv4(ip) => {
                ip.set_destination(UnicastIpv4Addr::try_from(addr).unwrap().into());
            }
            Net::Ipv6(ip) => {
                ip.set_destination(UnicastIpv6Addr::try_from(addr).unwrap().into());
            }
        }
    }

    fn create_test_packet(src_vni: Option<Vni>, dst_addr: IpAddr) -> Packet<TestBuffer> {
        let mut ret = match dst_addr {
            IpAddr::V4(_) => build_test_ipv4_packet(100).unwrap(),
            IpAddr::V6(_) => build_test_ipv6_packet(100).unwrap(),
        };
        set_dst_addr(&mut ret, dst_addr);
        ret.meta.src_vpcd = src_vni.map(VpcDiscriminant::VNI);
        ret
    }

    #[allow(clippy::too_many_lines)]
    #[test]
    fn test_dst_vni_lookup() {
        ////////////////////////////
        // Setup VNIs
        let vni100 = Vni::new_checked(100).unwrap();
        let vni101 = Vni::new_checked(101).unwrap();
        let vni102 = Vni::new_checked(102).unwrap();
        let vni200 = Vni::new_checked(200).unwrap();
        let vni201 = Vni::new_checked(201).unwrap();
        let vni202 = Vni::new_checked(202).unwrap();

        ////////////////////////////
        // Setup VNI tables

        // VNI 100
        let mut vni_table_100 = VniTable::new();
        let dst_vni_100_192_168_1_0_24 = vni101;
        let dst_vni_100_192_168_0_0_16 = vni102;
        vni_table_100
            .dst_vnis
            .insert(Prefix::from("192.168.1.0/24"), dst_vni_100_192_168_1_0_24);
        vni_table_100
            .dst_vnis
            .insert(Prefix::from("192.168.0.0/16"), dst_vni_100_192_168_0_0_16);
        vni_table_100.dst_vnis.insert(
            Prefix::from("::192.168.1.0/120"),
            dst_vni_100_192_168_1_0_24,
        );
        vni_table_100.dst_vnis.insert(
            Prefix::from("::192.168.0.0/112"),
            dst_vni_100_192_168_0_0_16,
        );

        // VNI 200
        let mut vni_table_200 = VniTable::new();
        let dst_vni_200_192_168_2_0_24 = vni201;
        let dst_vni_200_192_168_0_0_16 = vni202;
        vni_table_200
            .dst_vnis
            .insert(Prefix::from("192.168.2.0/24"), dst_vni_200_192_168_2_0_24);
        vni_table_200
            .dst_vnis
            .insert(Prefix::from("192.168.2.0/16"), dst_vni_200_192_168_0_0_16);
        vni_table_200.dst_vnis.insert(
            Prefix::from("::192.168.2.0/120"),
            dst_vni_200_192_168_2_0_24,
        );
        vni_table_200.dst_vnis.insert(
            Prefix::from("::192.168.0.0/112"),
            dst_vni_200_192_168_0_0_16,
        );

        ////////////////////////////
        // Setup VNI tables writer
        let mut vni_tables = VniTables::new();
        vni_tables.tables_by_vni.insert(vni100, vni_table_100);
        vni_tables.tables_by_vni.insert(vni200, vni_table_200);
        let mut vnitablesw = VniTablesWriter::new();
        vnitablesw.update_vni_tables(vni_tables);

        ////////////////////////////
        // Setup DstVniLookup stage
        let mut dst_vni_lookup = DstVniLookup::new("test", vnitablesw.get_reader());

        ////////////////////////////
        // Test IPv4 packets

        let p_100_dst_addr_192_168_1_1 =
            create_test_packet(Some(vni100), "192.168.1.1".parse().unwrap());
        let p_100_dst_addr_192_168_100_1 =
            create_test_packet(Some(vni100), "192.168.100.1".parse().unwrap());
        let p_200_dst_addr_192_168_2_1 =
            create_test_packet(Some(vni200), "192.168.2.1".parse().unwrap());
        let p_200_dst_addr_10_0_0_1 = create_test_packet(Some(vni100), "10.0.0.1".parse().unwrap());
        let p_none_dst_addr = create_test_packet(
            Some(Vni::new_checked(1000).unwrap()),
            "192.168.100.1".parse().unwrap(),
        );

        let packets_in = [
            p_100_dst_addr_192_168_1_1,
            p_100_dst_addr_192_168_100_1,
            p_200_dst_addr_192_168_2_1,
            p_200_dst_addr_10_0_0_1,
            p_none_dst_addr,
        ];
        let packets = dst_vni_lookup
            .process(packets_in.into_iter())
            .collect::<Vec<_>>();

        assert_eq!(packets.len(), 5);
        assert_eq!(
            packets[0].meta.dst_vpcd,
            Some(VpcDiscriminant::VNI(dst_vni_100_192_168_1_0_24))
        );
        assert!(!packets[0].is_done());
        assert_eq!(
            packets[1].meta.dst_vpcd,
            Some(VpcDiscriminant::VNI(dst_vni_100_192_168_0_0_16))
        );
        assert!(!packets[1].is_done());
        assert_eq!(
            packets[2].meta.dst_vpcd,
            Some(VpcDiscriminant::VNI(dst_vni_200_192_168_2_0_24))
        );
        assert!(!packets[2].is_done());
        assert_eq!(packets[3].meta.dst_vpcd, None);
        assert_eq!(packets[3].get_done(), Some(DoneReason::Unroutable));
        assert_eq!(packets[4].meta.dst_vpcd, None);
        assert_eq!(packets[4].get_done(), Some(DoneReason::Unroutable));

        ////////////////////////////
        // Test IPv6 packets

        let p_100_dst_addr_v6_192_168_1_1 =
            create_test_packet(Some(vni100), "::192.168.1.1".parse().unwrap());
        let p_100_dst_addr_v6_192_168_100_1 =
            create_test_packet(Some(vni100), "::192.168.100.1".parse().unwrap());
        let p_200_dst_addr_v6_192_168_2_1 =
            create_test_packet(Some(vni200), "::192.168.2.1".parse().unwrap());
        let p_200_dst_addr_v6_10_0_0_1 =
            create_test_packet(Some(vni100), "::10.0.0.1".parse().unwrap());

        let packets_in = [
            p_100_dst_addr_v6_192_168_1_1,
            p_100_dst_addr_v6_192_168_100_1,
            p_200_dst_addr_v6_192_168_2_1,
            p_200_dst_addr_v6_10_0_0_1,
        ];
        let packets = dst_vni_lookup
            .process(packets_in.into_iter())
            .collect::<Vec<_>>();
        assert_eq!(packets.len(), 4);
        assert_eq!(
            packets[0].meta.dst_vpcd,
            Some(VpcDiscriminant::VNI(dst_vni_100_192_168_1_0_24))
        );
        assert!(!packets[0].is_done());
        assert_eq!(
            packets[1].meta.dst_vpcd,
            Some(VpcDiscriminant::VNI(dst_vni_100_192_168_0_0_16))
        );
        assert!(!packets[1].is_done());
        assert_eq!(
            packets[2].meta.dst_vpcd,
            Some(VpcDiscriminant::VNI(dst_vni_200_192_168_2_0_24))
        );
        assert!(!packets[2].is_done());
        assert_eq!(packets[3].meta.dst_vpcd, None);
        assert_eq!(packets[3].get_done(), Some(DoneReason::Unroutable));
    }
}
