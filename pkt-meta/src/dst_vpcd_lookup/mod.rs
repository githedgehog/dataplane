// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use left_right::{Absorb, ReadGuard, ReadHandle, ReadHandleFactory, WriteHandle, new_from_empty};
use std::collections::HashMap;
use tracing::{debug, error, warn};

use lpm::trie::IpPrefixTrie;
use net::buffer::PacketBufferMut;
use net::headers::{TryHeaders, TryIp};
use net::packet::{DoneReason, Packet, VpcDiscriminant};
use pipeline::NetworkFunction;

pub mod setup;

use tracectl::trace_target;
trace_target!("vpc-routing", LevelFilter::INFO, &["pipeline"]);

#[derive(thiserror::Error, Debug, Clone)]
pub enum DstVpcdLookupError {
    #[error("Error building dst_vpcd_lookup table: {0}")]
    BuildError(String),
}

#[derive(Debug, Clone)]
pub struct VpcDiscriminantTables {
    tables_by_discriminant: HashMap<VpcDiscriminant, VpcDiscriminantTable>,
}

impl VpcDiscriminantTables {
    #[must_use]
    pub fn new() -> Self {
        Self {
            tables_by_discriminant: HashMap::new(),
        }
    }
}

impl Default for VpcDiscriminantTables {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
enum VpcDiscriminantTablesChange {
    UpdateVpcDiscTables(VpcDiscriminantTables),
}

impl Absorb<VpcDiscriminantTablesChange> for VpcDiscriminantTables {
    fn absorb_first(&mut self, change: &mut VpcDiscriminantTablesChange, _: &Self) {
        match change {
            VpcDiscriminantTablesChange::UpdateVpcDiscTables(vpcd_tables) => {
                *self = vpcd_tables.clone();
            }
        }
    }
    fn drop_first(self: Box<Self>) {}
    fn sync_with(&mut self, first: &Self) {
        *self = first.clone();
    }
}

#[derive(Debug)]
pub struct VpcDiscTablesReader(ReadHandle<VpcDiscriminantTables>);
impl VpcDiscTablesReader {
    fn enter(&self) -> Option<ReadGuard<'_, VpcDiscriminantTables>> {
        self.0.enter()
    }

    #[must_use]
    pub fn factory(&self) -> VpcDiscTablesReaderFactory {
        VpcDiscTablesReaderFactory(self.0.factory())
    }
}

#[derive(Debug)]
pub struct VpcDiscTablesReaderFactory(ReadHandleFactory<VpcDiscriminantTables>);
impl VpcDiscTablesReaderFactory {
    #[must_use]
    pub fn handle(&self) -> VpcDiscTablesReader {
        VpcDiscTablesReader(self.0.handle())
    }
}

#[derive(Debug)]
pub struct VpcDiscTablesWriter(WriteHandle<VpcDiscriminantTables, VpcDiscriminantTablesChange>);
impl VpcDiscTablesWriter {
    #[must_use]
    #[allow(clippy::new_without_default)]
    pub fn new() -> VpcDiscTablesWriter {
        let (w, _r) = new_from_empty::<VpcDiscriminantTables, VpcDiscriminantTablesChange>(
            VpcDiscriminantTables::new(),
        );
        VpcDiscTablesWriter(w)
    }
    #[must_use]
    pub fn get_reader(&self) -> VpcDiscTablesReader {
        VpcDiscTablesReader(self.0.clone())
    }

    pub fn get_reader_factory(&self) -> VpcDiscTablesReaderFactory {
        self.get_reader().factory()
    }

    pub fn update_vpcd_tables(&mut self, vpcd_tables: VpcDiscriminantTables) {
        self.0
            .append(VpcDiscriminantTablesChange::UpdateVpcDiscTables(
                vpcd_tables,
            ));
        self.0.publish();
        debug!("Updated tables for Destination vpcd Lookup");
    }
}

#[derive(Debug, Clone)]
struct VpcDiscriminantTable {
    dst_vpcds: IpPrefixTrie<VpcDiscriminant>,
}

impl VpcDiscriminantTable {
    fn new() -> Self {
        Self {
            dst_vpcds: IpPrefixTrie::new(),
        }
    }
}

impl Default for VpcDiscriminantTable {
    fn default() -> Self {
        Self::new()
    }
}

pub struct DstVpcdLookup {
    name: String,
    tablesr: VpcDiscTablesReader,
}

impl DstVpcdLookup {
    pub fn new(name: &str, tablesr: VpcDiscTablesReader) -> Self {
        Self {
            name: name.to_string(),
            tablesr,
        }
    }

    fn process_packet<Buf: PacketBufferMut>(
        &self,
        tablesr: &ReadGuard<'_, VpcDiscriminantTables>,
        packet: &mut Packet<Buf>,
    ) {
        let nfi = &self.name;
        if packet.meta.dst_vpcd.is_some() {
            debug!("{nfi}: Packet already has dst_vpcd: skipping");
            return;
        }
        let Some(net) = packet.headers().try_ip() else {
            warn!("{nfi}: Packet has no Ip headers: can't look up dst_vpcd");
            packet.done(DoneReason::NotIp);
            return;
        };
        let Some(src_vpcd) = packet.meta.src_vpcd else {
            warn!("{nfi}: Packet does not have src vpcd: marking as unroutable");
            packet.done(DoneReason::Unroutable);
            return;
        };
        let dst_ip = net.dst_addr();
        if let Some(vpcd_table) = tablesr.tables_by_discriminant.get(&src_vpcd) {
            let dst_vpcd = vpcd_table.dst_vpcds.lookup(dst_ip);
            if let Some((prefix, dst_vpcd)) = dst_vpcd {
                debug!(
                    "{nfi}: Set packet dst_vpcd to {dst_vpcd} from src_vpcd:{src_vpcd}, prefix:{prefix}"
                );
                packet.meta.dst_vpcd = Some(*dst_vpcd);
            } else {
                debug!(
                    "{nfi}: no dst_vpcd found for {dst_ip} in src_vpcd {src_vpcd}: marking packet as unroutable"
                );
                packet.done(DoneReason::Unroutable);
            }
        } else {
            debug!("{nfi}: no vpcd table found for src_vpcd {src_vpcd} (dst_addr={dst_ip})");
            packet.done(DoneReason::Unroutable);
        }
    }
}

impl<Buf: PacketBufferMut> NetworkFunction<Buf> for DstVpcdLookup {
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
                error!("{}: failed to read vpcd tables", self.name);
                packet.done(DoneReason::InternalFailure);
            }
            packet.enforce()
        })
    }
}

#[cfg(test)]
mod test {
    use super::{DstVpcdLookup, VpcDiscTablesWriter, VpcDiscriminantTable, VpcDiscriminantTables};
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
        let mut vpcd_table_100 = VpcDiscriminantTable::new();
        let dst_vpcd_100_192_168_1_0_24 = VpcDiscriminant::VNI(vni101);
        let dst_vpcd_100_192_168_0_0_16 = VpcDiscriminant::VNI(vni102);
        vpcd_table_100
            .dst_vpcds
            .insert(Prefix::from("192.168.1.0/24"), dst_vpcd_100_192_168_1_0_24);
        vpcd_table_100
            .dst_vpcds
            .insert(Prefix::from("192.168.0.0/16"), dst_vpcd_100_192_168_0_0_16);
        vpcd_table_100.dst_vpcds.insert(
            Prefix::from("::192.168.1.0/120"),
            dst_vpcd_100_192_168_1_0_24,
        );
        vpcd_table_100.dst_vpcds.insert(
            Prefix::from("::192.168.0.0/112"),
            dst_vpcd_100_192_168_0_0_16,
        );

        // VNI 200
        let mut vpcd_table_200 = VpcDiscriminantTable::new();
        let dst_vpcd_200_192_168_2_0_24 = VpcDiscriminant::VNI(vni201);
        let dst_vpcd_200_192_168_0_0_16 = VpcDiscriminant::VNI(vni202);
        vpcd_table_200
            .dst_vpcds
            .insert(Prefix::from("192.168.2.0/24"), dst_vpcd_200_192_168_2_0_24);
        vpcd_table_200
            .dst_vpcds
            .insert(Prefix::from("192.168.2.0/16"), dst_vpcd_200_192_168_0_0_16);
        vpcd_table_200.dst_vpcds.insert(
            Prefix::from("::192.168.2.0/120"),
            dst_vpcd_200_192_168_2_0_24,
        );
        vpcd_table_200.dst_vpcds.insert(
            Prefix::from("::192.168.0.0/112"),
            dst_vpcd_200_192_168_0_0_16,
        );

        ////////////////////////////
        // Setup VpcDiscriminant tables writer
        let mut vpcd_tables = VpcDiscriminantTables::new();
        vpcd_tables
            .tables_by_discriminant
            .insert(VpcDiscriminant::VNI(vni100), vpcd_table_100);
        vpcd_tables
            .tables_by_discriminant
            .insert(VpcDiscriminant::VNI(vni200), vpcd_table_200);
        let mut vpcd_tables_w = VpcDiscTablesWriter::new();
        vpcd_tables_w.update_vpcd_tables(vpcd_tables);

        ////////////////////////////
        // Setup DstVpcdLookup stage
        let mut dst_vpcd_lookup = DstVpcdLookup::new("test", vpcd_tables_w.get_reader());

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
        let packets = dst_vpcd_lookup
            .process(packets_in.into_iter())
            .collect::<Vec<_>>();

        assert_eq!(packets.len(), 5);
        assert_eq!(packets[0].meta.dst_vpcd, Some(dst_vpcd_100_192_168_1_0_24));
        assert!(!packets[0].is_done());
        assert_eq!(packets[1].meta.dst_vpcd, Some(dst_vpcd_100_192_168_0_0_16));
        assert!(!packets[1].is_done());
        assert_eq!(packets[2].meta.dst_vpcd, Some(dst_vpcd_200_192_168_2_0_24));
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
        let packets = dst_vpcd_lookup
            .process(packets_in.into_iter())
            .collect::<Vec<_>>();
        assert_eq!(packets.len(), 4);
        assert_eq!(packets[0].meta.dst_vpcd, Some(dst_vpcd_100_192_168_1_0_24));
        assert!(!packets[0].is_done());
        assert_eq!(packets[1].meta.dst_vpcd, Some(dst_vpcd_100_192_168_0_0_16));
        assert!(!packets[1].is_done());
        assert_eq!(packets[2].meta.dst_vpcd, Some(dst_vpcd_200_192_168_2_0_24));
        assert!(!packets[2].is_done());
        assert_eq!(packets[3].meta.dst_vpcd, None);
        assert_eq!(packets[3].get_done(), Some(DoneReason::Unroutable));
    }
}
