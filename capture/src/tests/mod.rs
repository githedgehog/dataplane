// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crate::{CaptureNames, CaptureRecord, CaptureStage, CaptureWriter, Direction};
use net::buffer::TestBuffer;
use net::interface::InterfaceIndex;
use net::packet::{DoneReason, Packet, VpcDiscriminant};
use net::vxlan::Vni;
use pcap_file::pcapng::blocks::enhanced_packet::EnhancedPacketOption;
use pcap_file::pcapng::blocks::interface_description::InterfaceDescriptionOption;
use pcap_file::pcapng::blocks::interface_statistics::InterfaceStatisticsOption;
use pcap_file::pcapng::blocks::opt_common::CommonOption;
use pcap_file::pcapng::{Block, PcapNgReader};
use pipeline::NetworkFunction;
use std::collections::HashSet;
use strum::EnumCount;

// Not under loom: shuttle covers the races (stop against admission, a full queue, budget exhaustion), and
// an exhaustive search over the writer thread costs far more CI time than it could find.
#[cfg(not(feature = "loom"))]
mod controller;

/// Metadata to stamp on a generated packet, drawn from small domains so interfaces repeat.
#[derive(Debug, Clone, Copy, bolero::TypeGenerator)]
struct Stamp {
    egress: bool,
    iif: u8,
    oif: u8,
    src_vni: u8,
    dst_vni: u8,
    done: u8,
}

fn interface(raw: u8) -> Option<InterfaceIndex> {
    InterfaceIndex::try_new(u32::from(raw % 4)).ok()
}

fn vpcd(raw: u8) -> Option<VpcDiscriminant> {
    let vni = Vni::new_checked(u32::from(raw % 3) * 100).ok()?;
    Some(VpcDiscriminant::VNI(vni))
}

/// Names interface 1 and 2 and the VPC behind VNI 100, leaving interface 3 and VNI 200 unnamed so both
/// paths are exercised.
fn names() -> CaptureNames {
    CaptureNames::default()
        .with_interface(InterfaceIndex::try_new(1).unwrap(), "eth1")
        .with_interface(InterfaceIndex::try_new(2).unwrap(), "eth2")
        .with_vpc(vpcd(1).unwrap(), "vpc-1")
}

fn stamp(packet: &mut Packet<TestBuffer>, stamp: Stamp) {
    let meta = packet.meta_mut();
    meta.iif = interface(stamp.iif);
    meta.oif = interface(stamp.oif);
    meta.src_vpcd = vpcd(stamp.src_vni);
    meta.dst_vpcd = vpcd(stamp.dst_vni);
    #[allow(clippy::cast_possible_truncation)] // DoneReason is repr(u8)
    let reasons = DoneReason::COUNT as u8 + 1;
    meta.done = DoneReason::from_repr(stamp.done % reasons);
}

/// The frame `packet` would put on the wire.
fn wire(packet: &Packet<TestBuffer>) -> Vec<u8> {
    let copy = packet.deep_copy().unwrap();
    copy.serialize().unwrap().as_ref().to_vec()
}

fn interface_name(interface: Option<InterfaceIndex>) -> &'static str {
    match interface.map(InterfaceIndex::to_u32) {
        Some(1) => "eth1",
        Some(2) => "eth2",
        Some(3) => "unnamed(3)",
        Some(other) => unreachable!("interface {other} is outside the generated domain"),
        None => "no interface",
    }
}

/// Capture `packets` going in each stamped direction, write them, read them back, and check every
/// packet block against the packet it came from.
fn round_trip(cases: Vec<(Packet<TestBuffer>, Stamp)>) {
    let mut expected = Vec::new();
    let mut records = Vec::new();
    for (mut packet, how) in cases {
        stamp(&mut packet, how);
        let direction = if how.egress {
            Direction::Egress
        } else {
            Direction::Ingress
        };
        let mut nf = CaptureStage::new(direction, Vec::<CaptureRecord>::new());
        let wire = wire(&packet);
        let mut burst = vec![packet];
        nf.process_burst(&mut burst);
        let [record] = <[_; 1]>::try_from(nf.into_sink()).unwrap();
        expected.push((wire, burst.pop().unwrap()));
        records.push(record);
    }

    let mut writer = CaptureWriter::new(Vec::new(), names()).unwrap();
    for record in &records {
        writer.write(record).unwrap();
    }
    let bytes = writer
        .finish(&"summary", std::time::Duration::from_secs(1))
        .unwrap();

    let mut reader = PcapNgReader::new(bytes.as_slice()).unwrap();
    let mut packets = 0;
    let mut statistics = 0;
    let mut described = Vec::new();
    while let Some(block) = reader.next_block() {
        let (block, state) = block.unwrap();
        match block {
            Block::InterfaceDescription(idb) => {
                let name = idb.options.iter().find_map(|option| match option {
                    InterfaceDescriptionOption::IfName(name) => Some(name.to_string()),
                    _ => None,
                });
                described.push(name.expect("interface without a name"));
            }
            Block::EnhancedPacket(epb) => {
                let record = &records[packets];
                let (wire, packet) = &expected[packets];
                packets += 1;

                let interface_id = usize::try_from(epb.interface_id).unwrap();
                assert_eq!(described[interface_id], interface_name(record.interface()));
                assert_eq!(epb.timestamp, record.timestamp());
                assert_eq!(epb.original_len, u32::try_from(wire.len()).unwrap());
                assert_eq!(epb.data.len(), usize::from(packet.header_len().get()));
                assert_eq!(&epb.data[..], &wire[..epb.data.len()]);

                let direction = epb.options.iter().find_map(|option| match option {
                    EnhancedPacketOption::Flags(flags) => Some(flags & 0b11),
                    _ => None,
                });
                let inbound = record.direction() == Direction::Ingress;
                assert_eq!(direction, Some(if inbound { 0b01 } else { 0b10 }));

                let comment = epb.options.iter().find_map(|option| match option {
                    EnhancedPacketOption::Common(CommonOption::Comment(text)) => {
                        Some(text.to_string())
                    }
                    _ => None,
                });
                assert_eq!(comment, Some(record.annotation(&names()).to_string()));
            }
            Block::InterfaceStatistics(isb) => {
                statistics += 1;
                let summary = isb.options.iter().find_map(|option| match option {
                    InterfaceStatisticsOption::Common(CommonOption::Comment(text)) => {
                        Some(text.to_string())
                    }
                    _ => None,
                });
                assert_eq!(summary.as_deref(), Some("summary"));
            }
            Block::SectionHeader(_) => {}
            other => panic!("unexpected block {other:?} (state {state:?})"),
        }
    }
    assert_eq!(packets, records.len());

    let distinct: HashSet<_> = records.iter().map(CaptureRecord::interface).collect();
    assert_eq!(
        described.len(),
        distinct.len(),
        "an interface was described twice"
    );
    assert_eq!(
        statistics,
        described.len(),
        "every interface gets the closing summary"
    );
}

#[test]
fn captured_frames_are_the_wire_headers() {
    bolero::check!()
        .with_type::<Vec<(Packet<TestBuffer>, Stamp)>>()
        .for_each(|cases| {
            let cases = cases
                .iter()
                .map(|(packet, how)| (packet.deep_copy().unwrap(), *how))
                .collect();
            round_trip(cases);
        });
}

#[test]
fn annotation_names_every_field() {
    let mut packet = net::packet::test_utils::build_test_ipv4_packet(64).unwrap();
    packet.meta_mut().iif = InterfaceIndex::try_new(1).ok();
    packet.meta_mut().oif = InterfaceIndex::try_new(3).ok();
    packet.meta_mut().src_vpcd = vpcd(1);
    packet.meta_mut().dst_vpcd = vpcd(2);
    packet.meta_mut().done = Some(DoneReason::AclDropped);
    let record = CaptureRecord::new(Direction::Egress, &packet, clock::system_now(), None);
    assert_eq!(
        record.annotation(&names()).to_string(),
        "direction=egress thread=- done=AclDropped iif=eth1 oif=unnamed(3) \
         src_vni=100 src_vpc=vpc-1 dst_vni=200 dst_vpc=- flow=-"
    );
    assert_eq!(record.interface(), InterfaceIndex::try_new(3).ok());
}
