// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![allow(dead_code)]

use lpm::prefix::Prefix;
use net::buffer::TestBuffer;
use net::interface::InterfaceIndex;
use net::ip::NextHeader;
use net::packet::Packet;
use net::packet::test_utils::build_test_ipv4_packet_with_transport;

use dataplane_routing::testing::{Fib, FibGroup, FibWriter, FwAction, NhopKey, RouteOrigin};
use dataplane_routing::{EgressObject, FibEntry, PktInstruction};

pub const ROUTE_ADDR: (&str, u8) = ("5.0.0.0", 8);

#[macro_export]
macro_rules! for_each_shape {
    ($expand:ident) => {
        $expand! {
            g1_e1 = (1, 1),
            g1_e4 = (1, 4),
            g4_e1 = (4, 1),
            g4_e4 = (4, 4),
            g8_e1 = (8, 1),
            g16_e1 = (16, 1),
            g16_e4 = (16, 4),
        }
    };
}

pub struct Fixture {
    pub writer: FibWriter,
    pub packet: Packet<TestBuffer>,
}

fn nhop_key(n: u8) -> NhopKey {
    NhopKey::new(
        RouteOrigin::default(),
        Some(format!("10.0.{n}.1").parse().expect("valid address")),
        InterfaceIndex::try_new(u32::from(n) + 1).ok(),
        None,
        FwAction::Forward,
    )
}

fn fib_group(n: u8, entries: u8) -> FibGroup {
    let mut group = FibGroup::new();
    for e in 0..entries {
        group.add(FibEntry::with_inst(PktInstruction::Egress(
            EgressObject::new(
                InterfaceIndex::try_new(u32::from(n) * 256 + u32::from(e) + 1).ok(),
                Some(format!("10.{n}.{e}.1").parse().expect("valid address")),
            ),
        )));
    }
    group
}

pub fn packet() -> Packet<TestBuffer> {
    build_test_ipv4_packet_with_transport(64, Some(NextHeader::UDP))
        .expect("a well-formed test packet")
}

pub fn fixture(groups: u8, entries_per_group: u8) -> &'static Fixture {
    let (mut writer, _reader) = FibWriter::new(0);
    let keys: Vec<NhopKey> = (0..groups).map(nhop_key).collect();
    for (n, key) in keys.iter().enumerate() {
        let n = u8::try_from(n).expect("group count fits a byte");
        writer.register_fibgroup(key, &fib_group(n, entries_per_group), false);
    }
    writer.add_fibroute(Prefix::expect_from(ROUTE_ADDR), keys, true);

    let packet = packet();

    {
        let fib = writer.enter().expect("fib is readable");
        let (hit, _) = Fib::lpm_entry_prefix(&fib, &packet);
        assert_eq!(
            hit,
            Prefix::expect_from(ROUTE_ADDR),
            "{groups}g x{entries_per_group}e: lookup missed the installed route"
        );
    }

    Box::leak(Box::new(Fixture { writer, packet }))
}

#[inline(always)]
pub fn lookup(fixture: &Fixture) {
    let fib = fixture.writer.enter().expect("fib is readable");
    let (prefix, entry) = Fib::lpm_entry_prefix(&fib, std::hint::black_box(&fixture.packet));
    std::hint::black_box((prefix, entry));
}
