// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![cfg(test)]

use crate::masquerade::{MasqueradeConfig, NatAllocatorWriter};
use bolero::TypeGenerator;
use concurrency::sync::Arc;
use config::external::overlay::vpcpeering::VpcExpose;
use config::external::overlay::vpcpeering::contract::{
    LOCAL_VNI, REMOTE_VNI, overlay_with_exposes,
};
use flow_entry::flow_table::{FlowLookup, FlowTable};
use lpm::prefix::Prefix;
use net::buffer::TestBuffer;
use net::packet::{Packet, VpcDiscriminant};
use net::vxlan::Vni;
use pipeline::NetworkFunction;
use std::net::IpAddr;

use crate::Masquerade;
use crate::static_nat::probe::{build, vni};

const FLOW_CAPACITY: usize = 4096;

const ABSENT_VNI: u32 = 4_000;

pub(crate) struct Fabric {
    flow_table: Arc<FlowTable>,
    allocator: NatAllocatorWriter,
    pub(crate) private: Vec<IpAddr>,
    pub(crate) public: Vec<Prefix>,
    pub(crate) peer: Vec<IpAddr>,
}

impl Fabric {
    pub(crate) fn build(exposes: &[VpcExpose]) -> Option<Self> {
        let overlay = overlay_with_exposes(exposes.to_vec()).ok()?;
        let validated = overlay.validate().ok()?;

        let private: Vec<IpAddr> = exposes
            .iter()
            .flat_map(|e| e.ips.iter().map(|p| p.prefix().as_address()))
            .collect();
        let public: Vec<Prefix> = validated
            .vpc_table()
            .values()
            .filter(|vpc| vpc.vni() == vni(LOCAL_VNI))
            .flat_map(config::external::overlay::vpc::ValidatedVpc::peerings)
            .flat_map(|peering| peering.local().valexp())
            .flat_map(|expose| expose.as_range_or_empty().iter())
            .map(lpm::prefix::PrefixWithOptionalPorts::prefix)
            .collect();

        let peer = match private.first() {
            Some(IpAddr::V6(_)) => vec![
                "2001:db8:ffff::1"
                    .parse()
                    .unwrap_or_else(|_| unreachable!()),
                "2001:db8:ffff::2"
                    .parse()
                    .unwrap_or_else(|_| unreachable!()),
            ],
            _ => vec![
                "3.3.3.1".parse().unwrap_or_else(|_| unreachable!()),
                "3.3.3.2".parse().unwrap_or_else(|_| unreachable!()),
            ],
        };

        let flow_table = Arc::new(FlowTable::new(FLOW_CAPACITY));
        let mut allocator = NatAllocatorWriter::new();
        let config = MasqueradeConfig::new(validated.vpc_table()).set_randomize(false);
        allocator.update_nat_allocator(config, 1, &flow_table);

        Some(Self {
            flow_table,
            allocator,
            private,
            public,
            peer,
        })
    }

    pub(crate) fn stages(&self) -> (FlowLookup, Masquerade) {
        (
            FlowLookup::new("flow-lookup", self.flow_table.clone()),
            Masquerade::new(
                "masquerade",
                self.flow_table.clone(),
                self.allocator.get_reader(),
            ),
        )
    }

    pub(crate) fn live_flows(&self) -> usize {
        let count = concurrency::sync::atomic::AtomicUsize::new(0);
        self.flow_table.for_each_flow_sharded(|_, _| {
            count.fetch_add(1, concurrency::sync::atomic::Ordering::Relaxed);
        });
        count.load(concurrency::sync::atomic::Ordering::Relaxed)
    }

    pub(crate) fn is_probeable(&self) -> bool {
        !self.private.is_empty() && !self.public.is_empty()
    }

    pub(crate) fn is_public(&self, addr: IpAddr) -> bool {
        self.public.iter().any(|p| p.covers_addr(&addr))
    }
}

pub(crate) fn run(
    lookup: &mut FlowLookup,
    masq: &mut Masquerade,
    packets: Vec<Packet<TestBuffer>>,
    dst_vpcd: Option<Vni>,
) -> Vec<Packet<TestBuffer>> {
    let mut looked: Vec<_> = lookup.process(packets.into_iter()).collect();
    for packet in &mut looked {
        packet.meta_mut().dst_vpcd = dst_vpcd.map(VpcDiscriminant::from_vni);
    }
    masq.process(looked.into_iter()).collect()
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Arrival {
    pub(crate) src_vpcd: Option<Vni>,
    pub(crate) dst_vpcd: Option<Vni>,
    pub(crate) wants_masquerade: bool,
}

impl Arrival {
    pub(crate) fn outbound() -> Self {
        Self {
            src_vpcd: Some(vni(LOCAL_VNI)),
            dst_vpcd: Some(vni(REMOTE_VNI)),
            wants_masquerade: true,
        }
    }

    pub(crate) fn inbound() -> Self {
        Self {
            src_vpcd: Some(vni(REMOTE_VNI)),
            dst_vpcd: Some(vni(LOCAL_VNI)),
            wants_masquerade: true,
        }
    }

    pub(crate) fn stamp(self, packet: &mut Packet<TestBuffer>) {
        let meta = packet.meta_mut();
        meta.src_vpcd = self.src_vpcd.map(VpcDiscriminant::from_vni);
        meta.set_overlay(true);
        meta.set_keep(true);
        meta.set_masquerade(self.wants_masquerade);
    }
}

#[derive(Debug, Clone, Copy, TypeGenerator)]
pub(crate) enum Stray {
    SourceNotExposed,
    UnknownSourceVni,
    UnknownDestVni,
    NotAskedFor,
}

#[derive(Debug, Clone, Copy, TypeGenerator)]
pub(crate) struct ProbeSpec {
    source: u8,
    peer: u8,
    sport: u16,
    dport: u16,
    stray: Option<Stray>,
}

pub(crate) struct Probe {
    pub(crate) source: IpAddr,
    pub(crate) destination: IpAddr,
    pub(crate) sport: u16,
    pub(crate) dport: u16,
    pub(crate) exposed: bool,
    pub(crate) arrival: Arrival,
    pub(crate) stray: Option<Stray>,
}

impl Probe {
    pub(crate) fn asks_for_translation(&self) -> bool {
        self.arrival.wants_masquerade
            && self.arrival.src_vpcd == Some(vni(LOCAL_VNI))
            && self.arrival.dst_vpcd == Some(vni(REMOTE_VNI))
    }

    pub(crate) fn packet(&self) -> Packet<TestBuffer> {
        let mut packet = build(self.source, self.destination, false, self.sport, self.dport);
        self.arrival.stamp(&mut packet);
        packet
    }

    pub(crate) fn reply(&self, translated: IpAddr, translated_port: u16) -> Packet<TestBuffer> {
        let mut packet = build(
            self.destination,
            translated,
            false,
            self.dport,
            translated_port,
        );
        Arrival::inbound().stamp(&mut packet);
        packet
    }
}

impl ProbeSpec {
    pub(crate) fn clear_stray(&mut self) {
        self.stray = None;
    }

    pub(crate) fn resolve(self, fabric: &Fabric) -> Probe {
        let mut arrival = Arrival::outbound();
        let mut source = fabric.private[self.source as usize % fabric.private.len()];
        let destination = fabric.peer[self.peer as usize % fabric.peer.len()];
        let mut exposed = true;

        match self.stray {
            None => {}
            Some(Stray::SourceNotExposed) => {
                source = destination;
                exposed = false;
            }
            Some(Stray::UnknownSourceVni) => arrival.src_vpcd = Some(vni(ABSENT_VNI)),
            Some(Stray::UnknownDestVni) => arrival.dst_vpcd = Some(vni(ABSENT_VNI)),
            Some(Stray::NotAskedFor) => arrival.wants_masquerade = false,
        }

        Probe {
            source,
            destination,
            sport: self.sport.max(1),
            dport: self.dport.max(1),
            exposed,
            arrival,
            stray: self.stray,
        }
    }
}
