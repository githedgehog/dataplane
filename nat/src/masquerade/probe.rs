// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Packets drawn relative to a masquerade configuration.
//!
//! The same shape as `static_nat::probe` -- a [`ProbeSpec`] of bare indices, resolved against a
//! built [`Fabric`] -- and the same reason for it. What differs is everything that follows from
//! masquerade being **stateful**, and that difference is the whole point of doing it second.
//!
//! # Static NAT is a function of its configuration; masquerade is not
//!
//! Static NAT's answer for a packet is fixed by the tables. Masquerade's is whatever the allocator
//! handed out the first time it saw the flow, kept in the flow table and reused thereafter. So:
//!
//! * **A probe is a flow, not a packet.** The first packet of a flow takes the allocation path; the
//!   second takes the hot path through `flow_info`. They are different code and the interesting
//!   properties relate them.
//! * **The reply needs a stage in front.** `Masquerade` recovers the reverse translation from
//!   `flow_info`, which `FlowLookup` attaches, and only when `dst_vpcd` is absent. So the harness
//!   runs two stages, and the reply arrives with the annotation deliberately left off.
//! * **Order matters.** Two runs of the same batch against the same fabric are not required to
//!   agree, because the first left allocations behind. Every property here either states something
//!   about one run or builds a fresh fabric.
//!
//! # The three prerequisites
//!
//! The development guide lists what has to be true before a stateful stage can be compared at all,
//! and all three are handled here rather than assumed:
//!
//! 1. **Seeded non-determinism.** `apply_masquerade_config` randomizes port selection, so two
//!    fabrics allocate differently for the same flow. [`Fabric::build`] sets `set_randomize(false)`.
//! 2. **Timers.** Flow entries expire on a wall clock the harness does not drive. Rather than fake
//!    it, every property here is written to complete within one flow lifetime -- the shortest
//!    masquerade timeout is five seconds and a probe is a handful of packets -- so no property
//!    depends on expiry either happening or not. Expiry is a separate subject and wants the
//!    explicit clock the guide asks for.
//! 3. **Projections, not state.** Nothing here inspects the allocator or the flow table. Every
//!    assertion is over what came out of the pipeline.

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

/// Flow table capacity. Large enough that no property here can exhaust it, so a translation failure
/// is never the table being full.
const FLOW_CAPACITY: usize = 4096;

/// A VNI no generated configuration uses.
const ABSENT_VNI: u32 = 4_000;

/// A built masquerade configuration, and the addresses it declares.
pub(crate) struct Fabric {
    flow_table: Arc<FlowTable>,
    allocator: NatAllocatorWriter,
    /// Every address the local exposes offer.
    pub(crate) private: Vec<IpAddr>,
    /// The prefixes translations must land inside.
    pub(crate) public: Vec<Prefix>,
    /// Addresses in the peer vpc.
    pub(crate) peer: Vec<IpAddr>,
}

impl Fabric {
    /// Build the allocator a set of exposes implies, or `None` if the overlay is not valid.
    pub(crate) fn build(exposes: &[VpcExpose]) -> Option<Self> {
        let overlay = overlay_with_exposes(exposes.to_vec()).ok()?;
        let validated = overlay.validate().ok()?;

        // Only the first address of each private prefix: masquerade puts many private addresses
        // behind few public ones, so the prefixes are /24s and enumerating them would be tens of
        // thousands of probes for no new behaviour. What matters is that distinct sources contend
        // for the same public range, and a handful of them does that.
        let private: Vec<IpAddr> = exposes
            .iter()
            .flat_map(|e| e.ips.iter().map(|p| p.prefix().as_address()))
            .collect();
        // From the *validated* overlay, not from `exposes`. Validation collapses exclusion
        // prefixes, so the raw `as_range` is a superset of what the allocator's pool is built
        // from -- and a containment property asserted against the superset would accept a
        // translation to an address the operator explicitly excluded. The generator emits no
        // exclusions today, which is the only reason the two agree.
        let public: Vec<Prefix> = validated
            .vpc_table()
            .values()
            .flat_map(|vpc| vpc.peerings())
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
        // Randomized port selection would make two fabrics built from one configuration disagree on
        // every flow, which is legitimate behaviour and useless to compare.
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

    /// The two stages a masqueraded packet passes through.
    ///
    /// `FlowLookup` first, because it is what turns a reply into something `Masquerade` can
    /// recognise: the reverse translation lives in the flow entry the forward packet created, and
    /// nothing else puts it on the packet.
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

    /// Whether this fabric can be probed at all.
    pub(crate) fn is_probeable(&self) -> bool {
        !self.private.is_empty() && !self.public.is_empty()
    }

    /// Whether `addr` is inside one of the public prefixes the configuration named.
    pub(crate) fn is_public(&self, addr: IpAddr) -> bool {
        self.public.iter().any(|p| p.covers_addr(&addr))
    }
}

/// Put a batch through the stages, in the order the real pipeline uses.
///
/// **The order is the whole point, and getting it wrong makes the harness lie.** `FlowLookup`
/// attaches a flow entry only to a packet whose `dst_vpcd` is *absent*, and the flow filter that
/// sets `dst_vpcd` runs after it. So a harness that stamps both annotations up front never attaches
/// any flow state, every packet takes the allocation path, and a flow appears to be re-allocated on
/// every packet -- which is what this harness did until it was corrected.
///
/// `Masquerade` then requires `dst_vpcd` to be present, so the annotation genuinely has to arrive
/// between the two stages rather than before or after both. That is the flow filter's job in
/// production and `TestFlowFilter`'s in the existing tests; here it is one assignment, which is all
/// of it that matters to masquerade.
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

/// The metadata a packet must carry for [`Masquerade`] to look at it.
///
/// Split in two on purpose. Everything here except `dst_vpcd` is set before the flow lookup;
/// `dst_vpcd` is set between the lookup and masquerade, because the lookup refuses to attach flow
/// state to a packet that already carries it. See [`run`].
#[derive(Debug, Clone, Copy)]
pub(crate) struct Arrival {
    pub(crate) src_vpcd: Option<Vni>,
    /// Supplied *after* the flow lookup, by [`run`], standing in for the flow filter.
    pub(crate) dst_vpcd: Option<Vni>,
    pub(crate) wants_masquerade: bool,
}

impl Arrival {
    /// The first packet of a flow leaving the local vpc.
    pub(crate) fn outbound() -> Self {
        Self {
            src_vpcd: Some(vni(LOCAL_VNI)),
            dst_vpcd: Some(vni(REMOTE_VNI)),
            wants_masquerade: true,
        }
    }

    /// The reply, arriving from the peer. The flow filter resolves its destination back to the
    /// local vpc from the flow entry, which is what [`run`] stands in for.
    pub(crate) fn inbound() -> Self {
        Self {
            src_vpcd: Some(vni(REMOTE_VNI)),
            dst_vpcd: Some(vni(LOCAL_VNI)),
            wants_masquerade: true,
        }
    }

    /// Everything an upstream stage sets *before* the flow lookup.
    pub(crate) fn stamp(self, packet: &mut Packet<TestBuffer>) {
        let meta = packet.meta_mut();
        meta.src_vpcd = self.src_vpcd.map(VpcDiscriminant::from_vni);
        meta.set_overlay(true);
        meta.set_keep(true);
        meta.set_masquerade(self.wants_masquerade);
    }
}

/// A deliberate deviation from a flow the configuration masquerades.
#[derive(Debug, Clone, Copy, TypeGenerator)]
pub(crate) enum Stray {
    /// A source address no expose offers, which the allocator has no range for.
    SourceNotExposed,
    /// A source vpc with no allocator entry of its own.
    UnknownSourceVni,
    /// A destination vpc the local vpc does not peer with.
    UnknownDestVni,
    /// Nothing asked for masquerade, so the stage should pass the packet through untouched.
    NotAskedFor,
}

/// A drawn probe, before it knows anything about a configuration.
#[derive(Debug, Clone, Copy, TypeGenerator)]
pub(crate) struct ProbeSpec {
    source: u8,
    peer: u8,
    /// UDP throughout. TCP is refused unless the packet is a first segment, which is a separate
    /// question from the mapping and would only add a rejection path to every property here.
    sport: u16,
    dport: u16,
    stray: Option<Stray>,
}

/// A probe resolved against a fabric.
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
    /// Whether masquerade was asked to translate this flow and given what it needs to.
    pub(crate) fn asks_for_translation(&self) -> bool {
        self.arrival.wants_masquerade
            && self.arrival.src_vpcd == Some(vni(LOCAL_VNI))
            && self.arrival.dst_vpcd == Some(vni(REMOTE_VNI))
    }

    /// The outbound packet, which may be built more than once.
    ///
    /// Unlike the static NAT probe this hands back a fresh packet each time on purpose: sending the
    /// same flow twice is how the hot path is reached, and a property that wants to compare the two
    /// needs both.
    pub(crate) fn packet(&self) -> Packet<TestBuffer> {
        let mut packet = build(self.source, self.destination, false, self.sport, self.dport);
        self.arrival.stamp(&mut packet);
        packet
    }

    /// The reply to a flow that was translated to `translated`.
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
    /// Drop the deviation, leaving a flow the configuration is meant to masquerade.
    pub(crate) fn clear_stray(&mut self) {
        self.stray = None;
    }

    /// Interpret this draw against a fabric.
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
