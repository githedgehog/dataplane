// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![doc = include_str!("../README.md")]

use crate::context::Route;
use concurrency::sync::{Arc, Weak};
use config::external::overlay::vpcpeering::{ValidatedExpose, VpcExposeNatConfig};
use net::FlowKey;
use net::buffer::PacketBufferMut;
use net::flows::{FlowInfo, FlowStatus};
use net::headers::{TryIp, TryTransport};
use net::packet::{DoneReason, Packet, PacketMeta, VpcDiscriminant};
use pipeline::{NetworkFunction, PipelineData};
use std::num::NonZero;
use tracectl::trace_target;
use tracing::{debug, error, warn};

trace_target!("flow-filter", LevelFilter::INFO, &["pipeline"]);

mod context;
#[cfg(test)]
mod fuzz_gen;
#[cfg(test)]
mod test_utils;
#[cfg(test)]
mod tests;

pub use context::{
    FlowFilterContext, FlowFilterContextReader, FlowFilterContextReaderFactory,
    FlowFilterContextWriter,
};
use context::{LookupInput, LookupResult};

pub struct FlowFilter {
    name: String,
    tables: FlowFilterContextReader,
    pipeline_data: Arc<PipelineData>,
}

/// Outcome of phase A (`classify`) for one packet.
enum Classification {
    /// Handled in place via active flow state; no table lookup needed.
    Bypassed,
    /// Drop the packet (Setting the DoneReason in its metadatas is done in place).
    Drop,
    /// Needs a table lookup; carries the query and any attached flow summary (for phase C).
    /// `LookupInput` may be built from the packet or the master flow in the reverse direction
    Lookup {
        input: LookupInput,
        flow_summary: Option<FlowSummary>,
    },
}

/// A packet awaiting phase C: its index in the burst and the flow summary from phase A.
struct WorkItem {
    idx: usize,
    flow_summary: Option<FlowSummary>,
}

impl FlowFilter {
    pub fn new(name: &str, tables: FlowFilterContextReader) -> Self {
        Self {
            name: name.to_string(),
            tables,
            pipeline_data: Arc::new(PipelineData::default()),
        }
    }

    /// Process a whole burst in three phases so the (only batchable) part -- the ACL lookup -- is
    /// pooled into batched rte_acl calls:
    ///
    /// - A (`classify`, per packet): passthrough / flow-bypass / drop, or gather a [`LookupInput`].
    /// - B (batched): one two-pass lookup for the burst; results are `Copy` so the context guard is
    ///   dropped before any packet is mutated.
    /// - C (`apply_route`, per packet): stamp the destination + NAT flags, or drop on a miss.
    fn process_burst<Buf: PacketBufferMut>(&mut self, burst: &mut [Packet<Buf>]) {
        let genid = self.pipeline_data.genid();

        let mut inputs: Vec<LookupInput> = Vec::new();
        let mut work: Vec<WorkItem> = Vec::new();
        for (idx, packet) in burst.iter_mut().enumerate() {
            if packet.is_done() || !packet.meta().is_overlay() || packet.meta().dst_vpcd.is_some() {
                continue;
            }
            match self.classify(packet, genid) {
                Classification::Bypassed | Classification::Drop => {}
                Classification::Lookup {
                    input,
                    flow_summary,
                } => {
                    work.push(WorkItem { idx, flow_summary });
                    inputs.push(input);
                }
            }
        }
        if inputs.is_empty() {
            return;
        }

        let mut results: Vec<LookupResult> = vec![LookupResult::DestinationMiss; inputs.len()];
        let tables = self.tables.load();
        tables.lookup_batch(&inputs, &mut results);

        // `work`, `inputs` and `results` are aligned by index
        for (i, item) in work.iter().enumerate() {
            self.apply_route(
                &mut burst[item.idx],
                item.flow_summary.as_ref(),
                inputs[i],
                results[i],
            );
        }
    }

    fn get_packet_flow_state<Buf: PacketBufferMut>(
        &self,
        packet: &Packet<Buf>,
    ) -> Option<FlowSummary> {
        let nfi = &self.name;
        let flow_info = packet.meta().flow_info.as_ref()?;
        if flow_info.status() != FlowStatus::Active {
            debug!("{nfi}: Packet hit non-active flow. Will ignore flow");
            return None;
        }
        let Some(summary) = FlowSummary::from_flow_info(flow_info) else {
            error!("{nfi}: Bad flow summary: missing src or dst vpc discriminant. This is a bug");
            packet.invalidate_flows();
            return None;
        };
        // packet hits a sane, active flow, but we have not yet checked if the flow
        // is compatible with the current generation id or not
        Some(summary)
    }

    /// Build a `LookupInput` from the flow key that led to the creation of this flow
    fn build_lookup_key_from_flow(summary: &FlowSummary) -> Option<LookupInput> {
        let flow_info = summary.flow_info.related.as_ref().and_then(Weak::upgrade)?;
        if !flow_info.get_flags().is_pair_master() {
            error!("Related flow of a non-master flow is not the master. This is a bug");
            return None;
        }
        // related flow could be inactive (unlikely)
        if flow_info.status() != FlowStatus::Active {
            debug!("Won't use related flow: it is not active");
            return None;
        }
        let key = flow_info.flowkey();
        let input = LookupInput {
            src_vpcd: key.src_vpcd().unwrap_or_else(|| unreachable!()),
            src_ip: *key.src_ip(),
            dst_ip: *key.dst_ip(),
            proto: key.proto(),
            ports: key.ports().map(|(s, d)| (s.get(), d.get())),
        };
        debug!("Will validate flow {key}");
        Some(input)
    }

    /// Build a `LookupInput` from the packet. This assumes that the packet is IP and
    /// that it is annotated with the src vpcd
    fn build_lookup_key_from_packet<Buf: PacketBufferMut>(packet: &Packet<Buf>) -> LookupInput {
        let net = packet.try_ip().unwrap_or_else(|| unreachable!());
        LookupInput {
            src_vpcd: packet.meta().src_vpcd.unwrap_or_else(|| unreachable!()),
            src_ip: net.src_addr(),
            dst_ip: net.dst_addr(),
            proto: net.next_header(),
            ports: packet.try_transport().and_then(|t| {
                t.src_port()
                    .map(NonZero::get)
                    .zip(t.dst_port().map(NonZero::get))
            }),
        }
    }

    #[inline]
    fn packet_is_valid<Buf: PacketBufferMut>(&self, packet: &mut Packet<Buf>) -> bool {
        let nfi = &self.name;

        // disqualify non-ip
        if packet.try_ip().is_none() {
            debug!("{nfi}: No IP header found, dropping packet");
            packet.done(DoneReason::NotIp);
            return false;
        };
        // disqualify unknown origin
        if packet.meta().src_vpcd.is_none() {
            debug!("{nfi}: Missing source VPC discriminant, dropping packet");
            packet.done(DoneReason::Unroutable);
            return false;
        };
        true
    }

    /// Phase A: decide what a single overlay packet needs. Tags bypass packets in place; returns
    /// the [`LookupInput`] (plus any attached flow summary, which phase C needs) otherwise.
    fn classify<Buf: PacketBufferMut>(
        &self,
        packet: &mut Packet<Buf>,
        genid: i64,
    ) -> Classification {
        let nfi = &self.name;

        if !self.packet_is_valid(packet) {
            return Classification::Drop;
        }

        // Get the flow info that the packet matched. If packet matched no flow or it did but the flow is not
        // active, we ignore it and the flow filter always evaluates the packet.
        // If the packet matched an active flow, there are two possiblities:
        //    1) the flow is up-to-date (in terms of genid): the packet can bypass the flow filter confidently.
        //    2) the flow is not up-to-date: the packet can't' bypass the flow filter since we don't know if
        //       the flow should still be allowed nor the current treatment.
        // In case (2) it may happen that we cannot determine if the packet is "routable" nor the treatment it
        // should get under a new config because it may not correspond to the flow that initiated the communication.
        // In that case, we ask the flow filter if a packet (in the reverse direction) that would have initiated the
        // flow would still be routable. If that packet would be denied, we know the packet/flow must be dropped.
        // If such a packet would be allowed (we get a route), we trust the possibly out-dated flow if its treatment is
        // compatible with the route hit by such a packet.

        // Build a flow summary from the packet: we only get one if the packet hit an active, valid flow (might be out-dated)
        let flow_summary = self.get_packet_flow_state(packet);
        if let Some(summary) = flow_summary.as_ref() {
            let flowkey = summary.flow_info.flowkey();
            debug!("{nfi}: Packet matched active flow ({flowkey})");
            if summary.genid < genid {
                let master = summary.is_master_flow;
                debug!("{nfi}: Flow ({flowkey}) (master: {master}) could be out-dated");
                let input = if master {
                    Some(Self::build_lookup_key_from_packet(packet))
                } else {
                    Self::build_lookup_key_from_flow(summary)
                };
                if let Some(input) = input {
                    Classification::Lookup {
                        input,
                        flow_summary,
                    }
                } else {
                    warn!("{nfi}: Could not build lookup key from master flow. Will drop");
                    packet.done(DoneReason::Unroutable);
                    packet.invalidate_flows();
                    Classification::Drop
                }
            } else {
                debug!("{nfi}: Flow ({flowkey}) is up-to-date. Will bypass flow-filter");
                Self::tag_for_bypass(packet.meta_mut(), summary);
                Classification::Bypassed
            }
        } else {
            debug!("{nfi}: Packet did not match any active flow");
            let input = Self::build_lookup_key_from_packet(packet);
            Classification::Lookup {
                input,
                flow_summary,
            }
        }
    }

    /// The NAT requirements of a route
    fn route_nat_requirements(route: &Route) -> PacketMeta {
        let mut meta = PacketMeta::default();
        Self::set_nat_requirements(&mut meta, route.src_nat_mode, route.dst_nat_mode);
        meta
    }

    fn validate_flow_from_reverse_route<Buf: PacketBufferMut>(
        &self,
        packet: &mut Packet<Buf>,
        flow_summary: &FlowSummary,
        route: &Route,
        input: LookupInput,
    ) {
        let nfi = &self.name;
        debug!("{nfi}: Reverse flow would match route {route}");

        // The initiating direction must point back to where the packet came from
        if route.dst_vpcd != flow_summary.src_vpcd {
            debug!(
                "{nfi}: Flow origin {} differs from route dst {}. Will drop",
                flow_summary.src_vpcd, route.dst_vpcd
            );
            packet.done(DoneReason::Filtered);
            packet.invalidate_flows();
            return;
        }

        // check if the flow should be invalidated because it does not have the state required
        // to process the flow according to the route requirements
        let requirements = Self::route_nat_requirements(route);
        if self.should_invalidate_flow(&requirements, input.src_vpcd, Some(flow_summary)) {
            packet.invalidate_flows();
            packet.done(DoneReason::Filtered);
            return;
        }

        // use the original flow to guide the packet
        let flowkey = flow_summary.flow_info.flowkey();
        debug!("{nfi}: Evaluated flow {flowkey} seems valid. Will let packet through");
        Self::tag_for_bypass(packet.meta_mut(), flow_summary);
    }

    fn route_packet<Buf: PacketBufferMut>(
        &self,
        packet: &mut Packet<Buf>,
        route: &Route,
        flow_summary: Option<&FlowSummary>,
    ) {
        let nfi = &self.name;
        debug!("{nfi}: Packet matches route {route}");

        // Annotate destination and requirements in packet
        packet.meta_mut().dst_vpcd = Some(route.dst_vpcd);
        Self::set_nat_requirements(packet.meta_mut(), route.src_nat_mode, route.dst_nat_mode);

        // if originator requires port-forwarding and the packet has no active port-forwarding flow,
        // drop the packet since port-forwarding should not initiate flows.
        if route.src_nat_mode == Some(NatRequirement::PortForwarding)
            && !has_active_pfw_flow(flow_summary)
        {
            debug!("{nfi}: dropping packet without active port-forwarding flow");
            packet.done(DoneReason::Filtered);
            packet.invalidate_flows();
            return;
        }

        // Port forwarding or masquerading used in combination with static NAT need to keep track of
        // the initial IP addresses for creating the right flow table entries, so we may have to
        // attach the flow key to packet's metadata.
        if ((packet.meta().requires_port_forwarding() || packet.meta().requires_masquerade())
            && packet.meta().requires_static_nat())
            && let Ok(flow_key) = FlowKey::try_from(&*packet)
        {
            packet.meta_mut().flow_key = Some(Box::new(flow_key));
        }

        // The packet is allowed. However, it may refer to an outdated flow and a new flow may be
        // needed. This pipeline stage cannot always tell whether a flow is valid or not, as it
        // lacks the NAT context and state to do so. Therefore, it should not upgrade flow to newer
        // gen ids. However, it can (and must) invalidate flows in some cases, because no other
        // network function will do it otherwise.
        if self.should_invalidate_flow(packet.meta(), route.dst_vpcd, flow_summary) {
            packet.invalidate_flows();
        }
    }

    /// Phase C: apply a resolved route (or drop on a miss) to a single packet.
    /// The input `LookupInput` may not correspond to the packet but to the flow
    /// in the reverse direction that initiated the flow that this packet matched.
    fn apply_route<Buf: PacketBufferMut>(
        &self,
        packet: &mut Packet<Buf>,
        flow_summary: Option<&FlowSummary>,
        input: LookupInput,
        result: LookupResult,
    ) {
        let nfi = &self.name;
        match result {
            LookupResult::Route(route) => {
                if let Some(s) = flow_summary.filter(|s| !s.is_master_flow) {
                    // if the packet did not hit a master (initiating) flow, we queried for the reverse
                    // flow and the route we get here is not for this packet but for a packet in the reverse
                    // direction. If we got here, that means that the reverse flow (the initiating) is allowed
                    // with the current config. But, the fact that such a packet is allowed does not imply that
                    // the flow the present packet matched is valid. We must check if the flow would be
                    // compatible with that route in terms of destination and packet treatment (nat mode).
                    self.validate_flow_from_reverse_route(packet, s, &route, input);
                    return;
                }
                // We got a route for the packet, so we know where to send it and how to process it.
                self.route_packet(packet, &route, flow_summary);
            }
            LookupResult::DestinationMiss => {
                let dst = input.dst_ip;
                debug!("{nfi}: Failed to determine dst VPC for dst {dst}. Will drop");
                packet.invalidate_flows();
                packet.done(DoneReason::Filtered);
            }
            LookupResult::SourceMiss(dst_vpcd) => {
                let src = input.src_ip;
                let svpc = input.src_vpcd;
                debug!("{nfi}: Source {src} @ {svpc} is not allowed to VPC {dst_vpcd}. Will drop");
                packet.invalidate_flows();
                packet.done(DoneReason::Filtered);
            }
        }
    }

    fn tag_for_bypass(meta: &mut PacketMeta, flow_summary: &FlowSummary) {
        meta.dst_vpcd = Some(flow_summary.dst_vpcd);
        if flow_summary.needs_masquerade {
            meta.set_masquerade(true);
        }
        if flow_summary.needs_port_forwarding {
            meta.set_port_forwarding(true);
        }
        if flow_summary.flow_info.get_flags().requires_static_nat_src() {
            meta.set_static_nat_src(true);
        }
        if flow_summary.flow_info.get_flags().requires_static_nat_dst() {
            meta.set_static_nat_dst(true);
        }
    }

    fn set_nat_requirements(meta: &mut PacketMeta, src_nat: NatMode, dst_nat: NatMode) {
        match src_nat {
            Some(NatRequirement::Masquerade) => meta.set_masquerade(true),
            Some(NatRequirement::Static) => meta.set_static_nat_src(true),
            Some(NatRequirement::PortForwarding) => meta.set_port_forwarding(true),
            None => {}
        }
        match dst_nat {
            Some(NatRequirement::Masquerade) => meta.set_masquerade(true),
            Some(NatRequirement::Static) => meta.set_static_nat_dst(true),
            Some(NatRequirement::PortForwarding) => meta.set_port_forwarding(true),
            None => {}
        }
    }

    // Once a packet has been validated, if it refers to a flow, check that the flow is consistent
    // with the annotations set for the packet. This is needed to invalidate flows on configuration
    // changes since the flow a packet refers to may have been created with a prior config and no
    // longer be valid with a newer configuration. The current pipeline stage can't validate all
    // cases since it does not have sufficient information and that is something that the NFs
    // annotated by the stage should do. However, there are cases where it can invalidate and it
    // should, since no other NF may do so. For example, when transitioning from a configuration
    // that for a given flow of traffic would require state into one where the same flow wouldn't,
    // like moving from masquerade to static NAT or no NAT at all. It can also invalidate flows if
    // the dst VPC indicated by the flow filter differs from that of the flow.
    fn should_invalidate_flow(
        &self,
        meta: &PacketMeta,
        new_dst_vpcd: VpcDiscriminant,
        flow_summary: Option<&FlowSummary>,
    ) -> bool {
        let Some(flow_summary) = flow_summary else {
            return false;
        };
        let (nfi, flowkey) = (&self.name, flow_summary.flow_info.flowkey());
        if flow_summary.dst_vpcd != new_dst_vpcd {
            debug!("{nfi}: Outdated flow {flowkey} (new dst: {new_dst_vpcd}) will be invalidated.");
            return true;
        }
        if meta.requires_masquerade() != flow_summary.needs_masquerade {
            debug!("{nfi}: Outdated flow {flowkey} (masquerade requirement) will be invalidated.");
            return true;
        }
        if meta.requires_port_forwarding() != flow_summary.needs_port_forwarding {
            debug!("{nfi}: Outdated flow {flowkey} (port-fwding requirement) will be invalidated.");
            return true;
        }
        if !meta.requires_port_forwarding() && !meta.requires_masquerade() {
            debug!("{nfi}: Outdated flow {flowkey} (no longer needed) will be invalidated.");
            return true;
        }
        // We could not invalidate despite the config change. This does not mean that the flow is
        // valid (or invalid). The NFs tagged in the requirements must determine whether it's valid:
        // if we were masquerading with address A and a new config requires masquerading with
        // address B, the above won't invalidate the flow, but the NF should (or it should update
        // the flow accordingly).
        false
    }
}

impl<Buf: PacketBufferMut> NetworkFunction<Buf> for FlowFilter {
    fn process<'a, Input: Iterator<Item = Packet<Buf>> + 'a>(
        &'a mut self,
        input: Input,
    ) -> impl Iterator<Item = Packet<Buf>> + 'a {
        // The driver hands us one bounded rx burst per poll and collects our whole output, so
        // materializing the burst here is safe (not an unbounded stream) and lets us pool the ACL
        // lookups into batched rte_acl calls (see `process_burst`).
        let mut burst: Vec<Packet<Buf>> = input.collect();
        self.process_burst(&mut burst);
        burst.into_iter().filter_map(Packet::enforce)
    }

    fn set_data(&mut self, data: Arc<PipelineData>) {
        self.pipeline_data = data;
    }
}

#[derive(Debug, Clone)]
struct FlowSummary {
    is_master_flow: bool,
    genid: i64,
    src_vpcd: VpcDiscriminant,
    dst_vpcd: VpcDiscriminant,
    needs_masquerade: bool,
    needs_port_forwarding: bool,
    flow_info: Arc<FlowInfo>,
}

impl FlowSummary {
    fn from_flow_info(flow_info: &Arc<FlowInfo>) -> Option<Self> {
        let locked_info = flow_info.locked.read();
        Some(Self {
            is_master_flow: flow_info.get_flags().is_pair_master(),
            genid: flow_info.genid(),
            src_vpcd: flow_info.flowkey().src_vpcd()?,
            dst_vpcd: locked_info.dst_vpcd?,
            needs_masquerade: locked_info.nat_state.is_some(),
            needs_port_forwarding: locked_info.port_fw_state.is_some(),
            flow_info: flow_info.clone(),
        })
    }
}

fn has_active_pfw_flow(summary: Option<&FlowSummary>) -> bool {
    summary
        .filter(|summary| {
            summary.flow_info.status() == FlowStatus::Active && summary.needs_port_forwarding
        })
        .is_some()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NatRequirement {
    Static,
    Masquerade,
    PortForwarding,
}

impl NatRequirement {
    fn from_expose(expose: &ValidatedExpose) -> Option<Self> {
        match expose.nat_config()? {
            VpcExposeNatConfig::Masquerade(_) => Some(Self::Masquerade),
            VpcExposeNatConfig::Static(_) => Some(Self::Static),
            VpcExposeNatConfig::PortForwarding(_) => Some(Self::PortForwarding),
        }
    }
}

pub(crate) type NatMode = Option<NatRequirement>;
