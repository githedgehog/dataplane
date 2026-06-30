// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![doc = include_str!("../README.md")]

use concurrency::sync::Arc;
use config::external::overlay::vpcpeering::{ValidatedExpose, VpcExposeNatConfig};
use net::FlowKey;
use net::buffer::PacketBufferMut;
use net::flows::{FlowInfo, FlowStatus};
use net::headers::{TryIp, TryTransport};
use net::packet::{DoneReason, Packet, PacketMeta, VpcDiscriminant};
use pipeline::{NetworkFunction, PipelineData};
use std::num::NonZero;
use tracing::debug;

mod context;
#[cfg(test)]
mod test_utils;
#[cfg(test)]
mod tests;

pub use context::{
    FlowFilterContext, FlowFilterContextReader, FlowFilterContextReaderFactory,
    FlowFilterContextWriter,
};
use context::{LookupInput, Route};

pub struct FlowFilter {
    name: String,
    tables: FlowFilterContextReader,
    pipeline_data: Arc<PipelineData>,
}

/// Outcome of phase A (`classify`) for one packet.
enum Classification {
    /// Handled in place via active flow state; no table lookup needed.
    Bypassed,
    /// Drop the packet with this reason (no IP header / no source VPC).
    Drop(DoneReason),
    /// Needs a table lookup; carries the query and any attached flow summary (for phase C).
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
                Classification::Bypassed => {}
                Classification::Drop(reason) => packet.done(reason),
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

        let mut routes: Vec<Option<Route>> = vec![None; inputs.len()];
        {
            let tables = self.tables.load();
            tables.lookup_route_batch(&inputs, &mut routes);
        }

        for (item, route) in work.iter().zip(routes) {
            self.apply_route(
                &mut burst[item.idx],
                route,
                item.flow_summary.as_ref(),
                genid,
            );
        }
    }

    /// Phase A: decide what a single overlay packet needs. Tags bypass packets in place; returns
    /// the [`LookupInput`] (plus any attached flow summary, which phase C needs) otherwise.
    fn classify<Buf: PacketBufferMut>(
        &self,
        packet: &mut Packet<Buf>,
        genid: i64,
    ) -> Classification {
        let nfi = &self.name;
        let attached_flow = FlowSummary::from_meta(packet.meta());
        if let Some(flow_summary) = attached_flow.as_ref() {
            // Bypass flow-filter if packet has up-to-date active flow-info
            if let Some(dst_vpcd) = self.dst_vpcd_from_valid_flow(flow_summary, genid) {
                Self::tag_for_bypass(packet.meta_mut(), dst_vpcd, flow_summary);
                return Classification::Bypassed;
            }
        }

        let Some(net) = packet.try_ip() else {
            debug!("{nfi}: No IP headers found, dropping packet");
            return Classification::Drop(DoneReason::NotIp);
        };
        let Some(src_vpcd) = packet.meta().src_vpcd else {
            debug!("{nfi}: Missing source VPC discriminant, dropping packet");
            return Classification::Drop(DoneReason::Unroutable);
        };

        let input = LookupInput {
            src_vpcd,
            src_ip: net.src_addr(),
            dst_ip: net.dst_addr(),
            proto: net.next_header(),
            ports: packet.try_transport().and_then(|t| {
                t.src_port()
                    .map(NonZero::get)
                    .zip(t.dst_port().map(NonZero::get))
            }),
        };
        Classification::Lookup {
            input,
            flow_summary: attached_flow,
        }
    }

    /// Phase C: apply a resolved route (or drop on a miss) to a single packet.
    fn apply_route<Buf: PacketBufferMut>(
        &self,
        packet: &mut Packet<Buf>,
        route: Option<Route>,
        flow_summary: Option<&FlowSummary>,
        genid: i64,
    ) {
        let nfi = &self.name;
        let Some((dst_vpcd, dst_nat_mode, src_nat_mode)) = route else {
            debug!("{nfi}: Could not determine destination VPC, dropping packet");
            packet.invalidate_flows();
            packet.done(DoneReason::Filtered);
            return;
        };
        debug!(
            "{nfi}: Packet matches peering configuration, found VPC {dst_vpcd} and NAT modes {src_nat_mode:?} (src), {dst_nat_mode:?} (dst)"
        );
        packet.meta_mut().dst_vpcd = Some(dst_vpcd);
        Self::set_nat_requirements(packet.meta_mut(), src_nat_mode, dst_nat_mode);

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
        if self.should_invalidate_flow(packet.meta(), dst_vpcd, genid, flow_summary) {
            packet.invalidate_flows();
        }
    }

    fn tag_for_bypass(
        meta: &mut PacketMeta,
        dst_vpcd: VpcDiscriminant,
        flow_summary: &FlowSummary,
    ) {
        meta.dst_vpcd = Some(dst_vpcd);
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
        genid: i64,
        flow_summary: Option<&FlowSummary>,
    ) -> bool {
        let Some(flow_summary) = flow_summary else {
            return false;
        };
        if flow_summary.genid == genid {
            return false;
        }
        let (nfi, flowkey) = (&self.name, flow_summary.flow_info.flowkey());
        if flow_summary.dst_vpcd != Some(new_dst_vpcd) {
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

    fn dst_vpcd_from_valid_flow(
        &self,
        flow_summary: &FlowSummary,
        genid: i64,
    ) -> Option<VpcDiscriminant> {
        let nfi = &self.name;
        if flow_summary.flow_info.status() != FlowStatus::Active {
            debug!("{nfi}: Packet has inactive flow information");
            return None;
        }
        let flow_genid = flow_summary.flow_info.genid();
        if flow_genid < genid {
            debug!(
                "{nfi}: Packet has outdated flow information from a prior configuration ({flow_genid} < {genid})"
            );
            return None;
        }

        let Some(dst_vpcd) = flow_summary.dst_vpcd else {
            debug!(
                "{nfi}: Flow information does not specify destination VPC. This is a bug. Ignoring it..."
            );
            flow_summary.flow_info.invalidate_pair();
            return None;
        };

        // The flow has the same generation id as the current config. Small transient period aside,
        // this means that the flow is up-to-date and we can bypass the filter
        debug!("{nfi}: Packet can bypass flow filter thanks to flow information");
        Some(dst_vpcd)
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
    genid: i64,
    dst_vpcd: Option<VpcDiscriminant>,
    needs_masquerade: bool,
    needs_port_forwarding: bool,
    flow_info: Arc<FlowInfo>,
}

impl FlowSummary {
    fn from_meta(meta: &PacketMeta) -> Option<Self> {
        let Some(flow_info) = &meta.flow_info else {
            return None;
        };
        let locked_info = flow_info.locked.read();
        Some(Self {
            genid: flow_info.genid(),
            dst_vpcd: locked_info.dst_vpcd,
            needs_masquerade: locked_info.nat_state.is_some(),
            needs_port_forwarding: locked_info.port_fw_state.is_some(),
            flow_info: flow_info.clone(),
        })
    }
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
