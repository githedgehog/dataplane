// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![doc = include_str!("../README.md")]

use concurrency::sync::Arc;
use config::external::overlay::vpcpeering::{ValidatedExpose, VpcExposeNatConfig};
use dag::generation::Join;
use dag::{Burst, Drops, Edit, Emit, Idx, Lacks, Sel, Set, Write, kind};
use net::FlowKey;
use net::buffer::PacketBufferMut;
use net::flows::{FlowInfo, FlowInfoFlags, FlowStatus};
use net::headers::{TryHeaders, TryIp, UpperLayerProto};
use net::ip::NextHeader;
use net::packet::{DoneReason, Packet, PacketMeta, VpcDiscriminant};
use pipeline::{NetworkFunction, PipelineData};
use tracectl::trace_target;
use tracing::debug;

trace_target!("flow-filter", LevelFilter::INFO, &["pipeline"]);

mod context;
#[cfg(test)]
mod tests;

pub use context::{
    Destination, FlowFilterContext, FlowFilterContextReader, FlowFilterContextReaderFactory,
    FlowFilterContextWriter,
};
use context::{LookupInput, LookupResult, SourceGate};

pub struct FlowFilter {
    name: String,
    tables: FlowFilterContextReader,
    pipeline_data: Arc<PipelineData>,
}

/// Outcome of phase A (`classify`) for one packet.
enum Classification {
    /// Handled in place via active flow state, which names the destination; no table lookup
    /// needed.
    Bypassed(VpcDiscriminant),
    /// Drop the packet for this reason.
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
    /// Where this stage reads its tables: the legacy path loads them itself, typed callers pass them.
    #[must_use]
    pub fn tables_reader(&self) -> &FlowFilterContextReader {
        &self.tables
    }

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
    fn route_burst<Buf: PacketBufferMut>(&mut self, burst: &mut [Packet<Buf>]) {
        let genid = self.pipeline_data.genid();

        let mut inputs: Vec<LookupInput> = Vec::new();
        let mut work: Vec<WorkItem> = Vec::new();
        for (idx, packet) in burst.iter_mut().enumerate() {
            if packet.is_done() || !packet.meta().is_overlay() || packet.meta().dst_vpcd.is_some() {
                continue;
            }
            let src_vpcd = packet.meta().src_vpcd;
            match self.classify(packet, src_vpcd, genid) {
                Classification::Bypassed(dst_vpcd) => packet.meta_mut().dst_vpcd = Some(dst_vpcd),
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

        let mut results: Vec<LookupResult> = vec![LookupResult::DestinationMiss; inputs.len()];
        let tables = self.tables.load();
        tables.lookup_batch(&inputs, &mut results);

        for ((item, result), input) in work.iter().zip(results).zip(&inputs) {
            let track = match result {
                LookupResult::Route((dst_vpcd, _, _)) => {
                    tables.requires_flow_tracking(input.src_vpcd, dst_vpcd)
                }
                LookupResult::SourceMiss(_) | LookupResult::DestinationMiss => false,
            };
            let packet = &mut burst[item.idx];
            match self.apply_route(packet, result, track, item.flow_summary.as_ref(), genid) {
                Ok(dst_vpcd) => packet.meta_mut().dst_vpcd = Some(dst_vpcd),
                Err(reason) => packet.done(reason),
            }
        }
    }

    /// Phase A: decide what a single overlay packet needs. Tags bypass packets in place; returns
    /// the [`LookupInput`] (plus any attached flow summary, which phase C needs) otherwise.
    fn classify<Buf: PacketBufferMut>(
        &self,
        packet: &mut Packet<Buf>,
        src_vpcd: Option<VpcDiscriminant>,
        genid: i64,
    ) -> Classification {
        let nfi = &self.name;
        let (mut revalidation_dst_vpcd, mut revalidation_gate) = (None, SourceGate::Ungated);
        let attached_flow = FlowSummary::from_meta(packet.meta());
        if let Some(flow_summary) = attached_flow.as_ref() {
            // Bypass flow-filter if packet has up-to-date active flow-info
            if let Some(dst_vpcd) = self.dst_vpcd_from_valid_flow(flow_summary, genid) {
                Self::tag_for_bypass(packet.meta_mut(), flow_summary);
                return Classification::Bypassed(dst_vpcd);
            }
            (revalidation_dst_vpcd, revalidation_gate) =
                self.flow_revalidation_data(flow_summary, genid);
        }

        let Some((_eth, net, transport)) = packet
            .headers()
            .pat()
            .opt_eth()
            .net()
            .opt_transport()
            .done()
        else {
            if packet.try_ip().is_none() {
                debug!("{nfi}: No IP headers found, dropping packet");
                return Classification::Drop(DoneReason::NotIp);
            }
            debug!("{nfi}: Header chain carries a layer this stage cannot account for");
            return Classification::Drop(DoneReason::Unhandled);
        };
        let Some(src_vpcd) = src_vpcd else {
            debug!("{nfi}: Missing source VPC discriminant, dropping packet");
            return Classification::Drop(DoneReason::Unroutable);
        };

        let upper = packet.upper_layer_proto();
        let proto = match upper {
            UpperLayerProto::Carried(proto) => proto,
            // Allow unrestricted exposes to match without inferring a transport.
            UpperLayerProto::NonFirstFragment => NextHeader::FRAGMENT,
            UpperLayerProto::Indeterminate => {
                debug!("{nfi}: Could not determine the upper-layer protocol, dropping packet");
                return Classification::Drop(DoneReason::Malformed);
            }
        };

        let input = LookupInput {
            src_vpcd,
            dst_vpcd: revalidation_dst_vpcd,
            src_ip: net.src_addr(),
            dst_ip: net.dst_addr(),
            proto,
            // The parser may have read ports from fragment payload.
            ports: match upper {
                UpperLayerProto::NonFirstFragment => None,
                _ => transport.and_then(|t| t.src_port().zip(t.dst_port())),
            },
            gate: revalidation_gate,
        };
        Classification::Lookup {
            input,
            flow_summary: attached_flow,
        }
    }

    /// Phase C: apply a resolved route to a single packet, and return its destination VPC (the
    /// caller records it); or the reason to drop it on a miss.
    fn apply_route<Buf: PacketBufferMut>(
        &self,
        packet: &mut Packet<Buf>,
        result: LookupResult,
        track: bool,
        flow_summary: Option<&FlowSummary>,
        genid: i64,
    ) -> Result<VpcDiscriminant, DoneReason> {
        let nfi = &self.name;
        let (dst_vpcd, dst_nat_mode, src_nat_mode) = match result {
            LookupResult::Route(route) => route,
            LookupResult::SourceMiss(dst_vpcd) => {
                debug!("{nfi}: Source not allowed towards {dst_vpcd}, dropping packet");
                packet.invalidate_flows();
                return Err(DoneReason::Filtered);
            }
            LookupResult::DestinationMiss => {
                debug!("{nfi}: Could not determine destination VPC, dropping packet");
                packet.invalidate_flows();
                return Err(DoneReason::Filtered);
            }
        };
        debug!(
            "{nfi}: Packet matches peering configuration, found VPC {dst_vpcd} and NAT modes {src_nat_mode:?} (src), {dst_nat_mode:?} (dst)"
        );
        Self::set_nat_requirements(packet.meta_mut(), src_nat_mode, dst_nat_mode);
        if !packet.meta().requires_masquerade() && !packet.meta().requires_port_forwarding() {
            packet.meta_mut().set_forced_flow_tracking(track);
        }

        Self::keep_flow_key(packet);

        // The packet is allowed. However, it may refer to an outdated flow and a new flow may be
        // needed. This pipeline stage cannot always tell whether a flow is valid or not, as it
        // lacks the NAT context and state to do so. Therefore, it should not upgrade flow to newer
        // gen ids. However, it can (and must) invalidate flows in some cases, because no other
        // network function will do it otherwise.
        if self.should_invalidate_flow(packet.meta(), dst_vpcd, genid, flow_summary) {
            packet.invalidate_flows();
        }
        Ok(dst_vpcd)
    }

    /// Port forwarding or masquerading used in combination with static NAT need to keep track of
    /// the initial IP addresses for creating the right flow table entries, so we may have to
    /// attach the flow key to packet's metadata.
    ///
    /// Pure, from the bytes and the NAT requirements: a packet trapped past the flow filter gets
    /// it back by replaying this (`notes/match-action-dag/TRAP-RESUME.md` Q6).
    pub fn keep_flow_key<Buf: PacketBufferMut>(packet: &mut Packet<Buf>) {
        if ((packet.meta().requires_port_forwarding() || packet.meta().requires_masquerade())
            && packet.meta().requires_static_nat())
            && let Ok(flow_key) = FlowKey::try_from(&*packet)
        {
            packet.meta_mut().flow_key = Some(Box::new(flow_key));
        }
    }

    fn tag_for_bypass(meta: &mut PacketMeta, flow_summary: &FlowSummary) {
        if flow_summary.needs_masquerade {
            meta.set_masquerade(true);
        }
        if flow_summary.needs_port_forwarding {
            meta.set_port_forwarding(true);
        }
        if flow_summary.needs_tracking {
            meta.set_forced_flow_tracking(true);
        }
        if flow_summary.flags.requires_static_nat_src() {
            meta.set_static_nat_src(true);
        }
        if flow_summary.flags.requires_static_nat_dst() {
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
        let nfi = &self.name;
        let flowkey = meta.flow_info.as_deref().map(FlowInfo::flowkey);
        let flowkey = Displayed(flowkey);
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
        // The reverse key of a flow depends on static NAT, whether or not the flow also uses
        // masquerade or port forwarding, and these NFs do not check it.
        let flags = flow_summary.flags;
        if meta.requires_static_nat_src() != flags.requires_static_nat_src()
            || meta.requires_static_nat_dst() != flags.requires_static_nat_dst()
        {
            debug!("{nfi}: Outdated flow {flowkey} (static NAT requirement) will be invalidated.");
            return true;
        }
        // Without masquerade or port forwarding, we only keep flows that are still tracked.
        if !meta.requires_port_forwarding()
            && !meta.requires_masquerade()
            && (!meta.has_forced_flow_tracking() || !flow_summary.needs_tracking)
        {
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

    fn flow_revalidation_data(
        &self,
        flow_summary: &FlowSummary,
        genid: i64,
    ) -> (Option<VpcDiscriminant>, SourceGate) {
        // The only case when we need re-validation is when we have an active flow with an outdated
        // genid. If this is not the case, return None.
        if flow_summary.status != FlowStatus::Active || flow_summary.genid >= genid {
            return (None, SourceGate::Ungated);
        }
        // We only need to pass this information when re-validating a flow in the return direction.
        // For the forward direction, we use the regular entries in the flow-filter tables, just as
        // if we were checking for a new flow.
        if flow_summary.is_initiator() {
            return (None, SourceGate::Ungated);
        }
        if flow_summary.needs_masquerade {
            // We need return traffic revalidation and the flow is masqueraded. Pass the destination
            // VPC id from the flow to look up for the related entry in the "remote"-side table.
            (Some(flow_summary.dst_vpcd), SourceGate::Ungated)
        } else if flow_summary.needs_port_forwarding {
            // We need return traffic revalidation and the flow is with port-forwarding. Turn on the
            // gate to enable looking up for entries for related traffic in the "local"-side table.
            (None, SourceGate::PortFwdReply)
        } else {
            (None, SourceGate::Ungated)
        }
    }

    fn dst_vpcd_from_valid_flow(
        &self,
        flow_summary: &FlowSummary,
        genid: i64,
    ) -> Option<VpcDiscriminant> {
        let nfi = &self.name;
        if flow_summary.status != FlowStatus::Active {
            debug!("{nfi}: Packet has inactive flow information");
            return None;
        }
        let flow_genid = flow_summary.genid;
        if flow_genid < genid {
            debug!(
                "{nfi}: Packet has outdated flow information from a prior configuration ({flow_genid} < {genid})"
            );
            return None;
        }

        // Current and newer-generation flows bypass the filter. Workers may observe a new config
        // generation after flows have already been stamped with it.
        debug!("{nfi}: Packet can bypass flow filter thanks to flow information");
        Some(flow_summary.dst_vpcd)
    }
}

impl FlowFilter {
    /// The typed stage: route a selection whose destination VPC is proven unset, batching lookups
    /// as the legacy stage does. The source VPC is read with a presence test, not required: a
    /// packet without one is dropped as `Unroutable`, but only after the header checks, as the
    /// legacy stage orders them.
    pub fn process_sel<'b, Buf, S>(
        &mut self,
        burst: &mut Burst<'b, Buf>,
        input: Sel<'b, S>,
        tables: &'b FlowFilterContext,
    ) -> Routed<'b, S>
    where
        Buf: PacketBufferMut,
        S: Lacks<kind::DstVpc> + Edit<kind::DstVpc>,
    {
        let genid = self.pipeline_data.genid();
        let mut routed = Emit::<S, Write<kind::DstVpc>>::new();
        let mut dropped = Drops::none();
        let mut work: Vec<(Idx<'b, S>, Option<FlowSummary>)> = Vec::new();
        let mut inputs: Vec<LookupInput> = Vec::new();
        for i in input {
            let src = burst.meta(&i).try_get::<kind::SrcVpc>().copied();
            match self.classify(burst.packet_mut(&i), src, genid) {
                Classification::Bypassed(dst) => routed.push(burst, i, dst),
                Classification::Drop(reason) => burst.drop(&mut dropped, i, reason),
                Classification::Lookup {
                    input,
                    flow_summary,
                } => {
                    work.push((i, flow_summary));
                    inputs.push(input);
                }
            }
        }
        if !inputs.is_empty() {
            let mut results: Vec<LookupResult> = vec![LookupResult::DestinationMiss; inputs.len()];
            tables.lookup_batch(&inputs, &mut results);
            for (((i, flow_summary), result), input) in work.into_iter().zip(results).zip(&inputs) {
                let track = match result {
                    LookupResult::Route((dst_vpcd, _, _)) => {
                        tables.requires_flow_tracking(input.src_vpcd, dst_vpcd)
                    }
                    LookupResult::SourceMiss(_) | LookupResult::DestinationMiss => false,
                };
                let packet = burst.packet_mut(&i);
                match self.apply_route(packet, result, track, flow_summary.as_ref(), genid) {
                    Ok(dst) => routed.push(burst, i, dst),
                    Err(reason) => burst.drop(&mut dropped, i, reason),
                }
            }
        }
        Routed {
            routed: routed.finish(),
            dropped,
        }
    }
}

/// What the typed flow filter does with its input.
#[derive(Debug)]
pub struct Routed<'b, S: Edit<kind::DstVpc>> {
    /// Allowed by a peering, with their destination VPC set.
    pub routed: Sel<'b, Set<S, kind::DstVpc>>,
    /// Filtered, or not routable.
    pub dropped: Drops<'b>,
}

impl<S: Edit<kind::DstVpc>> Join for Routed<'_, S> {
    fn join(self, other: Self) -> Self {
        Routed {
            routed: self.routed.union(other.routed),
            dropped: self.dropped.join(other.dropped),
        }
    }
}

impl<Buf: PacketBufferMut> NetworkFunction<Buf> for FlowFilter {
    fn process_burst(&mut self, burst: &mut Vec<Packet<Buf>>) {
        self.route_burst(burst);
    }

    fn set_data(&mut self, data: Arc<PipelineData>) {
        self.pipeline_data = data;
    }
}

/// What the filter needs to know about the flow a packet refers to: copied out, so that it does not
/// hold the flow (an atomic increment and decrement on the flow's line, per packet).
#[derive(Debug, Clone)]
struct FlowSummary {
    genid: i64,
    status: FlowStatus,
    flags: FlowInfoFlags,
    dst_vpcd: VpcDiscriminant,
    needs_masquerade: bool,
    needs_port_forwarding: bool,
    needs_tracking: bool,
}

impl FlowSummary {
    fn from_meta(meta: &PacketMeta) -> Option<Self> {
        let flow_info = meta.flow_info.as_ref()?;
        let locked_info = flow_info.locked.read();
        let Some(dst_vpcd) = locked_info.dst_vpcd else {
            debug!("Flow info lacks destination VPC. This is a bug. Invalidating flow..");
            flow_info.invalidate_pair();
            return None;
        };
        Some(Self {
            genid: flow_info.genid(),
            status: flow_info.status(),
            flags: flow_info.get_flags(),
            dst_vpcd,
            needs_masquerade: locked_info.nat.is_masquerade(),
            needs_port_forwarding: locked_info.nat.is_port_forward(),
            needs_tracking: locked_info.nat.is_tracked(),
        })
    }

    fn is_initiator(&self) -> bool {
        self.flags.is_initiator()
    }
}

/// An optional flow key, for log messages.
struct Displayed<'a>(Option<&'a FlowKey>);

impl std::fmt::Display for Displayed<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            Some(key) => write!(f, "{key}"),
            None => f.write_str("(unknown)"),
        }
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
