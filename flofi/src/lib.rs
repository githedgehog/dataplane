// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use concurrency::sync::Arc;
use config::external::overlay::vpcpeering::{ValidatedExpose, VpcExposeNatConfig};
use net::FlowKey;
use net::buffer::PacketBufferMut;
use net::flows::{FlowInfo, FlowStatus};
use net::headers::{TryIp, TryTransport};
use net::ip::NextHeader;
use net::packet::{DoneReason, Packet, PacketMeta, VpcDiscriminant};
use pipeline::{NetworkFunction, PipelineData};
use std::num::NonZero;
use tracing::debug;

mod context;

pub struct Flofi {
    name: String,
    tablesr: FlofiContextWrapper,
    pipeline_data: Arc<PipelineData>,
}

impl Flofi {
    pub fn new(name: String, tablesr: context::FlofiContext) -> Self {
        Self {
            name,
            tablesr: FlofiContextWrapper(tablesr),
            pipeline_data: Arc::new(PipelineData::default()),
        }
    }

    fn process_packet<Buf: PacketBufferMut>(&mut self, packet: &mut Packet<Buf>) {
        let nfi = &self.name;
        let genid = self.pipeline_data.genid();

        let attached_flow = FlowSummary::from_meta(packet.meta());
        if let Some(flow_summary) = attached_flow.as_ref() {
            // Bypass flow-filter if packet has up-to-date active flow-info
            if let Some(dst_vpcd) = self.dst_vpcd_from_valid_flow(flow_summary, genid) {
                Self::tag_for_bypass(packet.meta_mut(), dst_vpcd, flow_summary)
            }
        }

        let Some(net) = packet.try_ip() else {
            debug!("{nfi}: No IP headers found, dropping packet");
            packet.done(DoneReason::NotIp);
            return;
        };

        let Some(src_vpcd) = packet.meta().src_vpcd else {
            debug!("{nfi}: Missing source VPC discriminant, dropping packet");
            packet.done(DoneReason::Unroutable);
            return;
        };

        let src_ip = net.src_addr();
        let dst_ip = net.dst_addr();
        let proto = net.next_header();
        let ports = packet.try_transport().and_then(|t| {
            t.src_port()
                .map(NonZero::get)
                .zip(t.dst_port().map(NonZero::get))
        });

        let route = self
            .tablesr
            .lookup_route(src_vpcd, src_ip, dst_ip, proto, ports);

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

        if self
            .tablesr
            .acls_reject_packet(src_vpcd, dst_vpcd, src_ip, dst_ip, proto, ports)
        {
            debug!("{nfi}: Packet rejected by ACLs, dropping packet");
            packet.invalidate_flows();
            packet.done(DoneReason::Filtered);
            return;
        }

        // Port forwarding or masquerading used in combination with static NAT need to keep track of
        // the initial IP addresses for creating the right flow table entries, so we may have to
        // attach the flow key to packet's metadata.
        if let Some(flow_summary) = attached_flow.as_ref()
                && self.dst_vpcd_from_valid_flow(flow_summary, genid).is_some()
                    // Only attach the flow key when using {port forwarding, masquerading} + static NAT
                    && ((packet.meta().requires_port_forwarding() || packet.meta().requires_masquerade())
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
        if self.should_invalidate_flow(packet.meta(), dst_vpcd, genid, attached_flow.as_ref()) {
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

    fn set_nat_requirements(
        meta: &mut PacketMeta,
        src_nat: Option<NatRequirement>,
        dst_nat: Option<NatRequirement>,
    ) {
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
        result_dst_vpcd: VpcDiscriminant,
        genid: i64,
        flow_summary: Option<&FlowSummary>,
    ) -> bool {
        let nfi = &self.name;
        let Some(flow_summary) = flow_summary else {
            return false;
        };
        if flow_summary.genid == genid {
            return false;
        }
        let flowkey = flow_summary.flow_info.flowkey();
        if flow_summary.dst_vpcd != Some(result_dst_vpcd) {
            debug!("{nfi}: Flow-info is out-dated. New dst VPC is {result_dst_vpcd}");
            return true;
        }
        if !meta.requires_port_forwarding() && !meta.requires_masquerade() {
            debug!("{nfi}: Flow {flowkey} no longer requires state. Will invalidate...");
            return true;
        }
        if meta.requires_port_forwarding() && !flow_summary.needs_port_forwarding {
            debug!(
                "{nfi}: Flow {flowkey} requires port-forwarding, but flow-info lacks such a state"
            );
            return true;
        }
        if meta.requires_masquerade() && !flow_summary.needs_masquerade {
            debug!("{nfi}: Flow {flowkey} requires masquerading, but flow-info lacks such a state");
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

impl<Buf: PacketBufferMut> NetworkFunction<Buf> for Flofi {
    fn process<'a, Input: Iterator<Item = Packet<Buf>> + 'a>(
        &'a mut self,
        input: Input,
    ) -> impl Iterator<Item = Packet<Buf>> + 'a {
        input.filter_map(|mut packet| {
            if !packet.is_done() && packet.meta().is_overlay() && packet.meta().dst_vpcd.is_none() {
                self.process_packet(&mut packet);
            }
            packet.enforce()
        })
    }

    fn set_data(&mut self, data: Arc<PipelineData>) {
        self.pipeline_data = data;
    }
}

struct FlofiContextWrapper(context::FlofiContext);

impl FlofiContextWrapper {
    fn lookup_route(
        &self,
        src_vpcd: VpcDiscriminant,
        src_ip: std::net::IpAddr,
        dst_ip: std::net::IpAddr,
        proto: NextHeader,
        ports: Option<(u16, u16)>,
    ) -> Option<(
        VpcDiscriminant,
        Option<NatRequirement>,
        Option<NatRequirement>,
    )> {
        self.0.lookup_route(src_vpcd, src_ip, dst_ip, proto, ports)
    }

    fn acls_reject_packet(
        &self,
        _src_vpcd: VpcDiscriminant,
        _dst_vpcd: VpcDiscriminant,
        _src_ip: std::net::IpAddr,
        _dst_ip: std::net::IpAddr,
        _proto: NextHeader,
        _ports: Option<(u16, u16)>,
    ) -> bool {
        self.0.lookup_acls()
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
