// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use concurrency::sync::Arc;
use config::external::overlay::acl::{AclAction, AclScope};
use net::buffer::PacketBufferMut;
use net::flows::FlowInfo;
use net::flows::FlowStatus;
use net::headers::{TryHeaders, TryIp, UpperLayerProto};
use net::ip::NextHeader;
use net::packet::{DoneReason, Packet, PacketMeta, VpcDiscriminant};
use net::vxlan::Vni;
use pipeline::{NetworkFunction, PipelineData};
use std::num::NonZero;
use tracing::{debug, info};

use tracectl::trace_target;
trace_target!("acl-filter", LevelFilter::INFO, &["pipeline"]);

mod access;
mod context;
mod display;

#[cfg(test)]
mod fuzz;
#[cfg(test)]
mod fuzz_gen;
#[cfg(test)]
mod nf_fuzz;
#[cfg(test)]
mod tests;

pub use access::{
    AclFilterContext, AclFilterContextReader, AclFilterContextReaderFactory, AclFilterContextWriter,
};

pub struct AclFilter {
    name: String,
    tablesr: AclFilterContextReader,
    pipeline_data: Arc<PipelineData>,
}

impl AclFilter {
    #[must_use]
    pub fn new(name: &str, tablesr: AclFilterContextReader) -> Self {
        Self {
            name: name.to_string(),
            tablesr,
            pipeline_data: Arc::new(PipelineData::default()),
        }
    }

    fn process_packet<Buf: PacketBufferMut>(&mut self, packet: &mut Packet<Buf>) {
        let nfi = &self.name;
        let genid = self.pipeline_data.genid();

        let summary = match PacketSummary::try_from(&*packet) {
            Ok(summary) => summary,
            Err(reason) => {
                packet.done(reason);
                return;
            }
        };
        let valid_flow = self.packet_has_valid_flow(packet.meta(), genid);
        let has_valid_flow = valid_flow.is_some();

        let (verdict, flow_scoped_allow) = self.lookup(&summary, valid_flow);
        if verdict == AclAction::Deny {
            debug!("{nfi}: Packet rejected by ACLs, dropping packet");
            packet.invalidate_flows();
            packet.done(DoneReason::AclDropped);
            return;
        }

        // The flow filter requests flow tracking for all packets of a peering with flow-scoped
        // rules. Only flows opened by such a rule need it: we never use the others to let replies
        // through, so they would only take room in the flow table. Packets on a valid flow keep
        // the request, so that tracking keeps updating the flow.
        if !has_valid_flow && !flow_scoped_allow && packet.meta().has_forced_flow_tracking() {
            debug!("{nfi}: Packet not allowed by a flow-scoped rule, no flow tracking needed");
            packet.meta_mut().set_forced_flow_tracking(false);
        }
    }

    fn packet_has_valid_flow<'a>(
        &self,
        meta: &'a PacketMeta,
        genid: i64,
    ) -> Option<&'a Arc<FlowInfo>> {
        let nfi = &self.name;
        let Some(flow) = &meta.flow_info else {
            debug!("{nfi}: Packet has no flow information");
            return None;
        };

        if flow.status() != FlowStatus::Active {
            debug!("{nfi}: Packet has inactive flow information");
            return None;
        }
        let flow_genid = flow.genid();
        if flow_genid < genid {
            debug!(
                "{nfi}: Packet has outdated flow information from a prior configuration ({flow_genid} < {genid})"
            );
            return None;
        }
        Some(flow)
    }

    // Return the verdict for the packet, and whether it comes from an Allow rule of scope "flow"
    // matching the packet itself.
    fn lookup(
        &self,
        summary: &PacketSummary,
        flow_info: Option<&Arc<FlowInfo>>,
    ) -> (AclAction, bool) {
        let guard = self.tablesr.load();
        let tables = &guard.acls;

        // Every peering with an ACL has a default action registered for both directions, and only
        // such a peering has rules. Without one, nothing can match either way: allow the packet
        // without the lookups, and without reaching the reverse flow (a cold cache line, and an
        // atomic on it, for every packet of every flow).
        let Some(default_action) = tables.find_default_action(summary.src_vni, summary.dst_vni)
        else {
            return (AclAction::Allow, false);
        };

        // Look up for an ACL directly matching the packet
        let lookup_result = tables.lookup(summary);
        if let Some(result) = lookup_result {
            let verdict = result.action;
            if result.log {
                info!("ACL filtering: {summary} -> {verdict:?}")
            }
            return (
                verdict,
                verdict == AclAction::Allow && result.scope == AclScope::Flow,
            );
        }

        // If we have flow information, we may be dealing with a reply for an authorized flow. But
        // we need to check whether the corresponding ACL rule has a 'flow' or 'packet' scope. To do
        // that, we need to reverse-NAT the packet and do another lookup, to find the rule and its
        // scope, if any.
        if let Some(flow) = flow_info
            && let Some(reverse_summary) = summary.reverse_summary(flow)
        {
            let reverse_lookup_result = tables.lookup(&reverse_summary);
            if let Some(result) = reverse_lookup_result
                && result.action == AclAction::Allow
                && result.scope == AclScope::Flow
            {
                let verdict = result.action;
                if result.log {
                    info!("ACL filtering: {summary} -> {verdict:?} (reply from allowed flow)")
                }
                return (verdict, false);
            }
        }

        // Fall back to the peering's default action
        (default_action, false)
    }
}

impl<Buf: PacketBufferMut> NetworkFunction<Buf> for AclFilter {
    fn process_burst(&mut self, burst: &mut Vec<Packet<Buf>>) {
        for packet in burst.iter_mut() {
            if !packet.is_done() && packet.meta().is_overlay() {
                self.process_packet(packet);
            }
        }
    }

    fn set_data(&mut self, data: Arc<PipelineData>) {
        self.pipeline_data = data;
    }
}

#[derive(Debug, Clone)]
pub(crate) struct PacketSummary {
    pub(crate) src_vni: Vni,
    pub(crate) dst_vni: Vni,
    pub(crate) src_ip: std::net::IpAddr,
    pub(crate) dst_ip: std::net::IpAddr,
    pub(crate) proto: NextHeader,
    pub(crate) ports: Option<(NonZero<u16>, NonZero<u16>)>,
}

impl<Buf: PacketBufferMut> TryFrom<&Packet<Buf>> for PacketSummary {
    type Error = DoneReason;

    fn try_from(packet: &Packet<Buf>) -> Result<Self, Self::Error> {
        let Some((src_vpcd, dst_vpcd)) = packet.meta().src_vpcd.zip(packet.meta().dst_vpcd) else {
            debug!("Missing source or destination VPC discriminant, dropping packet");
            return Err(DoneReason::Unroutable);
        };
        let VpcDiscriminant::VNI(src_vni) = src_vpcd;
        let VpcDiscriminant::VNI(dst_vni) = dst_vpcd;

        let Some((_eth, net, transport)) = packet
            .headers()
            .pat()
            .opt_eth()
            .net()
            .opt_transport()
            .done()
        else {
            if packet.try_ip().is_none() {
                debug!("No IP headers found, dropping packet");
                return Err(DoneReason::NotIp);
            }
            debug!("Header chain carries a layer this stage cannot account for, dropping packet");
            return Err(DoneReason::Unhandled);
        };

        let src_ip = net.src_addr();
        let dst_ip = net.dst_addr();
        let upper = packet.upper_layer_proto();
        let proto = match upper {
            UpperLayerProto::Carried(proto) => proto,
            // Match wildcard and protocol-44 rules, without inferring a transport.
            UpperLayerProto::NonFirstFragment => NextHeader::FRAGMENT,
            UpperLayerProto::Indeterminate => {
                debug!("Could not determine the upper-layer protocol, dropping packet");
                return Err(DoneReason::Malformed);
            }
        };
        let ports = match upper {
            // The parser may have read ports from fragment payload.
            UpperLayerProto::NonFirstFragment => None,
            _ => transport.and_then(|t| t.src_port().zip(t.dst_port())),
        };

        Ok(Self {
            src_vni,
            dst_vni,
            src_ip,
            dst_ip,
            proto,
            ports,
        })
    }
}

impl PacketSummary {
    fn reverse_summary(&self, flow_info: &Arc<FlowInfo>) -> Option<PacketSummary> {
        let related = flow_info.related.as_ref()?.upgrade()?;
        let flow_key = related.flowkey();
        Some(PacketSummary {
            src_vni: self.dst_vni,
            dst_vni: self.src_vni,
            src_ip: flow_key.src_ip(),
            dst_ip: flow_key.dst_ip(),
            proto: flow_key.proto(),
            ports: flow_key.ports(),
        })
    }
}
