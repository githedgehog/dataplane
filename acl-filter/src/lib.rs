// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use concurrency::sync::Arc;
use config::external::overlay::acl::{AclAction, AclScope};
use net::buffer::PacketBufferMut;
use net::flows::FlowInfo;
use net::flows::FlowStatus;
use net::headers::{TryIp, TryTransport};
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

        if self.lookup(&summary, valid_flow) == AclAction::Deny {
            debug!("{nfi}: Packet rejected by ACLs, dropping packet");
            packet.invalidate_flows();
            packet.done(DoneReason::AclDropped);
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

    fn lookup(&self, summary: &PacketSummary, flow_info: Option<&Arc<FlowInfo>>) -> AclAction {
        let guard = self.tablesr.load();
        let tables = &guard.acls;

        // Look up for an ACL directly matching the packet
        let lookup_result = tables.lookup(summary);
        if let Some(result) = lookup_result {
            let verdict = result.action;
            if result.log {
                info!("ACL filtering: {summary} -> {verdict:?}")
            }
            return verdict;
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
                return verdict;
            }
        }

        // Look for a fallback default action for the peering
        tables
            .find_default_action(summary.src_vni, summary.dst_vni)
            .unwrap_or(
                // No default action was found for this peering, this means no ACL list was
                // configured for the peering. Allow packet to go through.
                AclAction::Allow,
            )
    }
}

impl<Buf: PacketBufferMut> NetworkFunction<Buf> for AclFilter {
    fn process<'a, Input: Iterator<Item = Packet<Buf>> + 'a>(
        &'a mut self,
        input: Input,
    ) -> impl Iterator<Item = Packet<Buf>> + 'a {
        input.filter_map(|mut packet| {
            if !packet.is_done() && packet.meta().is_overlay() {
                self.process_packet(&mut packet);
            }
            packet.enforce()
        })
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
    pub(crate) ports: Option<(u16, u16)>,
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

        let Some(net) = packet.try_ip() else {
            debug!("No IP headers found, dropping packet");
            return Err(DoneReason::NotIp);
        };

        let src_ip = net.src_addr();
        let dst_ip = net.dst_addr();
        let proto = net.next_header();
        let ports = packet.try_transport().and_then(|t| {
            t.src_port()
                .map(NonZero::get)
                .zip(t.dst_port().map(NonZero::get))
        });

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
            src_ip: *flow_key.src_ip(),
            dst_ip: *flow_key.dst_ip(),
            proto: flow_key.proto(),
            ports: flow_key.ports().map(|(src, dst)| (src.get(), dst.get())),
        })
    }
}
