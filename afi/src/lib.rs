// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use concurrency::sync::Arc;
use net::buffer::PacketBufferMut;
use net::headers::{TryIp, TryTransport};
use net::ip::NextHeader;
use net::packet::{DoneReason, Packet, VpcDiscriminant};
use pipeline::{NetworkFunction, PipelineData};
use std::num::NonZero;
use tracing::debug;

mod context;

pub struct AclFilter {
    name: String,
    tablesr: AclFilterContextWrapper,
    pipeline_data: Arc<PipelineData>,
}

impl AclFilter {
    pub fn new(name: String, tablesr: context::AclFilterContext) -> Self {
        Self {
            name,
            tablesr: AclFilterContextWrapper(tablesr),
            pipeline_data: Arc::new(PipelineData::default()),
        }
    }

    fn process_packet<Buf: PacketBufferMut>(&mut self, packet: &mut Packet<Buf>) {
        let nfi = &self.name;

        let summary = match PacketSummary::try_from(&*packet) {
            Ok(summary) => summary,
            Err(reason) => {
                packet.done(reason);
                return;
            }
        };

        if self.tablesr.acls_reject_packet(&summary) {
            debug!("{nfi}: Packet rejected by ACLs, dropping packet");
            packet.invalidate_flows();
            packet.done(DoneReason::Filtered);
        }
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

struct AclFilterContextWrapper(context::AclFilterContext);

impl AclFilterContextWrapper {
    fn acls_reject_packet(&self, summary: &PacketSummary) -> bool {
        self.0.lookup(summary)
    }
}

#[derive(Debug, Clone)]
pub(crate) struct PacketSummary {
    src_vpcd: VpcDiscriminant,
    dst_vpcd: VpcDiscriminant,
    src_ip: std::net::IpAddr,
    dst_ip: std::net::IpAddr,
    proto: NextHeader,
    ports: Option<(u16, u16)>,
    has_flow: bool,
}

impl<Buf: PacketBufferMut> TryFrom<&Packet<Buf>> for PacketSummary {
    type Error = DoneReason;

    fn try_from(packet: &Packet<Buf>) -> Result<Self, Self::Error> {
        let Some((src_vpcd, dst_vpcd)) = packet.meta().src_vpcd.zip(packet.meta().dst_vpcd) else {
            debug!("Missing source VPC discriminant, dropping packet");
            return Err(DoneReason::Unroutable);
        };

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

        let has_flow = packet.meta().flow_info.is_some();

        Ok(Self {
            src_vpcd,
            dst_vpcd,
            src_ip,
            dst_ip,
            proto,
            ports,
            has_flow,
        })
    }
}
