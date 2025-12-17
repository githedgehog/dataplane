// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use net::buffer::PacketBufferMut;
use net::headers::{TryIp, TryTransport};
use net::packet::{DoneReason, Packet};
use pipeline::NetworkFunction;
use std::num::NonZero;
use tracing::{debug, error};

mod filter_rw;
mod ip_port_prefix_trie;
mod setup;
mod tables;

pub use filter_rw::{FlowFilterTableReader, FlowFilterTableReaderFactory, FlowFilterTableWriter};
pub use tables::FlowFilterTable;

use tracectl::trace_target;
trace_target!("flow-filter", LevelFilter::INFO, &["pipeline"]);

/// A structure to implement the flow filter pipeline stage.
pub struct FlowFilter {
    name: String,
    tablesr: FlowFilterTableReader,
}

impl FlowFilter {
    /// Create a new [`FlowFilter`] instance.
    pub fn new(name: &str, tablesr: FlowFilterTableReader) -> Self {
        Self {
            name: name.to_string(),
            tablesr,
        }
    }

    /// Process a packet.
    fn process_packet<Buf: PacketBufferMut>(
        &self,
        tablesr: &left_right::ReadGuard<'_, FlowFilterTable>,
        packet: &mut Packet<Buf>,
    ) {
        let nfi = &self.name;

        let Some(net) = packet.try_ip() else {
            debug!("{nfi}: Packet has no IP headers: dropping");
            packet.done(DoneReason::NotIp);
            return;
        };

        let (Some(src_vpcd), Some(dst_vpcd)) = (packet.meta.src_vpcd, packet.meta.dst_vpcd) else {
            debug!("{nfi}: Packet missing VPC discriminants: dropping");
            packet.done(DoneReason::Unroutable);
            return;
        };

        let src_ip = net.src_addr();
        let dst_ip = net.dst_addr();
        let ports = packet.try_transport().and_then(|t| {
            t.src_port()
                .map(NonZero::get)
                .zip(t.dst_port().map(NonZero::get))
        });

        if !tablesr.contains(src_vpcd, &src_ip, &dst_ip, ports) {
            debug!(
                "{nfi}: Flow not allowed, dropping packet: src_vpcd={src_vpcd}, dst_vpcd={dst_vpcd}, src={src_ip}:{}, dst={dst_ip}:{}",
                ports.map_or(String::new(), |p| format!("{}", p.0)),
                ports.map_or(String::new(), |p| format!("{}", p.1)),
            );
            packet.done(DoneReason::Filtered);
            return;
        }

        debug!(
            "{nfi}: Flow allowed: src_vpcd={src_vpcd}, src={src_ip}:{}, dst={dst_ip}:{}",
            ports.map_or(String::new(), |p| format!("{}", p.0)),
            ports.map_or(String::new(), |p| format!("{}", p.1)),
        );
    }
}

impl<Buf: PacketBufferMut> NetworkFunction<Buf> for FlowFilter {
    fn process<'a, Input: Iterator<Item = Packet<Buf>> + 'a>(
        &'a mut self,
        input: Input,
    ) -> impl Iterator<Item = Packet<Buf>> + 'a {
        input.filter_map(|mut packet| {
            if let Some(tablesr) = &self.tablesr.enter() {
                if !packet.is_done() {
                    self.process_packet(tablesr, &mut packet);
                }
            } else {
                error!("{}: failed to read flow filter table", self.name);
                packet.done(DoneReason::InternalFailure);
            }
            packet.enforce()
        })
    }
}
