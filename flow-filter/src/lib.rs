// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Flow-filter pipeline stage
//!
//! [`FlowFilter`] is a pipeline stage serving two purposes:
//!
//! - It retrieves the destination VPC discriminant for the packet, when possible, and attaches it
//!   to packet metadata.
//!
//! - It validates that the packet is associated with an existing peering connection, as defined in
//!   the user-provided configuration. Packets that do not have a source IP, port and destination
//!   IP, port corresponding to existing, valid connections between the prefixes in exposed lists of
//!   peerings, get dropped.

use net::buffer::PacketBufferMut;
use net::headers::{TryIp, TryTransport};
use net::packet::{DoneReason, Packet};
use pipeline::NetworkFunction;
use std::net::IpAddr;
use std::num::NonZero;
use tracing::{debug, error};

mod filter_rw;
mod setup;
mod tables;

pub use filter_rw::{FlowFilterTableReader, FlowFilterTableReaderFactory, FlowFilterTableWriter};
pub use tables::FlowFilterTable;

use tracectl::trace_target;

use crate::tables::VpcdLookupResult;
trace_target!("flow-filter", LevelFilter::INFO, &["pipeline"]);

/// A structure to implement the flow-filter pipeline stage.
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
            debug!("{nfi}: No IP headers found, dropping packet");
            packet.done(DoneReason::NotIp);
            return;
        };

        let Some(src_vpcd) = packet.meta.src_vpcd else {
            debug!("{nfi}: Missing source VPC discriminant, dropping packet");
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
        let log_str = format_packet_addrs_ports(&src_ip, &dst_ip, ports);

        let Some(dst_vpcd_lookup_res) = tablesr.lookup(src_vpcd, &src_ip, &dst_ip, ports) else {
            debug!("{nfi}: Flow not allowed, dropping packet: {log_str}");
            packet.done(DoneReason::Filtered);
            return;
        };

        match dst_vpcd_lookup_res {
            VpcdLookupResult::Single(dst_vpcd) => {
                debug!("{nfi}: Set packet dst_vpcd to {dst_vpcd}: {log_str}");
                packet.meta.dst_vpcd = Some(dst_vpcd);
            }
            VpcdLookupResult::MultipleMatches => {
                debug!(
                    "{nfi}: Ambiguous dst_vpcd for {dst_ip} in src_vpcd {src_vpcd}: falling back to flow table lookup to see if a session exists"
                );
            }
        }

        debug!("{nfi}: Flow allowed: {log_str}");
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

fn format_packet_addrs_ports(
    src_addr: &IpAddr,
    dst_addr: &IpAddr,
    ports: Option<(u16, u16)>,
) -> String {
    format!(
        "src={src_addr}{}, dst={dst_addr}{}",
        ports.map_or(String::new(), |p| format!(":{}", p.0)),
        ports.map_or(String::new(), |p| format!(":{}", p.1))
    )
}
