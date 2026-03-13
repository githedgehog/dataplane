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

use crate::tables::{NatRequirement, RemoteData, VpcdLookupResult};
use indenter::indented;
use lpm::prefix::L4Protocol;
use net::buffer::PacketBufferMut;
use net::flows::FlowStatus;
use net::flows::flow_info_item::ExtractRef;
use net::headers::{Transport, TryIp, TryTransport};
use net::packet::{DoneReason, Packet, VpcDiscriminant};
use pipeline::{NetworkFunction, PipelineData};
use std::collections::HashSet;
use std::fmt::{Display, Write};
use std::net::IpAddr;
use std::num::NonZero;
use std::sync::Arc;
use tracing::{debug, error};

mod filter_rw;
mod setup;
mod tables;
#[cfg(test)]
mod tests;

pub use filter_rw::{FlowFilterTableReader, FlowFilterTableReaderFactory, FlowFilterTableWriter};
pub use tables::FlowFilterTable;

use tracectl::trace_target;

trace_target!("flow-filter", LevelFilter::INFO, &["pipeline"]);

/// A structure to implement the flow-filter pipeline stage.
pub struct FlowFilter {
    name: String,
    tablesr: FlowFilterTableReader,
    pipeline_data: Arc<PipelineData>,
}

impl FlowFilter {
    /// Create a new [`FlowFilter`] instance.
    pub fn new(name: &str, tablesr: FlowFilterTableReader) -> Self {
        Self {
            name: name.to_string(),
            tablesr,
            pipeline_data: Arc::from(PipelineData::default()),
        }
    }

    /// Attempt to determine destination vpc from packet's flow-info
    fn check_packet_flow_info<Buf: PacketBufferMut>(
        &self,
        packet: &mut Packet<Buf>,
    ) -> Result<Option<VpcDiscriminant>, DoneReason> {
        let nfi = &self.name;

        let Some(flow_info) = &packet.meta().flow_info else {
            debug!("{nfi}: Packet does not contain any flow-info");
            return Ok(None);
        };

        let Ok(locked_info) = flow_info.locked.read() else {
            debug!("{nfi}: Warning! failed to lock flow-info for packet, dropping packet");
            return Err(DoneReason::InternalFailure);
        };

        let vpcd = locked_info
            .dst_vpcd
            .as_ref()
            .and_then(|d| d.extract_ref::<VpcDiscriminant>());

        let Some(dst_vpcd) = vpcd else {
            debug!("{nfi}: No VPC discriminant found, dropping packet");
            return Err(DoneReason::Unroutable);
        };

        let status = flow_info.status();
        if status != FlowStatus::Active {
            debug!(
                "{nfi}: Found flow-info with dst_vpcd {dst_vpcd} but status {status}, dropping packet"
            );
            return Err(DoneReason::Unroutable);
        }

        debug!("{nfi}: dst_vpcd discriminant is {dst_vpcd} (from active flow-info entry)");
        Ok(Some(*dst_vpcd))
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

        let Some(src_vpcd) = packet.meta().src_vpcd else {
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

        // For Display
        let tuple = FlowTuple::new(src_vpcd, src_ip, dst_ip, ports);

        let dst_vpcd = match tablesr.lookup(src_vpcd, &src_ip, &dst_ip, ports) {
            None => {
                debug!("{nfi}: No valid destination VPC found for flow {tuple}");
                None
            }
            Some(VpcdLookupResult::Single(dst_data)) => {
                set_nat_requirements(packet, &dst_data);
                Some(dst_data.vpcd)
            }
            Some(VpcdLookupResult::MultipleMatches(data_set)) => {
                debug!(
                    "{nfi}: Found multiple matches for destination VPC for flow {tuple}. Checking for a flow table entry..."
                );

                match self.check_packet_flow_info(packet) {
                    Ok(Some(dst_vpcd)) => {
                        if set_nat_requirements_from_flow_info(packet).is_ok() {
                            Some(dst_vpcd)
                        } else {
                            debug!("{nfi}: Failed to set NAT requirements from flow info");
                            None
                        }
                    }
                    Ok(None) => {
                        debug!(
                            "{nfi}: No flow table entry found for flow {tuple}, trying to figure out destination VPC anyway"
                        );
                        deal_with_multiple_matches(packet, &data_set, nfi, &tuple)
                    }
                    Err(reason) => {
                        debug!("Will drop packet. Reason: {reason}");
                        packet.done(reason);
                        return;
                    }
                }
            }
        };

        // At this point, we may have determined the destination VPC for a packet or not. If we haven't, we
        // should drop the packet. However, if it is an ICMP error packet, let the icmp-error handler deal with it.
        // Now, the icmp-error handler works for masquerading and port-forwarding, but not stateless NAT,
        // nor the absence of NAT, and here we don't know if the icmp error corresponds to traffic that
        // was masqueraded, port-forwarded, statically nated or neither of the previous. If the dst-vpcd
        // for an icmp error packet is known, the icmp handler will transparently let the static NAT NF deal with it.
        if packet.is_icmp_error() {
            debug!("Letting ICMP error handler process this packet. dst-vpcd is {dst_vpcd:?}");
            packet.meta_mut().dst_vpcd = dst_vpcd; // wether we discovered the vpcd or not
            return;
        }

        // Drop the packet since we don't know destination and it is not an icmp error
        let Some(dst_vpcd) = dst_vpcd else {
            debug!("Could not determine dst vpcd. Dropping packet");
            packet.done(DoneReason::Filtered);
            return;
        };

        debug!("{nfi}: Flow {tuple} is allowed, setting packet dst_vpcd to {dst_vpcd}");
        packet.meta_mut().dst_vpcd = Some(dst_vpcd);
    }
}

fn deal_with_multiple_matches<Buf: PacketBufferMut>(
    packet: &mut Packet<Buf>,
    data_set: &HashSet<RemoteData>,
    nfi: &str,
    tuple: &FlowTuple,
) -> Option<VpcDiscriminant> {
    // We should always have at least one matching RemoteData object applying to our packet.
    debug_assert!(
        !data_set.is_empty(),
        "{nfi}: No matching RemoteData objects left for flow {tuple}"
    );

    // Do all matches have the same destination VPC?
    let Some(first_vpcd) = data_set.iter().next().map(|d| d.vpcd) else {
        debug!("{nfi}: Missing destination VPC information for flow {tuple}, dropping packet");
        return None;
    };
    if data_set.iter().any(|d| d.vpcd != first_vpcd) {
        debug!(
            "{nfi}: Unable to decide what destination VPC to use for flow {tuple}, dropping packet"
        );
        return None;
    };

    // data_set may actually contain RemoteData objects that do not apply to our packet, because the
    // table lookup does not account for TCP vs. UDP, we only deal with the protocol when looking at
    // NAT requirements. Here we filter out RemoteData objects that do not apply to our packet.

    let packet_proto = get_l4_proto(packet);
    let data_set = data_set
        .iter()
        .filter(|d| d.applies_to(packet_proto))
        .collect::<HashSet<_>>();

    if data_set.is_empty() {
        debug!(
            "{nfi}: No NAT requirement found for flow {tuple} after filtering by protocol, dropping packet"
        );
        return None;
    }

    // Can we do something sensible from the NAT requirements? At the moment we allow prefix overlap
    // only when port forwarding is used in conjunction with stateful NAT, so if we reach this case
    // this is what we should have.

    // Note: if data_set.len() == 1 we can trivially figure out the destination VPC and NAT
    // requirement.
    if data_set.len() == 1 {
        let dst_data = data_set.iter().next().unwrap_or_else(|| unreachable!());
        set_nat_requirements(packet, dst_data);
        return Some(first_vpcd);
    }

    if data_set.len() > 2 {
        debug!("{nfi}: Unsupported NAT requirements for flow {tuple}");
        return None;
    }

    // If we have stateful NAT and port masquerading on the source side, given that we haven't found
    // a valid NAT entry, stateful NAT should take precedence so the packet can come out.
    if let Some(dst_data) = data_set
        .iter()
        .find(|d| d.src_nat_req == Some(NatRequirement::Stateful))
        && data_set.iter().any(|d| {
            let Some(NatRequirement::PortForwarding(requirement_proto)) = d.src_nat_req else {
                return false;
            };
            requirement_proto.intersection(&packet_proto).is_some()
        })
    {
        set_nat_requirements(packet, dst_data);
        return Some(first_vpcd);
    }
    // If we have stateful NAT and port masquerading on the destination side, given that we haven't
    // found a valid NAT entry, port forwarding should take precedence.
    if let Some(dst_data) = data_set.iter().find(|d| {
        let Some(NatRequirement::PortForwarding(req_proto)) = d.dst_nat_req else {
            return false;
        };
        req_proto.intersection(&packet_proto).is_some()
    }) && data_set
        .iter()
        .any(|d| d.dst_nat_req == Some(NatRequirement::Stateful))
    {
        set_nat_requirements(packet, dst_data);
        return Some(first_vpcd);
    }

    debug!("{nfi}: Unsupported NAT requirements for flow {tuple}");
    None
}

impl<Buf: PacketBufferMut> NetworkFunction<Buf> for FlowFilter {
    fn process<'a, Input: Iterator<Item = Packet<Buf>> + 'a>(
        &'a mut self,
        input: Input,
    ) -> impl Iterator<Item = Packet<Buf>> + 'a {
        input.filter_map(|mut packet| {
            if let Some(tablesr) = &self.tablesr.enter() {
                if !packet.is_done() && packet.meta().is_overlay() {
                    self.process_packet(tablesr, &mut packet);
                }
            } else {
                error!("{}: failed to read flow filter table", self.name);
                packet.done(DoneReason::InternalFailure);
            }
            packet.enforce()
        })
    }

    fn set_data(&mut self, data: Arc<PipelineData>) {
        self.pipeline_data = data;
    }
}

// Only used for Display
struct OptPort(Option<u16>);
impl std::fmt::Display for OptPort {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(port) = self.0 {
            write!(f, ":{port}")?;
        }
        Ok(())
    }
}

// Only used for Display
struct FlowTuple {
    src_vpcd: VpcDiscriminant,
    src_addr: IpAddr,
    dst_addr: IpAddr,
    src_port: OptPort,
    dst_port: OptPort,
}

impl FlowTuple {
    fn new(
        src_vpcd: VpcDiscriminant,
        src_addr: IpAddr,
        dst_addr: IpAddr,
        ports: Option<(u16, u16)>,
    ) -> Self {
        let ports = ports.unzip();
        Self {
            src_vpcd,
            src_addr,
            dst_addr,
            src_port: OptPort(ports.0),
            dst_port: OptPort(ports.1),
        }
    }
}

impl Display for FlowTuple {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "srcVpc={} src={}{} dst={}{}",
            self.src_vpcd, self.src_addr, self.src_port, self.dst_addr, self.dst_port
        )
    }
}

impl Display for FlowFilter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{}:", self.name)?;
        if let Some(table) = self.tablesr.enter() {
            write!(indented(f).with_str("  "), "{}", *table)
        } else {
            writeln!(f, "  [no table]")
        }
    }
}

fn set_nat_requirements<Buf: PacketBufferMut>(packet: &mut Packet<Buf>, data: &RemoteData) {
    if data.requires_stateful_nat() {
        packet.meta_mut().set_stateful_nat(true);
    }
    if data.requires_stateless_nat() {
        packet.meta_mut().set_stateless_nat(true);
    }
    if data.requires_port_forwarding(get_l4_proto(packet)) {
        packet.meta_mut().set_port_forwarding(true);
    }
}

fn set_nat_requirements_from_flow_info<Buf: PacketBufferMut>(
    packet: &mut Packet<Buf>,
) -> Result<(), ()> {
    let locked_info = packet
        .meta()
        .flow_info
        .as_ref()
        .ok_or(())?
        .locked
        .read()
        .map_err(|_| ())?;
    let needs_stateful_nat = locked_info.nat_state.is_some();
    let needs_port_forwarding = locked_info.port_fw_state.is_some();
    drop(locked_info);

    match (needs_stateful_nat, needs_port_forwarding) {
        (true, false) => {
            packet.meta_mut().set_stateful_nat(true);
            Ok(())
        }
        (false, true) => {
            packet.meta_mut().set_port_forwarding(true);
            Ok(())
        }
        _ => Err(()),
    }
}

pub(crate) fn get_l4_proto<Buf: PacketBufferMut>(packet: &Packet<Buf>) -> L4Protocol {
    match packet.try_transport() {
        Some(Transport::Tcp(_)) => L4Protocol::Tcp,
        Some(Transport::Udp(_)) => L4Protocol::Udp,
        _ => L4Protocol::Any,
    }
}
