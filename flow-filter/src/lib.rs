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
use lpm::prefix::L4Protocol;
use net::buffer::PacketBufferMut;
use net::headers::{Transport, TryIp, TryTransport};
use net::packet::{DoneReason, Packet, VpcDiscriminant};
use pipeline::{NetworkFunction, PipelineData};
use std::collections::HashSet;
use std::fmt::Display;
use std::net::IpAddr;
use std::num::NonZero;
use std::sync::Arc;
use tracing::{debug, error};

mod display;
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

    /// Invalidate the flow that a packet refers to if any
    fn invalidate_packet_flow<Buf: PacketBufferMut>(packet: &Packet<Buf>) {
        if let Some(flow_info) = packet.meta().flow_info.as_ref() {
            let flow_key = flow_info.flowkey().unwrap_or_else(|| unreachable!());
            debug!("Invalidating flow {flow_key}:{flow_info}");
            flow_info.invalidate_pair();
        }
    }

    /// Once a packet has been validated, if it refers to a flow, check that the flow
    /// is consistent with the annotations set for the packet. This is needed to invalidate
    /// flows on configuration changes since the flow a packet refers to may have been created with
    /// a prior config and no longer be valid with a newer configuration.
    /// The flow filter can't validate all cases since it does not have sufficient information and that
    /// is something that the NFs annotated by the flow-filter should do. However, there are cases where
    /// it can invalidate and it should, since no other NF may do so. For example, when transitioning
    /// from a configuration that for a given flow of traffic would require state into one where the same
    /// flow wouldn't, like moving from masquerade to static NAT or no NAT at all. It can also invalidate
    /// flows if the dst VPC indicated by the flow filter differs from that of the flow.
    fn should_invalidate_flow<Buf: PacketBufferMut>(
        packet: &Packet<Buf>,
        dst_vpcd: VpcDiscriminant,
        genid: i64,
    ) -> bool {
        let Some(flow_info) = &packet.meta().flow_info else {
            return false;
        };
        if flow_info.genid() == genid {
            return false;
        }
        let locked_info = flow_info.locked.read().unwrap();
        let flow_port_fw = locked_info.port_fw_state.is_some();
        let flow_masquerade = locked_info.nat_state.is_some();
        let flowkey = flow_info.flowkey().unwrap_or_else(|| unreachable!());
        if locked_info.dst_vpcd != Some(dst_vpcd) {
            debug!("Flow-info is out-dated. New dst VPC is {dst_vpcd}");
            return true;
        }
        if !packet.meta().requires_port_forwarding() && !packet.meta().requires_stateful_nat() {
            debug!("Flow {flowkey} no longer requires state. Will invalidate...");
            return true;
        }
        if packet.meta().requires_port_forwarding() && !flow_port_fw {
            debug!("Flow {flowkey} requires port-forwarding, but flow-info lacks such a state");
            return true;
        }
        if packet.meta().requires_stateful_nat() && !flow_masquerade {
            debug!("Flow {flowkey} requires masquerading, but flow-info lacks such a state");
            return true;
        }
        // we could not invalidate despite the config change. This does not mean that the flow is
        // valid (nor invalid). The NFs annotated in the requirements must determine. E.g. if we were
        // masquerading with address A and, a new config, requires masquerading with address B, the above
        // won't invalidate the flow, but the NF should (or update it accordingly).
        false
    }

    /// Check if flow-info is up-to-date and allows bypassing the main filtering logic.
    fn bypass_with_flow_info<Buf: PacketBufferMut>(
        &self,
        packet: &mut Packet<Buf>,
        genid: i64,
    ) -> bool {
        let nfi = &self.name;
        let Some(flow_info) = packet.active_flow_info() else {
            return false;
        };
        let Some(vpcd) = flow_info.get_dst_vpcd() else {
            debug!(
                "{nfi}: Flow-info does not specify destination VPC. This is a bug. Ignoring flow"
            );
            flow_info.invalidate_pair();
            return false;
        };
        let flow_genid = flow_info.genid();
        if flow_genid < genid {
            debug!("{nfi}: Packet has flow-info but from a prior config ({flow_genid} < {genid})");
            return false;
        }
        // The flow has the same generation id as the current config. Small transient state aside
        // this means that the flow is up-to-date and we can bypass the filter
        debug!("{nfi}: Packet can bypass filter due to flow {flow_info}");
        if Self::set_nat_requirements_from_flow_info(packet).is_err() {
            debug!("{nfi}: Failed to set nat requirements");
            return false;
        }
        packet.meta_mut().dst_vpcd = Some(vpcd);
        true
    }

    /// Process a packet.
    fn process_packet<Buf: PacketBufferMut>(
        &self,
        tablesr: &left_right::ReadGuard<'_, FlowFilterTable>,
        packet: &mut Packet<Buf>,
    ) {
        let nfi = &self.name;
        let genid = self.pipeline_data.genid();

        // bypass flow-filter if packet has flow-info and it is not outdated
        if self.bypass_with_flow_info(packet, genid) {
            return;
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
                // Check NAT requirements are sensible
                if self
                    .check_nat_requirements(packet, &dst_data, true)
                    .is_err()
                {
                    debug!(
                        "{nfi}: Invalid NAT requirements found for flow {tuple}, dropping packet"
                    );
                    Self::invalidate_packet_flow(packet);
                    packet.done(DoneReason::Filtered);
                    return;
                }
                Self::set_nat_requirements(packet, &dst_data);
                Some(dst_data.vpcd)
            }
            Some(VpcdLookupResult::MultipleMatches(data_set)) => {
                debug!(
                    "{nfi}: Found multiple matches for destination VPC for flow {tuple}. Checking for a flow table entry..."
                );

                match self.check_packet_flow_info(packet) {
                    Ok(Some(dst_vpcd)) => {
                        if Self::set_nat_requirements_from_flow_info(packet).is_ok() {
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
                        self.deal_with_multiple_matches(packet, &data_set, &tuple)
                    }
                    Err(reason) => {
                        debug!("Will drop packet. Reason: {reason}");
                        Self::invalidate_packet_flow(packet);
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
            packet.meta_mut().dst_vpcd = dst_vpcd; // whether we discovered the vpcd or not
            return;
        }

        // Drop the packet since we don't know destination and it is not an icmp error
        let Some(dst_vpcd) = dst_vpcd else {
            debug!("Could not determine dst vpcd for packet. Dropping it...");
            Self::invalidate_packet_flow(packet);
            packet.done(DoneReason::Filtered);
            return;
        };
        debug!("{nfi}: Flow {tuple} is allowed. Dst VPC is {dst_vpcd}");
        packet.meta_mut().dst_vpcd = Some(dst_vpcd);

        // The packet is ALLOWED. However, if it refers to a flow, the flow may no longer be
        // valid and a new one be required. The flow-filter cannot tell in many cases, as it
        // does not have enough information, nor should it upgrade flows to newer gen ids.
        // It should, however, invalidate flows in some cases.
        if Self::should_invalidate_flow(packet, dst_vpcd, genid) {
            Self::invalidate_packet_flow(packet);
        }
    }

    /// Attempt to determine destination VPC from packet's flow-info.
    fn check_packet_flow_info<Buf: PacketBufferMut>(
        &self,
        packet: &mut Packet<Buf>,
    ) -> Result<Option<VpcDiscriminant>, DoneReason> {
        let nfi = &self.name;

        let Some(flow_info) = packet.active_flow_info() else {
            return Ok(None);
        };

        let vpcd = flow_info.get_dst_vpcd();

        let Some(dst_vpcd) = vpcd else {
            debug!("{nfi}: No VPC discriminant found, dropping packet");
            return Err(DoneReason::Unroutable);
        };

        debug!("{nfi}: dst_vpcd discriminant is {dst_vpcd} (from active flow-info entry)");
        Ok(Some(dst_vpcd))
    }

    /// Handle destination VPC retrieval and NAT requirements setting when multiple matches were
    /// found, with no accompanying flow-info for the packet.
    fn deal_with_multiple_matches<Buf: PacketBufferMut>(
        &self,
        packet: &mut Packet<Buf>,
        data_set: &HashSet<RemoteData>,
        tuple: &FlowTuple,
    ) -> Option<VpcDiscriminant> {
        let nfi = &self.name;

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
            // Check NAT requirements are sensible - no need to check flow availability, we know we
            // don't have an active flow if we reached that point.
            if self
                .check_nat_requirements(packet, dst_data, false)
                .is_err()
            {
                return None;
            }
            Self::set_nat_requirements(packet, dst_data);
            return Some(first_vpcd);
        }

        if data_set.len() > 2 {
            debug!("{nfi}: Unsupported NAT requirements for flow {tuple}");
            return None;
        }

        // If we have masquerading and port forwarding on the source side, given that we haven't
        // found a valid NAT entry, stateful NAT should take precedence so the packet can come out.
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
            Self::set_nat_requirements(packet, dst_data);
            return Some(first_vpcd);
        }
        // If we have masquerading and port forwarding on the destination side, given that we
        // haven't found a valid NAT entry, port forwarding should take precedence.
        if let Some(dst_data) = data_set.iter().find(|d| {
            let Some(NatRequirement::PortForwarding(req_proto)) = d.dst_nat_req else {
                return false;
            };
            req_proto.intersection(&packet_proto).is_some()
        }) && data_set
            .iter()
            .any(|d| d.dst_nat_req == Some(NatRequirement::Stateful))
        {
            Self::set_nat_requirements(packet, dst_data);
            return Some(first_vpcd);
        }

        debug!("{nfi}: Unsupported NAT requirements for flow {tuple}");
        None
    }

    /// Check if the packet has valid NAT requirements.
    fn check_nat_requirements<Buf: PacketBufferMut>(
        &self,
        packet: &Packet<Buf>,
        dst_data: &RemoteData,
        needs_flow_verif: bool,
    ) -> Result<(), ()> {
        if needs_flow_verif && packet.active_flow_info().is_some() {
            return Ok(());
        }

        // We have no valid flow table entry for the packet: in this case, some NAT requirements are
        // not supported.
        let nfi = &self.name;
        if matches!(dst_data.dst_nat_req, Some(NatRequirement::Stateful)) {
            debug!(
                "{nfi}: Packet requires destination NAT with masquerade, but packet does not contain flow-info"
            );
            return Err(());
        }
        if matches!(
            dst_data.src_nat_req,
            Some(NatRequirement::PortForwarding(_))
        ) {
            debug!(
                "{nfi}: Packet requires source NAT with port forwarding, but packet does not contain flow-info"
            );
            return Err(());
        }
        Ok(())
    }

    /// Set NAT requirements on the packet based on the remote data object.
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

    /// Set NAT requirements on the packet based on packet's flow-info, if any.
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

pub(crate) fn get_l4_proto<Buf: PacketBufferMut>(packet: &Packet<Buf>) -> L4Protocol {
    match packet.try_transport() {
        Some(Transport::Tcp(_)) => L4Protocol::Tcp,
        Some(Transport::Udp(_)) => L4Protocol::Udp,
        _ => L4Protocol::Any,
    }
}
