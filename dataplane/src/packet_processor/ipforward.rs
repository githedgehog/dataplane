// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors
//
//! Implements an Ip forwarding stage

#![allow(clippy::similar_names)]

use net::eth::mac::DestinationMac;
use net::headers::{Headers, Net};
use net::headers::{TryHeadersMut, TryIpv4Mut, TryIpv6Mut};
use net::interface::InterfaceIndex;
use net::ip::NextHeader;
use net::ip::UnicastIpAddr;
use net::ipv4::Ipv4;
use net::ipv6::Ipv6;
use net::packet::{DoneReason, Packet};
use net::packet::{VpcDiscriminant, VxLanPeekedData};
use net::udp::UdpEncap;
use net::vxlan::Vni;
use net::vxlan::{Vxlan, VxlanEncap};
use net::{buffer::PacketBufferMut, checksum::Checksum};
use pipeline::NetworkFunction;
use std::net::IpAddr;
use std::rc::Rc;
use tracing::{debug, error, warn};

use routing::{
    EgressObject, Encapsulation, FibEntry, FibKey, FibReader, FibTableReader, PktInstruction, Vtep,
    VxlanEncapsulation,
};

use tracectl::{custom_target, tdebug, trace_target};
trace_target!("ip-forward", LevelFilter::WARN, &["pipeline"]);

const VXLAN_D: &str = "vxlan-decap";
const VXLAN_E: &str = "vxlan-encap";
custom_target!(VXLAN_D, LevelFilter::OFF, &["vxlan"]);
custom_target!(VXLAN_E, LevelFilter::OFF, &["vxlan"]);

pub struct IpForwarder {
    name: String,
    fibtr: FibTableReader,
}

/// Cache up to two FIB readers per burst to avoid repeated table lookups.
///
/// Two slots cover the routing FIB and the VNI FIB used after VXLAN decapsulation.
/// FIB replacements are picked up on eviction or at the next burst.
#[derive(Default)]
struct FibMemo {
    slots: [Option<(FibKey, Rc<FibReader>)>; 2],
}

impl FibMemo {
    /// Return an owned reader so the memo remains usable while a read guard is held.
    fn reader(&mut self, key: FibKey, fibtr: &FibTableReader) -> Option<Rc<FibReader>> {
        if self.slots[1].as_ref().is_some_and(|(k, _)| *k == key) {
            self.slots.swap(0, 1);
        } else if self.slots[0].as_ref().is_none_or(|(k, _)| *k != key) {
            let reader = fibtr.get_fib_reader(key).ok()?;
            self.slots[1] = self.slots[0].take();
            self.slots[0] = Some((key, reader));
        }
        self.slots[0].as_ref().map(|(_, reader)| Rc::clone(reader))
    }
}

impl IpForwarder {
    /// Build a new IP forwarding stage to use the indicated [`FibTableReader`]
    #[must_use]
    pub fn new(name: &str, fibtr: FibTableReader) -> Self {
        Self {
            name: name.to_owned(),
            fibtr,
        }
    }

    /// Forward a [`Packet`]
    #[allow(clippy::collapsible_else_if)]
    fn forward_packet<Buf: PacketBufferMut>(&self, packet: &mut Packet<Buf>, memo: &mut FibMemo) {
        let nfi = &self.name;
        let vrfid = packet.meta().vrf;

        let fibkey = if let Some(dst_vpcd) = packet.meta().dst_vpcd {
            let VpcDiscriminant::VNI(dst_vni) = dst_vpcd;
            FibKey::from_vni(dst_vni)
        } else if let Some(vrfid) = vrfid {
            FibKey::from_vrfid(vrfid)
        } else {
            if packet.meta().is_overlay() {
                warn!("{nfi}: missing vrf/vpc annotation to handle packet. Will drop it.");
                packet.done(DoneReason::InternalFailure);
                return;
            }
            debug!("{nfi}: there is no vrf/vpc annotation to handle packet. Skipping...");
            // not dropped
            return;
        };

        /* get destination ip address */
        let Some(dst) = packet.ip_destination() else {
            error!("{nfi}: logic error, failed to get destination ip address for packet");
            packet.done(DoneReason::InternalFailure);
            return;
        };
        debug!("{nfi}: processing packet to {dst} with FIB {fibkey}");

        /* access fib, by fetching FibReader from the burst memo (falling back to the cache) */
        let Some(fibr) = memo.reader(fibkey, &self.fibtr) else {
            warn!("{nfi}: Unable to read fib. Key={fibkey}");
            packet.done(DoneReason::InternalFailure);
            return;
        };
        let Some(fib) = fibr.enter() else {
            warn!("{nfi}: Unable to read from fib. Key={fibkey}");
            packet.done(DoneReason::InternalFailure);
            return;
        };

        /* Perform lookup in the fib. This always returns a FibEntry */
        let (prefix, fibentry) = fib.lpm_entry_prefix(packet);
        debug!("{nfi}: Packet hits prefix {prefix} in fib {fibkey}");
        debug!("{nfi}: Entry is:\n{fibentry}");

        /* decrement packet TTL, unless the packet is for us */
        if !fibentry.is_iplocal() {
            Self::decrement_ttl(packet, dst);
            if packet.is_done() {
                debug!("TTL/Hop-count limit exceeded!");
                return;
            }
        }

        /* execute instructions according to FIB */
        self.packet_exec_instructions(packet, fibentry, fib.get_vtep(), memo);

        /* strip vrfid */
        if packet.meta().vrf == vrfid {
            packet.meta_mut().vrf.take();
        }
    }

    fn get_fib_for_vni(&self, memo: &mut FibMemo, vni: Vni) -> Option<Rc<FibReader>> {
        let fibkey = FibKey::from_vni(vni);
        memo.reader(fibkey, &self.fibtr)
    }

    // Process a packet that we know has a valid VxLAN-encapsulated frame,
    // by decapsulating it and annotating it. The packet will be dropped if
    // decapsulation fails or if any of the following is true:
    //    1) there is no fib associated to the Vni
    //    2) the fib has no VTEP associated: this is a bug.
    //    3) the packet is not IP-destined to our VTEP IP.
    //    4) the packet has VLAN tags
    //    5) if `check_dst_mac` is true, the dst mac of the inner frame
    //       differs from the of the VTEP. The flag should be true for L3 VNIs.
    fn handle_vxlan<Buf: PacketBufferMut>(
        &self,
        packet: &mut Packet<Buf>,
        peeked: VxLanPeekedData,
        check_dst_mac: bool,
        memo: &mut FibMemo,
    ) {
        let nfi = &self.name;
        let vni = peeked.vni;

        // I am not sure about why this restriction  was recently added
        if peeked.inner_vlan_tagged {
            debug!(
                "{nfi}: Inner frame carries VLAN tag(s), which nothing downstream is equipped to carry"
            );
            packet.done(DoneReason::Unhandled);
            return;
        }
        let Some(fibr) = self.get_fib_for_vni(memo, vni) else {
            debug!("{nfi}: Failed to find fib associated to vni {vni}");
            packet.done(DoneReason::Unroutable);
            return;
        };
        let Some(fib) = fibr.enter() else {
            error!("{nfi}: Failed to access fib for vni {vni}");
            packet.done(DoneReason::InternalFailure);
            return;
        };
        let Some(vtep) = fib.get_vtep() else {
            error!("{nfi}: Fib for {vni} has no VTEP. This is a bug");
            packet.done(DoneReason::InternalFailure);
            return;
        };
        if peeked.outer_dst_ip != vtep.ip().inner() {
            debug!("{nfi}: VxLAN dst ip does not match our vtep {}", vtep.ip());
            packet.done(DoneReason::VxlanNotForUs);
            return;
        }
        if check_dst_mac && peeked.inner_dst_mac != vtep.mac().into() {
            debug!(
                "{nfi}: Inner frame is not for us but {}",
                peeked.inner_dst_mac
            );
            packet.done(DoneReason::VxlanNotForUs);
            return;
        }

        // do the actual decapsulation
        match packet.vxlan_decap() {
            Some(Ok(_)) => {
                // At this point decapsulation has already happened. `Packet` refers to the inner packet.
                let next_vrf = fib.get_id().as_u32();
                tdebug!(VXLAN_D, "DECAPSULATED vxlan packet (vni={vni}):\n{packet}");
                debug!("{nfi}: DECAPSULATED vxlan packet, vni = {vni}. Next vrf = {next_vrf}");

                // Annotate the incoming vni and the corresponding vrf, so that lookups are made in that vrf
                packet.meta_mut().src_vpcd = Some(VpcDiscriminant::VNI(vni));
                packet.meta_mut().vrf = Some(next_vrf);
                packet.meta_mut().set_overlay(true);
            }
            Some(Err(bad)) => {
                // this should not happen: vxlan_peek() succeeded, and it fails when decapsulation would.
                debug!("{nfi}: Failure decapsulating VxLAN packet!: {bad:#?}");
                packet.done(DoneReason::VxlanDecapFailure);
            }
            None => {
                // this should not happen since we checked that the packet was vxlan
                warn!("Vxlan decap failed on packet assumed to be VxLAN");
                packet.done(DoneReason::InternalFailure);
            }
        }
    }

    /// Execute a local packet instruction
    fn packet_exec_instruction_local<Buf: PacketBufferMut>(
        &self,
        packet: &mut Packet<Buf>,
        _ifindex: InterfaceIndex, /* we get it from metadata */
        memo: &mut FibMemo,
    ) {
        // We got a packet that the routing table says is for us.
        // If the packet contains a VxLAN encapsulation, decapsulate it and further process it.
        // Otherwise, the packet is meant for local consumption.
        match packet.vxlan_peek() {
            Ok(Some(peeked_data)) => self.handle_vxlan(packet, peeked_data, true, memo),
            Err(e) => {
                // Packet contains VxLAN encap but we failed to peek the data. Peeking fails
                // exactly when decapsulation would (the inner Ethernet header does not parse),
                // so account for it as a decapsulation failure.
                let nfi = &self.name;
                debug!("{nfi}: VxLAN encap peeking failed: {e}");
                packet.done(DoneReason::VxlanDecapFailure);
            }
            Ok(None) => {
                // Packet does not include VxLAN encap. Consume it.
                packet.done(DoneReason::Local);
            }
        }
    }

    /// Build the vxlan headers needed to encapsulate the packet in vxlan. This function returns
    /// an error as a string since there's nothing we can do other than logging if this fails.
    fn build_vxlan_headers(vxlan: &VxlanEncapsulation, vtep: &Vtep) -> Result<VxlanEncap, String> {
        let src_ip = vtep.ip();

        // IPv4 or IPv6
        let net = match (src_ip, &vxlan.remote) {
            (UnicastIpAddr::V4(src_ip), IpAddr::V4(dst_ip)) => {
                let mut ip = Ipv4::default();
                ip.set_source(src_ip).set_destination(*dst_ip).set_ttl(64);
                ip.set_next_header(NextHeader::UDP);
                Net::Ipv4(ip)
            }
            (UnicastIpAddr::V6(src_ip), IpAddr::V6(dst_ip)) => {
                let mut ip = Ipv6::default();
                ip.set_source(src_ip)
                    .set_destination(*dst_ip)
                    .set_hop_limit(64)
                    .set_next_header(NextHeader::UDP);
                Net::Ipv6(ip)
            }
            _ => return Err("Invalid src/dst address IP versions".to_string()),
        };

        // Encapsulation pseudo header
        let udp_encap = UdpEncap::Vxlan(Vxlan::new(vxlan.vni));

        // Vxlan encap API headers
        let mut headers = Headers::default();
        headers.set_net(Some(net));
        headers.set_udp_encap(Some(udp_encap));
        VxlanEncap::new(headers).map_err(|e| format!("{e}"))
    }

    // RFC 4787's "NAT" is the device, not the translation stage: REQ-13 is router behavior
    // (RFC 1812), and it belongs here because encapsulation is where a packet grows past the
    // egress MTU.
    //= https://www.rfc-editor.org/rfc/rfc4787#section-10
    //= type=todo
    //# REQ-13:  If the packet received on an internal IP address has DF=1,
    //# the NAT MUST send back an ICMP message "Fragmentation needed and
    //# DF set" to the host, as described in [RFC0792].
    //= https://www.rfc-editor.org/rfc/rfc4787#section-10
    //= type=todo
    //# a) If the packet has DF=0, the NAT MUST fragment the packet and
    //# SHOULD send the fragments in order.
    fn vxlan_encap<Buf: PacketBufferMut>(
        &self,
        packet: &mut Packet<Buf>,
        vxlan: &VxlanEncapsulation,
        vtep: &Vtep,
    ) {
        let nfi = &self.name;

        // set the src mac of the current packet (inner)
        if packet.set_eth_source_mac(vtep.mac()).is_err() {
            packet.done(DoneReason::VxlanEncapFailure);
            return;
        }

        // set current packet dst mac (inner)
        if packet
            .set_eth_dest_mac(DestinationMac::from(vxlan.rmac))
            .is_err()
        {
            packet.done(DoneReason::VxlanEncapFailure);
            return;
        }

        // Refresh requested checksums, or just the IPv4 checksum after decrementing TTL.
        // IPv6 has no header checksum.
        if packet.meta().checksum_refresh() {
            packet.update_checksums();
        } else if let Some(ipv4) = packet.headers_mut().try_ipv4_mut() {
            ipv4.update_checksum(&())
                .unwrap_or_else(|()| unreachable!()); // IPv4 checksum update never fails
        }

        // build vxlan headers for encapsulation
        match Self::build_vxlan_headers(vxlan, vtep) {
            Err(e) => {
                warn!("{nfi}: Failed to build VxLAN headers: {e}");
                packet.done(DoneReason::VxlanEncapFailure);
            }
            Ok(vxlan_headers) => match packet.vxlan_encap(&vxlan_headers) {
                Ok(()) => {
                    packet.meta_mut().dst_vpcd = Some(VpcDiscriminant::from_vni(vxlan.vni));
                    tdebug!(VXLAN_E, "ENCAPSULATED packet with VxLAN:\n{packet}");
                }
                Err(e) => {
                    error!("{nfi}: Failed to ENCAPSULATE packet with VxLAN: {e}");
                    packet.done(DoneReason::VxlanEncapFailure);
                }
            },
        }
    }

    fn packet_exec_instruction_encap<Buf: PacketBufferMut>(
        &self,
        packet: &mut Packet<Buf>,
        encap: &Encapsulation,
        vtep: Option<&Vtep>,
    ) {
        match encap {
            Encapsulation::Mpls(_label) => todo!(),
            Encapsulation::Vxlan(vxlan) => {
                if let Some(vtep) = vtep {
                    self.vxlan_encap(packet, vxlan, vtep);
                } else {
                    let nfi = &self.name;
                    error!("{nfi}: VxLAN encap FAILED: no VTEP info available");
                    packet.done(DoneReason::VxlanEncapFailure);
                }
            }
        }
    }

    /// Execute an egress instruction given by the [`EgressObject`] by setting the required metadata
    /// to send the packet (at an egress stage).
    #[allow(clippy::unused_self)] // Reserve the right to use self in the future
    fn packet_exec_instruction_egress<Buf: PacketBufferMut>(
        &self,
        packet: &mut Packet<Buf>,
        egress: &EgressObject,
    ) {
        let meta = packet.meta_mut();
        meta.oif = *egress.ifindex(); // may be None
        meta.nh_addr = *egress.address(); // may be None
        if meta.oif.is_some() {
            debug!("Marked packet to send via interface {:?}", meta.oif);
        } else {
            // We should not see this log if we squash all of the
            // egress instructions and have one with an outgoing interface
            warn!("Packet hit egress object without outgoing interface");
        }
    }

    /// Execute a drop instruction: mark the packet as to drop
    #[allow(clippy::unused_self)] // Reserve the right to use self in the future
    fn packet_exec_instruction_drop<Buf: PacketBufferMut>(&self, packet: &mut Packet<Buf>) {
        packet.done(DoneReason::RouteDrop);
    }

    #[inline]
    /// Execute a [`PktInstruction`] on the packet
    fn packet_exec_instruction<Buf: PacketBufferMut>(
        &self,
        vtep: Option<&Vtep>,
        packet: &mut Packet<Buf>,
        instruction: &PktInstruction,
        memo: &mut FibMemo,
    ) {
        match instruction {
            PktInstruction::Drop => self.packet_exec_instruction_drop(packet),
            PktInstruction::Local(ifindex) => {
                self.packet_exec_instruction_local(packet, *ifindex, memo);
            }
            PktInstruction::Encap(encap) => self.packet_exec_instruction_encap(packet, encap, vtep),
            PktInstruction::Egress(egress) => self.packet_exec_instruction_egress(packet, egress),
        }
    }

    /// Execute all of the [`PktInstruction`]s indicated by the given [`FibEntry`] on the packet
    fn packet_exec_instructions<Buf: PacketBufferMut>(
        &self,
        packet: &mut Packet<Buf>,
        fibentry: &FibEntry,
        vtep: Option<&Vtep>,
        memo: &mut FibMemo,
    ) {
        for inst in fibentry.iter() {
            self.packet_exec_instruction(vtep, packet, inst, memo);
            if packet.is_done() {
                return;
            }
        }
    }

    /// Decrement the TTL or the hop count for a packet
    fn decrement_ttl<Buf: PacketBufferMut>(packet: &mut Packet<Buf>, dst_address: IpAddr) {
        match dst_address {
            IpAddr::V4(_) => {
                if let Some(ipv4) = packet.try_ipv4_mut() {
                    if ipv4.decrement_ttl().is_err() || ipv4.ttl() == 0 {
                        packet.done(DoneReason::HopLimitExceeded);
                    }
                } else {
                    unreachable!()
                }
            }
            IpAddr::V6(_) => {
                if let Some(ipv6) = packet.try_ipv6_mut() {
                    if ipv6.decrement_hop_limit().is_err() || ipv6.hop_limit() == 0 {
                        packet.done(DoneReason::HopLimitExceeded);
                    }
                } else {
                    unreachable!()
                }
            }
        }
    }
}

impl<Buf: PacketBufferMut> NetworkFunction<Buf> for IpForwarder {
    #[tracing::instrument(level = "trace", skip(self, burst))]
    fn process_burst(&mut self, burst: &mut Vec<Packet<Buf>>) {
        let mut memo = FibMemo::default();
        for packet in burst.iter_mut() {
            if !packet.is_done() {
                self.forward_packet(packet, &mut memo);
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::FibMemo;
    use super::IpForwarder;
    use net::buffer::TestBuffer;
    use net::eth::mac::{DestinationMac, Mac, SourceMac};
    use net::headers::{TryEthMut, TryHeaders, TryHeadersMut, TryIpv4Mut, TryVxlan};
    use net::interface::InterfaceIndex;
    use net::ip::dscp::Dscp;
    use net::ip::ecn::Ecn;
    use net::ip::{NextHeader, UnicastIpAddr};
    use net::packet::test_utils::{
        build_test_ipv4_packet, build_test_ipv6_packet_with_transport,
        build_test_vxlan_ipv4_packet_carrying_vni,
    };
    use net::packet::{DoneReason, Packet, VpcDiscriminant};
    use net::vlan::Vid;
    use net::vxlan::Vni;
    use routing::testing::RouterTables;
    use routing::{
        EgressObject, Encapsulation, FibEntry, PktInstruction, Vtep, VxlanEncapsulation,
    };
    use std::net::{IpAddr, Ipv4Addr};
    use std::str::FromStr;

    fn test_vtep() -> Vtep {
        Vtep::new(
            UnicastIpAddr::from_str("192.0.2.1").expect("Bad Ip"),
            SourceMac::try_from("02:00:00:00:00:01").expect("Bad mac"),
        )
    }

    fn test_vxlan() -> VxlanEncapsulation {
        VxlanEncapsulation {
            vni: Vni::new_checked(100).unwrap(),
            remote: IpAddr::from([192, 0, 2, 2]),
            rmac: SourceMac::new(Mac([0x02, 0, 0, 0, 0, 0x02])).unwrap(),
        }
    }

    /// A fib entry that encapsulates in vxlan and sends the packet over interface 1
    fn vxlan_fibentry() -> FibEntry {
        let mut entry =
            FibEntry::with_inst(PktInstruction::Encap(Encapsulation::Vxlan(test_vxlan())));
        entry.add(PktInstruction::Egress(EgressObject::new(
            InterfaceIndex::try_new(1).ok(),
            Some(IpAddr::from([192, 0, 2, 2])),
        )));
        entry
    }

    /// IPv6 packets need no header checksum refresh before encapsulation.
    #[test]
    fn an_ipv6_packet_without_a_refresh_encapsulates() {
        let forwarder = IpForwarder::new("test", RouterTables::new().fibs());
        let vtep = test_vtep();
        let vxlan = test_vxlan();

        let mut packet = build_test_ipv6_packet_with_transport(64, Some(NextHeader::UDP)).unwrap();
        assert!(!packet.meta().checksum_refresh());

        forwarder.vxlan_encap(&mut packet, &vxlan, &vtep);

        assert_eq!(packet.get_done(), None);
        assert!(
            packet.meta().dst_vpcd.is_some(),
            "the packet was not encapsulated"
        );
    }

    /// A vxlan fib entry is executed: the packet is encapsulated and sent over the interface
    #[test]
    fn a_vxlan_entry_with_a_vtep_encapsulates_and_egresses() {
        let forwarder = IpForwarder::new("test", RouterTables::new().fibs());
        let vtep = test_vtep();
        let mut memo = FibMemo::default();
        let mut packet = build_test_ipv6_packet_with_transport(64, Some(NextHeader::UDP)).unwrap();

        forwarder.packet_exec_instructions(&mut packet, &vxlan_fibentry(), Some(&vtep), &mut memo);

        assert_eq!(packet.get_done(), None);
        assert!(
            packet.meta().dst_vpcd.is_some(),
            "the packet was not encapsulated"
        );
        assert_eq!(packet.meta().oif, InterfaceIndex::try_new(1).ok());
    }

    /// Without a VTEP a packet can't be encapsulated in vxlan: it is dropped and the
    /// remaining instructions of the fib entry are not executed
    #[test]
    fn a_vxlan_entry_without_a_vtep_drops_the_packet() {
        let forwarder = IpForwarder::new("test", RouterTables::new().fibs());
        let mut memo = FibMemo::default();
        let mut packet = build_test_ipv6_packet_with_transport(64, Some(NextHeader::UDP)).unwrap();

        forwarder.packet_exec_instructions(&mut packet, &vxlan_fibentry(), None, &mut memo);

        assert_eq!(packet.get_done(), Some(DoneReason::VxlanEncapFailure));
        assert!(
            packet.meta().dst_vpcd.is_none(),
            "the packet should not be encapsulated"
        );
        assert!(
            packet.meta().oif.is_none(),
            "the egress instruction should not be executed"
        );
    }

    const VRF: u32 = 1;

    fn our_vni() -> Vni {
        Vni::new_checked(3000).unwrap()
    }

    /// Router tables with a vrf for `our_vni()` that has `test_vtep()` as its VTEP.
    /// The tables must outlive the forwarder, which only holds readers.
    fn tables_with_vtep() -> RouterTables {
        let mut tables = RouterTables::new();
        tables.vrf(VRF, Some(our_vni())).vtep(VRF, test_vtep());
        tables
    }

    fn vtep_ip() -> Ipv4Addr {
        let IpAddr::V4(ip) = test_vtep().ip().inner() else {
            unreachable!()
        };
        ip
    }

    fn vtep_mac() -> DestinationMac {
        test_vtep().mac().into()
    }

    /// A VXLAN packet for `vni`, sent to `outer_dst`, whose inner frame is addressed to
    /// `inner_dst` and optionally carries a VLAN tag.
    fn vxlan_packet(
        vni: Vni,
        outer_dst: Ipv4Addr,
        inner_dst: DestinationMac,
        vlan: Option<Vid>,
    ) -> Packet<TestBuffer> {
        let mut inner = build_test_ipv4_packet(64).unwrap();
        inner.try_eth_mut().unwrap().set_destination(inner_dst);
        if let Some(vid) = vlan {
            inner.headers_mut().push_vlan(vid).unwrap();
        }
        let inner_buf = inner.serialize().unwrap();
        let mut packet = build_test_vxlan_ipv4_packet_carrying_vni(
            vni,
            Dscp::new(0).unwrap(),
            Ecn::new(0).unwrap(),
            inner_buf.as_ref(),
        )
        .unwrap();
        packet.try_ipv4_mut().unwrap().set_destination(outer_dst);
        packet
    }

    fn exec_local(forwarder: &IpForwarder, packet: &mut Packet<TestBuffer>) {
        let mut memo = FibMemo::default();
        forwarder.packet_exec_instruction_local(
            packet,
            InterfaceIndex::try_new(1).unwrap(),
            &mut memo,
        );
    }

    /// A VXLAN packet for our VTEP and VNI is decapsulated and annotated with its vni and vrf
    #[test]
    fn a_vxlan_packet_for_our_vtep_is_decapsulated() {
        let tables = tables_with_vtep();
        let forwarder = IpForwarder::new("test", tables.fibs());
        let mut packet = vxlan_packet(our_vni(), vtep_ip(), vtep_mac(), None);

        exec_local(&forwarder, &mut packet);

        assert_eq!(packet.get_done(), None);
        assert!(
            packet.headers().try_vxlan().is_none(),
            "the packet was not decapsulated"
        );
        assert_eq!(
            packet.meta().src_vpcd,
            Some(VpcDiscriminant::VNI(our_vni()))
        );
        assert_eq!(packet.meta().vrf, Some(VRF));
        assert!(packet.meta().is_overlay());
    }

    /// A VXLAN packet whose outer destination is not our VTEP is dropped without decapsulation
    #[test]
    fn a_vxlan_packet_for_another_vtep_is_not_for_us() {
        let tables = tables_with_vtep();
        let forwarder = IpForwarder::new("test", tables.fibs());
        let other = Ipv4Addr::new(192, 0, 2, 99);
        let mut packet = vxlan_packet(our_vni(), other, vtep_mac(), None);

        exec_local(&forwarder, &mut packet);

        assert_eq!(packet.get_done(), Some(DoneReason::VxlanNotForUs));
        assert!(packet.headers().try_vxlan().is_some());
    }

    /// A VXLAN packet whose inner frame is not addressed to our VTEP MAC is dropped without
    /// decapsulation
    #[test]
    fn a_vxlan_packet_for_another_inner_mac_is_not_for_us() {
        let tables = tables_with_vtep();
        let forwarder = IpForwarder::new("test", tables.fibs());
        let other = DestinationMac::new(Mac([0x02, 0, 0, 0, 0, 0x99])).unwrap();
        let mut packet = vxlan_packet(our_vni(), vtep_ip(), other, None);

        exec_local(&forwarder, &mut packet);

        assert_eq!(packet.get_done(), Some(DoneReason::VxlanNotForUs));
        assert!(packet.headers().try_vxlan().is_some());
    }

    /// A VXLAN packet for a VNI we have no fib for is unroutable
    #[test]
    fn a_vxlan_packet_for_an_unknown_vni_is_unroutable() {
        let tables = tables_with_vtep();
        let forwarder = IpForwarder::new("test", tables.fibs());
        let unknown = Vni::new_checked(4000).unwrap();
        let mut packet = vxlan_packet(unknown, vtep_ip(), vtep_mac(), None);

        exec_local(&forwarder, &mut packet);

        assert_eq!(packet.get_done(), Some(DoneReason::Unroutable));
    }

    /// A VXLAN packet whose inner frame is VLAN-tagged is not handled
    #[test]
    fn a_vxlan_packet_with_a_tagged_inner_frame_is_unhandled() {
        let tables = tables_with_vtep();
        let forwarder = IpForwarder::new("test", tables.fibs());
        let vid = Vid::new(100).unwrap();
        let mut packet = vxlan_packet(our_vni(), vtep_ip(), vtep_mac(), Some(vid));

        exec_local(&forwarder, &mut packet);

        assert_eq!(packet.get_done(), Some(DoneReason::Unhandled));
    }

    /// A VXLAN packet whose inner frame is too short for an Ethernet header fails to decapsulate
    #[test]
    fn a_vxlan_packet_with_a_truncated_inner_frame_fails_decapsulation() {
        let tables = tables_with_vtep();
        let forwarder = IpForwarder::new("test", tables.fibs());
        let mut packet = build_test_vxlan_ipv4_packet_carrying_vni(
            our_vni(),
            Dscp::new(0).unwrap(),
            Ecn::new(0).unwrap(),
            &[0u8; 6],
        )
        .unwrap();

        exec_local(&forwarder, &mut packet);

        assert_eq!(packet.get_done(), Some(DoneReason::VxlanDecapFailure));
    }

    /// A packet without VXLAN encapsulation is for local consumption
    #[test]
    fn a_packet_without_vxlan_is_local() {
        let tables = tables_with_vtep();
        let forwarder = IpForwarder::new("test", tables.fibs());
        let mut packet = build_test_ipv4_packet(64).unwrap();

        exec_local(&forwarder, &mut packet);

        assert_eq!(packet.get_done(), Some(DoneReason::Local));
    }
}

#[cfg(test)]
mod fib_memo_test {
    use super::{FibKey, FibMemo};
    use routing::testing::RouterTables;

    #[test]
    fn memo_answers_as_the_table_would() {
        let mut tables = RouterTables::default();
        tables.vrf(1, None).vrf(2, None);
        let fibtr = tables.fibs();

        let (k1, k2) = (FibKey::from_vrfid(1), FibKey::from_vrfid(2));
        let absent = FibKey::from_vrfid(99);

        let id = |memo: &mut FibMemo, key| {
            memo.reader(key, &fibtr)
                .and_then(|reader| reader.get_id().map(|id| id.as_u32()))
        };

        let mut memo = FibMemo::default();
        assert_eq!(id(&mut memo, k1), Some(1), "first lookup");
        assert_eq!(id(&mut memo, k1), Some(1), "repeat hits slot 0");
        assert_eq!(id(&mut memo, k2), Some(2), "new key evicts into slot 1");
        assert_eq!(
            id(&mut memo, k1),
            Some(1),
            "old key still served, from slot 1"
        );
        assert_eq!(id(&mut memo, k2), Some(2), "and back again");

        assert_eq!(id(&mut memo, absent), None, "a key the table lacks");
        assert_eq!(id(&mut memo, k2), Some(2), "miss left the memo intact");
        assert_eq!(id(&mut memo, k1), Some(1), "for both slots");
    }
}
