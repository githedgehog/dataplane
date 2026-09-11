// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors
//
//! Implements an Ip forwarding stage

#![allow(clippy::similar_names)]

use net::headers::{TryHeaders, TryHeadersMut, TryIpv4Mut, TryIpv6Mut};
use net::packet::{DoneReason, Packet};
use net::{buffer::PacketBufferMut, checksum::Checksum};
use pipeline::NetworkFunction;
use std::net::IpAddr;
use std::rc::Rc;
use tracing::{debug, error, warn};

use routing::{
    EgressObject, FibEntry, FibKey, FibReader, FibTableReader, PktInstruction,
    ResolvedEncapsulation, ResolvedVxlan, Vtep,
};

use net::headers::{Headers, Net};
use net::interface::InterfaceIndex;
use net::ip::NextHeader;
use net::ipv4::{Ipv4, UnicastIpv4Addr};
use net::ipv6::{Ipv6, UnicastIpv6Addr};
use net::packet::VpcDiscriminant;
use net::udp::UdpEncap;
use net::vxlan::{Vxlan, VxlanEncap};

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

/// A two-slot memo of FIB readers, live for the length of one burst.
///
/// `FibTableReader::get_fib_reader` is not a getter. Each call takes a left-right read guard on
/// the FIB *table*, borrows a thread-local `RefCell`, hashes the key, revalidates the cached
/// entry against the provider -- which takes a second read guard -- and clones an `Rc`. Profiled
/// on the bench it was 7.6% of all cycles, of which about 3.2% was the memory fences in those two
/// guards alone, paid per packet for an answer that is the same for every packet in a burst.
///
/// Two slots rather than one because a single packet can need two different FIBs: the one it
/// routes in, and, on the vxlan decap path, the one named by the VNI just decapsulated. A single
/// slot would thrash between them and memoize nothing.
///
/// The memo does not outlive a `process_burst` call, so a FIB replaced by a config apply is
/// picked up on the next burst instead of the next packet. That widens the window from one packet
/// to one rx burst -- microseconds -- and config application is already unordered with respect to
/// traffic: nothing decides whether a packet that arrived before an apply is routed by the table
/// before or after it. Routing a burst that arrived together with one view of the table is, if
/// anything, the more defensible of the two.
#[derive(Default)]
struct FibMemo {
    slots: [Option<(FibKey, Rc<FibReader>)>; 2],
}

impl FibMemo {
    /// The reader for `key`, from the memo if it is there and from the table if it is not.
    ///
    /// Returns the `Rc` by value rather than by reference. A borrow would tie the memo to the
    /// lifetime of the read guard taken from it, and the caller needs the memo again while that
    /// guard is alive. The clone is a non-atomic refcount bump against the two memory fences it
    /// avoids.
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
                warn!(
                    "{}: missing vrf/vpc annotation to handle packet. Will drop it.",
                    self.name
                );
                packet.done(DoneReason::InternalFailure);
                return;
            }
            debug!(
                "{}: there is no vrf/vpc annotation to handle packet. Skipping...",
                self.name
            );
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

    /// Execute a local packet instruction
    fn packet_exec_instruction_local<Buf: PacketBufferMut>(
        &self,
        packet: &mut Packet<Buf>,
        _ifindex: InterfaceIndex, /* we get it from metadata */
        memo: &mut FibMemo,
    ) {
        let nfi = &self.name;

        /* packet is destined to gateway. Either we send the packet to the kernel or,
        if it contains an encapsulated packet (e.g. Vxlan), we send it to the next stage */

        match packet.vxlan_decap() {
            Some(Ok(vxlan)) => {
                let vni = vxlan.vni();
                tdebug!(VXLAN_D, "DECAPSULATED vxlan packet (vni={vni}):\n{packet}");
                debug!("{nfi}: DECAPSULATED vxlan packet, vni = {vni}");

                // access fib for Vni vni
                let fibkey = FibKey::from_vni(vni);
                let Some(fibr) = memo.reader(fibkey, &self.fibtr) else {
                    error!("{nfi}: Failed to find fib associated to vni {vni}. Fib key = {fibkey}");
                    packet.done(DoneReason::Unroutable);
                    return;
                };
                let Some(next_vrf) = fibr.get_id().map(|id| id.as_u32()) else {
                    debug!(
                        "{nfi}: Failed to access fib {fibkey} to determine vrf. Fib Key={fibkey}"
                    );
                    packet.done(DoneReason::InternalFailure);
                    return;
                };
                debug!("Next fib/vrf is {next_vrf}");

                /* At this point decapsulation has already happened and `Packet` refers to
                the innner packet. Annotate the incoming vni and the corresponding vrf to
                make lookups from */

                if !packet.headers().vlan().is_empty() {
                    debug!(
                        "{nfi}: Decapsulated frame carries a VLAN tag, which nothing downstream is equipped to carry"
                    );
                    packet.done(DoneReason::Unhandled);
                    return;
                }

                packet.meta_mut().src_vpcd = Some(VpcDiscriminant::VNI(vni));
                packet.meta_mut().vrf = Some(next_vrf);
                packet.meta_mut().set_overlay(true);
            }
            Some(Err(bad)) => {
                debug!("The decapsulated packet is malformed!: {bad:#?}");
                packet.done(DoneReason::VxlanDecapFailure);
            }
            None => {
                /* send to kernel, among other options */
                debug!("Packet should be delivered to kernel...");
                /*
                We can't re-inject packet on ingress, so let's disable this to avoid churn
                packet.get_meta_mut().oif = Some(packet.get_meta().iif);
                 */
                packet.done(DoneReason::Local);
            }
        }
    }

    /// Build the vxlan headers needed to encapsulate the packet in vxlan. This function returns
    /// an error as a string since there's nothing we can do other than logging if this fails.
    fn build_vxlan_headers(vxlan: &ResolvedVxlan, vtep: &Vtep) -> Result<VxlanEncap, String> {
        let Some(src_ip) = &vtep.get_ip() else {
            return Err("VTEP has no Ip address".to_string());
        };

        // IPv4 or IPv6
        let net = match (&src_ip, &vxlan.remote) {
            (IpAddr::V4(src_ip), IpAddr::V4(dst_ip)) => {
                let Ok(src_ip) = UnicastIpv4Addr::new(*src_ip) else {
                    return Err(format!("Invalid source IPv4 address '{src_ip}'"));
                };
                let mut ip = Ipv4::default();
                ip.set_source(src_ip).set_destination(*dst_ip).set_ttl(64);
                ip.set_next_header(NextHeader::UDP);
                Net::Ipv4(ip)
            }
            (IpAddr::V6(src_ip), IpAddr::V6(dst_ip)) => {
                let Ok(src_ip) = UnicastIpv6Addr::new(*src_ip) else {
                    return Err(format!("Invalid source IPv4 address '{src_ip}'"));
                };
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
        vxlan: &ResolvedVxlan,
        vtep: &Vtep,
    ) {
        let nfi = &self.name;

        let Some(src_mac) = &vtep.get_mac() else {
            error!("{nfi}: VxLAN encap FAILED: VTEP has no mac associated!");
            packet.done(DoneReason::VxlanEncapFailure);
            return;
        };
        let dst_mac = &vxlan.dmac;

        // set current packet src mac (inner)
        if let Err(e) = packet.set_eth_source(*src_mac) {
            error!("{nfi}: VxLAN encap FAILED: can't set src mac '{src_mac}': {e}");
            packet.done(DoneReason::VxlanEncapFailure);
            return;
        }

        // set current packet dst mac (inner)
        if let Err(e) = packet.set_eth_destination(*dst_mac) {
            error!("{nfi}: VxLAN encap FAILED: can't set dst mac '{dst_mac}': {e}");
            packet.done(DoneReason::VxlanEncapFailure);
            return;
        }

        // If packet requires updating checksums (e.g. because it was natted), do so.
        // Otherwise, refresh at least the ipv4 checksum, as we decremented the TTL.
        if packet.meta().checksum_refresh() {
            packet.update_checksums();
        } else if let Some(ipv4) = packet.headers_mut().try_ipv4_mut() {
            ipv4.update_checksum(&())
                .unwrap_or_else(|()| unreachable!()); // IPv4 checksum update never fails
        } else {
            unreachable!()
        }

        // build vxlan headers for encapsulation
        match Self::build_vxlan_headers(vxlan, vtep) {
            Err(e) => {
                warn!("{nfi}: Failed to build VxLAN headers: {e}");
                packet.done(DoneReason::VxlanEncapFailure);
            }
            Ok(vxlan_headers) => match packet.vxlan_encap(&vxlan_headers) {
                Ok(()) => {
                    let vni = vxlan_headers
                        .headers()
                        .udp_encap()
                        .unwrap_or_else(|| unreachable!())
                        .vxlan_vni();

                    packet.meta_mut().dst_vpcd = vni.map(VpcDiscriminant::VNI);
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
        #[allow(clippy::unused_self)] // Reserve the right to use self in the future
        &self,
        packet: &mut Packet<Buf>,
        encap: &ResolvedEncapsulation,
        vtep: &Vtep,
    ) {
        match encap {
            ResolvedEncapsulation::Mpls(_label) => todo!(),
            ResolvedEncapsulation::Vxlan(vxlan) => self.vxlan_encap(packet, vxlan, vtep),
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
        vtep: &Vtep,
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
        vtep: &Vtep,
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
mod fib_memo_test {
    use super::{FibMemo, FibKey};
    use routing::testing::RouterTables;

    /// The memo has to be transparent: for any key it must hand back the same FIB the table
    /// would have, whichever slot that lands in and however the keys interleave. Two slots is
    /// the smallest arrangement that can get this wrong, so the sequence below walks a hit in
    /// slot 0, an eviction, a hit in slot 1 with promotion, and a miss on a key the table does
    /// not have -- the last because a failed lookup must not disturb what is already memoized.
    ///
    /// Break-tested both ways. Returning slot 0 without comparing its key fails here on the
    /// third assertion, which is the bug worth guarding against. Disabling the slot-1 lookup
    /// entirely still passes, and should: that is the memo failing to memoize, which costs
    /// speed and not correctness, and no unit test can see it. Whether the memo actually hits
    /// is a question for the profile.
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
        assert_eq!(id(&mut memo, k1), Some(1), "old key still served, from slot 1");
        assert_eq!(id(&mut memo, k2), Some(2), "and back again");

        assert_eq!(id(&mut memo, absent), None, "a key the table lacks");
        assert_eq!(id(&mut memo, k2), Some(2), "miss left the memo intact");
        assert_eq!(id(&mut memo, k1), Some(1), "for both slots");
    }
}
