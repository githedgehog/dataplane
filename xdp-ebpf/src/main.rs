// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! The XDP program the AF_XDP driver attaches to each of its interfaces.
//!
//! It decides, for every packet, whether the dataplane sees it or the kernel
//! does. Redirecting to an AF_XDP socket is final -- the packet never enters
//! the network stack -- so anything the host itself needs has to be recognised
//! here and passed on instead.
//!
//! What the host needs is what the pipeline would have marked `Local`: traffic
//! addressed to the gateway that is not carrying an overlay. Userspace keeps
//! the gateway's own addresses in [`LOCAL_IPV4`] and [`LOCAL_IPV6`], and this
//! program passes anything destined to one of them. VXLAN is the exception:
//! it arrives addressed to the gateway too, and it is exactly what the
//! dataplane exists to handle.
//!
//! Anything that is not IP -- ARP, LLDP -- goes to the kernel as well. The
//! pipeline has nothing to do with those and drops them, and the host needs
//! them to resolve neighbours and be discovered.
//!
//! So does link-local multicast, which is how the protocols that run between
//! neighbours address each other: IPv6 neighbour discovery, router
//! advertisements, OSPF, VRRP. None of it is addressed to the gateway, so
//! nothing above would recognise it, and all of it is the host's.
//!
//! Everything else, which is the traffic the dataplane forwards, is redirected
//! to the socket bound to the queue it arrived on.

#![no_std]
#![no_main]

use aya_ebpf::bindings::xdp_action;
use aya_ebpf::macros::{map, xdp};
use aya_ebpf::maps::{HashMap, XskMap};
use aya_ebpf::programs::XdpContext;
use core::mem::size_of;

/// The AF_XDP sockets, indexed by RX queue.
///
/// Sized for the largest queue count we expect to serve on one interface;
/// queues beyond it are simply not redirected. The userspace side clamps to
/// the same number, which it keeps as `xdp::program::MAX_QUEUES` -- this crate
/// is `no_std` and built for another target, so it cannot share the constant.
#[map]
static XSKMAP: XskMap = XskMap::with_max_entries(64, 0);

/// The gateway's own IPv4 addresses, as they appear in a packet header.
///
/// Userspace owns the contents. An empty map means we know of no local
/// address, and everything IP goes to the dataplane.
#[map]
static LOCAL_IPV4: HashMap<u32, u8> = HashMap::with_max_entries(MAX_LOCAL_ADDRESSES, 0);

/// The gateway's own IPv6 addresses, as they appear in a packet header.
#[map]
static LOCAL_IPV6: HashMap<[u8; 16], u8> = HashMap::with_max_entries(MAX_LOCAL_ADDRESSES, 0);

/// How many addresses of each family the maps hold.
pub const MAX_LOCAL_ADDRESSES: u32 = 1024;

/// UDP port VXLAN arrives on. Matches `net::vxlan::Vxlan::PORT`.
const VXLAN_PORT: u16 = 4789;

// Ethernet, in the shapes this program needs. Kept here rather than taken from
// `net`, which is a std crate and cannot be built for this target.
const ETH_HDR_LEN: usize = 14;
const ETH_P_IPV4: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86dd;
const ETH_P_VLAN: u16 = 0x8100;
const ETH_P_QINQ: u16 = 0x88a8;
const VLAN_HDR_LEN: usize = 4;
/// How many stacked VLAN tags to look past. Two covers QinQ.
const MAX_VLAN_TAGS: usize = 2;

const IPPROTO_UDP: u8 = 17;

/// The IPv4 link-local multicast block, 224.0.0.0/24, as it appears in a
/// header. Everything a host says to its neighbours is in here.
const IPV4_LINK_LOCAL_MULTICAST: [u8; 3] = [224, 0, 0];
/// The IPv4 limited broadcast address, 255.255.255.255.
const IPV4_BROADCAST: [u8; 4] = [255, 255, 255, 255];
/// The first byte of any IPv6 multicast address, and the second byte of the
/// link-local scope: ff02::/16.
const IPV6_LINK_LOCAL_MULTICAST: [u8; 2] = [0xff, 0x02];
const IPV4_MIN_HDR_LEN: usize = 20;
const IPV6_HDR_LEN: usize = 40;

/// Read a `T` at `offset` from the start of the packet, if the packet is long
/// enough to hold one there.
///
/// Every read of packet data has to be proven in-bounds against `data_end`, or
/// the verifier rejects the program.
#[inline(always)]
fn read_at<T: Copy>(ctx: &XdpContext, offset: usize) -> Option<T> {
    let start = ctx.data();
    let end = ctx.data_end();
    // Checked as offset-from-start so that the comparison the verifier sees is
    // the one that bounds the read.
    if start + offset + size_of::<T>() > end {
        return None;
    }
    // SAFETY: the bounds check above puts the whole of T within the packet,
    // and the kernel guarantees the packet is readable for the life of the
    // call. The read is unaligned because packet data has no alignment.
    Some(unsafe { ((start + offset) as *const T).read_unaligned() })
}

/// Decide where a packet goes, and send it there.
///
/// `frags` says the program copes with a packet that arrives in more than one
/// buffer, which is what the kernel requires before it will attach one to an
/// interface whose MTU is larger than a buffer. It costs nothing here: the
/// headers this reads are all in the first buffer, which is the only part
/// `data`..`data_end` covers either way.
#[xdp(frags)]
pub fn xdp_redirect(ctx: XdpContext) -> u32 {
    if is_for_the_host(&ctx) {
        return xdp_action::XDP_PASS;
    }

    // SAFETY: the kernel hands the program a valid context for the life of
    // the call, and `rx_queue_index` is part of it.
    let queue_id = unsafe { (*ctx.ctx).rx_queue_index };

    // A queue with no socket in the map is not an error: the packet belongs
    // to the kernel stack.
    XSKMAP.redirect(queue_id, 0).unwrap_or(xdp_action::XDP_PASS)
}

/// Whether the kernel, rather than the dataplane, should have this packet.
#[inline(always)]
fn is_for_the_host(ctx: &XdpContext) -> bool {
    let Some((ethertype, l3_offset)) = l3_header(ctx) else {
        // Too short to classify. The dataplane would not make sense of it
        // either, and the kernel counts what it drops.
        return true;
    };

    match ethertype {
        ETH_P_IPV4 => ipv4_is_for_the_host(ctx, l3_offset),
        ETH_P_IPV6 => ipv6_is_for_the_host(ctx, l3_offset),
        // ARP, LLDP, and anything else the pipeline has no use for.
        _ => true,
    }
}

/// The ethertype of the packet and the offset of the header it names, looking
/// past any VLAN tags.
#[inline(always)]
fn l3_header(ctx: &XdpContext) -> Option<(u16, usize)> {
    let mut ethertype = u16::from_be(read_at::<u16>(ctx, 12)?);
    let mut offset = ETH_HDR_LEN;

    // Bounded so the verifier can unroll it; QinQ is as deep as we look.
    for _ in 0..MAX_VLAN_TAGS {
        if ethertype != ETH_P_VLAN && ethertype != ETH_P_QINQ {
            break;
        }
        ethertype = u16::from_be(read_at::<u16>(ctx, offset + 2)?);
        offset += VLAN_HDR_LEN;
    }

    Some((ethertype, offset))
}

/// Whether an IPv4 packet is one the host should receive.
#[inline(always)]
fn ipv4_is_for_the_host(ctx: &XdpContext, offset: usize) -> bool {
    // The header is read as its parts rather than a struct, so that each read
    // carries its own bounds check.
    let Some(version_ihl) = read_at::<u8>(ctx, offset) else {
        return true;
    };
    let Some(protocol) = read_at::<u8>(ctx, offset + 9) else {
        return true;
    };
    // The destination address, exactly as it sits in the header.
    let Some(destination) = read_at::<u32>(ctx, offset + 16) else {
        return true;
    };

    let header_len = ((version_ihl & 0x0f) as usize) * 4;
    if header_len < IPV4_MIN_HDR_LEN {
        return true;
    }

    if protocol == IPPROTO_UDP && is_vxlan(ctx, offset + header_len) {
        return false;
    }

    let octets = destination.to_ne_bytes();
    if octets[..3] == IPV4_LINK_LOCAL_MULTICAST || octets == IPV4_BROADCAST {
        return true;
    }

    // SAFETY: the map is not created with BPF_F_NO_PREALLOC, and userspace
    // only ever replaces whole entries, so a concurrent update cannot alias
    // this one into something else.
    unsafe { LOCAL_IPV4.get(destination).is_some() }
}

/// Whether an IPv6 packet is one the host should receive.
#[inline(always)]
fn ipv6_is_for_the_host(ctx: &XdpContext, offset: usize) -> bool {
    let Some(next_header) = read_at::<u8>(ctx, offset + 6) else {
        return true;
    };
    let Some(destination) = read_at::<[u8; 16]>(ctx, offset + 24) else {
        return true;
    };

    // Only the first header is looked at: VXLAN over IPv6 with extension
    // headers in front is not something we produce.
    if next_header == IPPROTO_UDP && is_vxlan(ctx, offset + IPV6_HDR_LEN) {
        return false;
    }

    if destination[..2] == IPV6_LINK_LOCAL_MULTICAST {
        return true;
    }

    // SAFETY: see `ipv4_is_for_the_host`.
    unsafe { LOCAL_IPV6.get(destination).is_some() }
}

/// Whether the UDP header at `offset` is carrying VXLAN.
#[inline(always)]
fn is_vxlan(ctx: &XdpContext, offset: usize) -> bool {
    read_at::<u16>(ctx, offset + 2).is_some_and(|port| u16::from_be(port) == VXLAN_PORT)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // Nothing here can panic, and the profile builds without the checks that
    // would reach this. It exists because a no_std binary must have one.
    loop {}
}
