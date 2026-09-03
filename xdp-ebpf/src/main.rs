// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! The XDP program the AF_XDP driver attaches to each of its interfaces.
//!
//! For every packet, it looks up the RX queue the packet arrived on in a map
//! of AF_XDP sockets, which userspace fills in as it binds them. A packet
//! whose queue has a socket goes to that socket; anything else is passed to
//! the kernel network stack, so that traffic on queues we do not serve, and
//! traffic arriving before the sockets are bound, still reaches the host.

#![no_std]
#![no_main]

use aya_ebpf::bindings::xdp_action;
use aya_ebpf::macros::{map, xdp};
use aya_ebpf::maps::XskMap;
use aya_ebpf::programs::XdpContext;

/// The AF_XDP sockets, indexed by RX queue.
///
/// Sized for the largest queue count we expect to serve on one interface;
/// queues beyond it are simply not redirected. The userspace side clamps to
/// the same number, which it keeps as `xdp::program::MAX_QUEUES` -- this crate
/// is `no_std` and built for another target, so it cannot share the constant.
#[map]
static XSKMAP: XskMap = XskMap::with_max_entries(64, 0);

/// Redirect a packet to the socket bound to the queue it arrived on.
#[xdp]
pub fn xdp_redirect(ctx: XdpContext) -> u32 {
    // SAFETY: the kernel hands the program a valid context for the life of
    // the call, and `rx_queue_index` is part of it.
    let queue_id = unsafe { (*ctx.ctx).rx_queue_index };

    // A queue with no socket in the map is not an error: the packet belongs
    // to the kernel stack.
    XSKMAP.redirect(queue_id, 0).unwrap_or(xdp_action::XDP_PASS)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // The verifier rejects any program that can reach an unbounded loop, so
    // this is never actually compiled into anything reachable.
    loop {}
}
