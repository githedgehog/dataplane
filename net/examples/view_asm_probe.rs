// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! ASM probe for `HeadersView<T>::look`.
//!
//! Build and dump assembly:
//!
//! ```text
//! cargo rustc --release --example view_asm_probe --features test_buffer \
//!     -- --emit=asm -C debuginfo=0
//! # Output lands in target/release/examples/view_asm_probe-<hash>.s
//! ```
//!
//! Each `probe_*` function is `#[unsafe(no_mangle)]` so its symbol
//! is easy to grep for.  Each is also `#[inline(never)]` to force a
//! standalone emission (without this the optimizer could fold the
//! probe into `main`).  Inside the probe the `HeadersView` API calls **do**
//! get inlined -- that's the point of the exercise.
//!
//! The probes use the Rust ABI (`pub fn`, not `pub extern "C" fn`)
//! deliberately: `extern "C" fn ... -> Option<(&T, &U, &V)>` would
//! trigger `improper_ctypes_definitions`, and nothing links these
//! probes from C anyway.  `#[unsafe(no_mangle)]` keeps the symbol
//! stable for asm inspection, which is all we need.  Hence the
//! module-level `allow(clippy::no_mangle_with_rust_abi)` below.

#![deny(clippy::all, clippy::pedantic)]
#![allow(clippy::no_mangle_with_rust_abi)] // probes are asm-only; no C linkage

use dataplane_net::eth::Eth;
use dataplane_net::headers::{Headers, HeadersView, Look};
use dataplane_net::icmp4::Icmp4;
use dataplane_net::icmp6::Icmp6;
use dataplane_net::ipv4::Ipv4;
use dataplane_net::ipv6::{DestOpts, HopByHop, Ipv6};
use dataplane_net::tcp::Tcp;
use dataplane_net::udp::Udp;
use dataplane_net::vlan::Vlan;

#[inline(never)]
#[unsafe(no_mangle)]
pub fn probe_v4_tcp(h: &Headers) -> Option<(&Eth, &Ipv4, &Tcp)> {
    h.as_view::<(&Eth, &Ipv4, &Tcp)>().map(Look::look)
}

#[inline(never)]
#[unsafe(no_mangle)]
pub fn probe_v4_udp(h: &Headers) -> Option<(&Eth, &Ipv4, &Udp)> {
    h.as_view::<(&Eth, &Ipv4, &Udp)>().map(Look::look)
}

#[inline(never)]
#[unsafe(no_mangle)]
pub fn probe_v6_tcp(h: &Headers) -> Option<(&Eth, &Ipv6, &Tcp)> {
    h.as_view::<(&Eth, &Ipv6, &Tcp)>().map(Look::look)
}

#[inline(never)]
#[unsafe(no_mangle)]
pub fn probe_v4_icmp(h: &Headers) -> Option<(&Eth, &Ipv4, &Icmp4)> {
    h.as_view::<(&Eth, &Ipv4, &Icmp4)>().map(Look::look)
}

#[inline(never)]
#[unsafe(no_mangle)]
pub fn probe_v6_icmp(h: &Headers) -> Option<(&Eth, &Ipv6, &Icmp6)> {
    h.as_view::<(&Eth, &Ipv6, &Icmp6)>().map(Look::look)
}

#[inline(never)]
#[unsafe(no_mangle)]
pub fn probe_vlan_v4_tcp(h: &Headers) -> Option<(&Eth, &Vlan, &Ipv4, &Tcp)> {
    h.as_view::<(&Eth, &Vlan, &Ipv4, &Tcp)>().map(Look::look)
}

#[inline(never)]
#[unsafe(no_mangle)]
pub fn probe_v6_hbh_tcp(h: &Headers) -> Option<(&Eth, &Ipv6, &HopByHop, &Tcp)> {
    h.as_view::<(&Eth, &Ipv6, &HopByHop, &Tcp)>()
        .map(Look::look)
}

#[inline(never)]
#[unsafe(no_mangle)]
pub fn probe_v6_hbh_do_tcp(h: &Headers) -> Option<(&Eth, &Ipv6, &HopByHop, &DestOpts, &Tcp)> {
    h.as_view::<(&Eth, &Ipv6, &HopByHop, &DestOpts, &Tcp)>()
        .map(Look::look)
}

// Separate probe: matches-only path (no look), to compare overhead of
// look() vs pure presence-check.
#[inline(never)]
#[unsafe(no_mangle)]
pub fn probe_v4_tcp_matches_only(h: &Headers) -> bool {
    h.as_view::<(&Eth, &Ipv4, &Tcp)>().is_some()
}

// look() on an already-proven HeadersView: should compile to pure offset
// arithmetic with NO branches (the shape invariant was proved at
// `as_view` time, so no runtime check should remain).
#[inline(never)]
#[unsafe(no_mangle)]
pub fn probe_existing_view<'a>(
    w: &'a HeadersView<(&Eth, &Ipv4, &Tcp)>,
) -> (&'a Eth, &'a Ipv4, &'a Tcp) {
    w.look()
}

fn main() {
    // Touch every probe so it cannot be dead-code-eliminated.  The
    // probes themselves read only the heap-allocated Headers, so this
    // main body is trivial.
    let h = Headers::default();
    std::hint::black_box(probe_v4_tcp(&h));
    std::hint::black_box(probe_v4_udp(&h));
    std::hint::black_box(probe_v6_tcp(&h));
    std::hint::black_box(probe_v4_icmp(&h));
    std::hint::black_box(probe_v6_icmp(&h));
    std::hint::black_box(probe_vlan_v4_tcp(&h));
    std::hint::black_box(probe_v6_hbh_tcp(&h));
    std::hint::black_box(probe_v6_hbh_do_tcp(&h));
    std::hint::black_box(probe_v4_tcp_matches_only(&h));
    // `probe_existing_view` takes a `&HeadersView` (not `&Headers`), so
    // rather than constructing one we touch the function pointer
    // itself -- enough to keep the symbol alive for asm inspection.
    std::hint::black_box(probe_existing_view as fn(_) -> _);
}
