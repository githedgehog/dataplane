// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! A library for working with and validating network data

#![deny(
    unsafe_code,
    missing_docs,
    clippy::all,
    clippy::pedantic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]
#![cfg_attr(not(unix), allow(unused))] // for wasm32 builds
#![allow(clippy::should_panic_without_expect)] // we panic in contract checks with simple unwrap()

pub mod addr_parse_error;
pub mod buffer;
pub mod checksum;
pub mod eth;
/// `FixedSize` impls bridging `net` field types into match-action keys.
mod fixed_size;
#[cfg(unix)]
pub mod flows;
pub mod headers;
pub mod icmp4;
pub mod icmp6;
pub mod icmp_any;
pub mod interface;
pub mod ip;
pub mod ip_auth;
pub mod ipv4;
pub mod ipv6;
#[cfg(unix)]
pub mod packet;
pub mod parse;
pub mod pci;
pub mod route;
pub mod tcp;
pub mod tcp_udp;
pub mod udp;
pub mod vlan;
pub mod vxlan;

// re-export
#[cfg(unix)]
pub use flows::flow_key::{self, FlowKey, IcmpProtoKey, IpProtoKey, TcpProtoKey, UdpProtoKey};
