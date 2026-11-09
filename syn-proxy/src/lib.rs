// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![deny(
    unsafe_code,
    missing_docs,
    clippy::all,
    clippy::pedantic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]
#![cfg_attr(test, allow(clippy::unwrap_used))]

//! A SYN proxy for the TCP connections that go through the gateway.
//!
//! When it is on, the gateway answers the SYNs of clients itself, with a SYN cookie, and keeps no
//! state for them. Only when a client completes the handshake, proving that it owns its address,
//! does the gateway open the connection to the server and create flows for it.
//!
//! The proxy protects the flow table, not the CPU: every SYN and every ACK without a flow still
//! goes through the pipeline, and costs a hash. A flood large enough fills the receive queues
//! whatever the proxy does.
//!
//! While the proxy accepts cookies, the stages after the cookie checker, including the ACL, see
//! the client's ACK that completes the handshake as the SYN it stands for. ACL rules that the NIC
//! enforces see the ACK itself.

mod control;
mod cookie;
mod stage;

#[cfg(test)]
mod tests;

pub use control::{Counters, SynProxyControl, SynProxyMode};
pub use stage::{SynCookieChecker, SynProxy};
