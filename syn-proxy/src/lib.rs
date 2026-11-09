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

pub mod cookie;
