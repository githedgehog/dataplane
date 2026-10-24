// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! NAT port: a type to represent L4 ports usable in stateful NAT. It lives in `net`, with the NAT
//! state flows carry.

pub use net::flows::nat_state::{NatPort, NatPortError};
