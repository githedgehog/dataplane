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
#![allow(clippy::should_panic_without_expect)] // we panic in contract checks with simple unwrap()

pub mod buffer;
pub mod eth;
pub mod headers;
pub mod icmp4;
pub mod icmp6;
pub mod interface;
pub mod ip;
pub mod ip_auth;
pub mod ipv4;
pub mod ipv6;
pub mod packet;
pub mod parse;
pub mod route;
pub mod tcp;
pub mod udp;
pub mod vlan;
pub mod vxlan;

#[cfg(test)]
mod tests {
    use rand::Rng;

    #[test]
    fn im_a_flake() {
        let mut rng = rand::rng();
        assert!(rng.random::<u8>() >= 230, "I'm a flake");
    }

    #[test]
    fn im_also_a_flake() {
        let mut rng = rand::rng();
        assert!(rng.random::<u8>() >= 240, "I'm a flake");
    }
}
