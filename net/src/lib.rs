#![cfg_attr(not(test), no_std)] // This library should always compile without std (even if we never ship that way)
#![forbid(unsafe_code)] // Validation logic should always be strictly safe
#![deny(missing_docs, clippy::all, clippy::pedantic)] // yeah, I'm that guy.  I'm not sorry.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // Do you know where your towel is?

//! A library for working with and strictly validating network data
 
#[cfg(all(kani, feature = "_fake_kani"))]
compile_error!("kani should not be used with internal _fake_kani feature.");

pub mod vlan;
pub mod vxlan;
