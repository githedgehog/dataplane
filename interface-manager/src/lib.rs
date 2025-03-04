//! Network interface management tools for the dataplane

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

mod interface;
mod name;

pub use interface::*;
pub use name::*;
