//! This is a collection of fake proc macros to aid in writing Kani proofs.
//!
//! The main idea is to get my IDE to calm down about the many kani methods it can't
//! understand.
//!
//! This is done by simply stubbing out all of the kani method calls and replacing them
//! with no-ops.

#![deny(
    clippy::all,
    clippy::pedantic,
    clippy::unwrap_used,
    clippy::expect_used
)]
extern crate proc_macro;

use proc_macro::TokenStream;

#[proc_macro_attribute]
pub fn proof(_args: TokenStream, input: TokenStream) -> TokenStream {
    input
}

#[proc_macro_attribute]
pub fn ensures(_args: TokenStream, input: TokenStream) -> TokenStream {
    input
}

#[proc_macro_attribute]
pub fn requires(_args: TokenStream, input: TokenStream) -> TokenStream {
    input
}

#[proc_macro_attribute]
pub fn stub(_args: TokenStream, input: TokenStream) -> TokenStream {
    input
}

#[proc_macro_attribute]
pub fn stub_verified(_args: TokenStream, input: TokenStream) -> TokenStream {
    input
}

#[proc_macro_attribute]
pub fn proof_for_contract(_args: TokenStream, input: TokenStream) -> TokenStream {
    input
}

#[proc_macro_attribute]
pub fn modifies(_args: TokenStream, input: TokenStream) -> TokenStream {
    input
}
