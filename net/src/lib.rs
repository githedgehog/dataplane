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

extern crate alloc;
extern crate core;

use core::fmt::Debug;

pub mod eth;
pub mod icmp4;
pub mod icmp6;
pub mod ip;
pub mod ip_auth;
pub mod ipv4;
pub mod ipv6;
pub mod packet;
pub mod parse;
pub mod tcp;
pub mod udp;
pub mod vlan;
pub mod vxlan;

/// Assert that the [`Err`] / [`None`] case is unreachable and unwrap the value.
pub trait AssertErrUnreachable {
    /// The success type.  Usually the [`Ok`] in a [`Result`] or the [`Some`] in an [`Option`].
    type Ok;
    /// Assert that the [`Err`] / [`None`] case is unreachable and unwrap the value.
    ///
    /// This is functionally identical to `unwrap` in that it will cause a panic if your assertion
    /// is incorrect and the [`Err`] / [`None`] case is reached.
    /// It is distinct from [`unwrap`] in that [`unwrap`] only indicates that you wish to panic if
    /// you get an [`Err`] / [`None`] variant.
    /// This method is to be used to indicate that you have considered the conditions which might
    /// leave an [`Err`] / [`None`] and believe they are unreachable.
    ///
    /// [`unwrap`]: Result::unwrap
    fn err_unreachable(self) -> Self::Ok;
}

impl<Ok, Err: Debug> AssertErrUnreachable for Result<Ok, Err> {
    type Ok = Ok;

    fn err_unreachable(self) -> Ok {
        self.unwrap_or_else(|err| unreachable!("{err:?}"))
    }
}

impl<Some> AssertErrUnreachable for Option<Some> {
    type Ok = Some;

    fn err_unreachable(self) -> Some {
        self.unwrap_or_else(|| unreachable!("option is none"))
    }
}

/// Use this error to indicate a return value of unreachable code.
///
/// Note that you should never even be able to construct this value to return it.
///
/// The whole thesis is that it is unreachable :)
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
#[error("Entered unreachable code")]
pub struct UnreachableError;
