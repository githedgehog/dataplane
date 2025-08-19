// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! A library to keep generic Vpc mappings and pairs of mappings.
//! This crate contains two types of tables allowing to store arbitrary data
//! for a VPC discriminant or a pair of them. A Vpc discriminant is a value
//! that allows associating a packet to a VPC. In the simplest case, it is a
//! VxLAN Vni, but it could be an MPLS label, the id of a sub-interface or
//! some packet meta-data.

#![deny(clippy::all, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use thiserror::Error;

pub use net::packet::VpcDiscriminant;

/// The errors produced by the tables in this module
#[derive(Error, Debug, PartialEq)]
pub enum VpcMapError {
    #[error("An entry for vpc discriminant {0} already exists")]
    EntryExists(VpcDiscriminant),
    #[error("An entry for discriminants ({0},{1}) already exists")]
    PairedEntryExists(VpcDiscriminant, VpcDiscriminant),
    #[error("Invalid paired entry")]
    InvalidInput,
    #[error("Failure to read data")]
    Unavailable,
}

type VpcMapResult<T> = Result<T, VpcMapError>;

pub mod map;
#[cfg(test)]
mod map_test;
pub mod pairmap;
#[cfg(test)]
pub mod pairmap_test;
