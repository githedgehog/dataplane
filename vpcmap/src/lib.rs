// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! A library to keep generic Vpc mappings and pairs of mappings.
//! This crate contains two types of tables allowing to store arbitrary data
//! for a VPC discriminant or a pair of them. A Vpc discriminant is a value
//! that allows associating a packet to a VPC. In the simplest case, it is a
//! VxLAN Vni, but it could be an MPLS label, the id of a sub-interface or
//! some packet meta-data.

#![deny(clippy::all, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use net::vxlan::Vni;
use serde::Serialize;
use std::fmt::Display;
use thiserror::Error;

/// A dataplane-level discriminant to identify (traffic pertaining to) a Vpc
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, Ord, PartialOrd, Serialize)]
#[cfg_attr(any(test, feature = "bolero"), derive(bolero::TypeGenerator))]
pub enum VpcDiscriminant {
    VNI(Vni),
}

impl AsRef<VpcDiscriminant> for VpcDiscriminant {
    fn as_ref(&self) -> &VpcDiscriminant {
        self
    }
}

impl VpcDiscriminant {
    pub fn from_vni(vni: Vni) -> Self {
        Self::VNI(vni)
    }
}

impl From<Vni> for VpcDiscriminant {
    fn from(vni: Vni) -> Self {
        Self::VNI(vni)
    }
}
impl Display for VpcDiscriminant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VpcDiscriminant::VNI(vni) => vni.fmt(f),
        }
    }
}

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
