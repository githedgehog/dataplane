// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Human-readable names for the identifiers a [`CaptureRecord`] carries.
//!
//! [`CaptureRecord`]: crate::CaptureRecord

use net::interface::InterfaceIndex;
use net::packet::VpcDiscriminant;
use std::collections::HashMap;
use std::fmt::{Display, Formatter};

/// Names for interfaces and VPCs, looked up on the capture writer's thread and never on a worker.
///
/// Packets identify interfaces by [`InterfaceIndex`], which is currently a kernel ifindex.
/// That number means nothing to someone reading a capture, and nothing at all once a device is unbound
/// from the kernel, so a capture shows interfaces only by the names given here.
///
/// Packets identify VPCs by [`VpcDiscriminant`], which is a VNI.
/// A VNI is not a VPC (the two are 1:1 today, but that is not a rule), so a capture reports the VNI as a
/// VNI and adds a VPC name only where one is given here.
#[derive(Debug, Default, Clone)]
pub struct CaptureNames {
    interfaces: HashMap<InterfaceIndex, String>,
    vpcs: HashMap<VpcDiscriminant, String>,
}

impl CaptureNames {
    /// Name the interface `index`.
    #[must_use]
    pub fn with_interface(mut self, index: InterfaceIndex, name: impl Into<String>) -> Self {
        self.interfaces.insert(index, name.into());
        self
    }

    /// Name the VPC that `vpcd` identifies.
    #[must_use]
    pub fn with_vpc(mut self, vpcd: VpcDiscriminant, name: impl Into<String>) -> Self {
        self.vpcs.insert(vpcd, name.into());
        self
    }

    /// The name to show for `index`.
    pub(crate) fn interface(&self, index: InterfaceIndex) -> InterfaceDisplay<'_> {
        match self.interfaces.get(&index) {
            Some(name) => InterfaceDisplay::Named(name),
            None => InterfaceDisplay::Unnamed(index),
        }
    }

    /// The name of the VPC `vpcd` identifies, if known.
    pub(crate) fn vpc(&self, vpcd: VpcDiscriminant) -> Option<&str> {
        self.vpcs.get(&vpcd).map(String::as_str)
    }
}

/// How an interface appears in a capture.
pub(crate) enum InterfaceDisplay<'a> {
    Named(&'a str),
    /// An interface nobody named, which is a gap in the caller's [`CaptureNames`].
    /// The index is the only thing that distinguishes it from other unnamed interfaces.
    Unnamed(InterfaceIndex),
}

impl Display for InterfaceDisplay<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            InterfaceDisplay::Named(name) => f.write_str(name),
            InterfaceDisplay::Unnamed(index) => write!(f, "unnamed({index})"),
        }
    }
}
