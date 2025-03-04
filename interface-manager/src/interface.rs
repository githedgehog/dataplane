// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! State objects for network interfaces and interface table.

#![allow(missing_docs)] // TEMP(blocking for merge)
#![allow(clippy::missing_errors_doc)] // TEMP(blocking for merge)

use crate::InterfaceName;
use net::eth::mac::SourceMac;
use net::vlan::Vlan;
use std::collections::BTreeSet;
use std::fmt::{Debug, Display, Formatter};
use std::num::NonZero;

/// A network interface id (also known as ifindex in linux).
#[repr(transparent)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "u32", into = "u32"))]
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IfIndex(NonZero<u32>);

impl Debug for IfIndex {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        <_ as Debug>::fmt(&self.0.get(), f)
    }
}

impl Display for IfIndex {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        <_ as Display>::fmt(&self.0.get(), f)
    }
}

#[derive(Debug, thiserror::Error)]
#[error("Zero is not a legal network interface index")]
pub struct ZeroIfIndex;

impl IfIndex {
    #[must_use]
    pub fn new(raw: NonZero<u32>) -> IfIndex {
        IfIndex(raw)
    }

    pub fn try_new(raw: u32) -> Result<IfIndex, ZeroIfIndex> {
        Ok(IfIndex(NonZero::new(raw).ok_or(ZeroIfIndex)?))
    }

    #[must_use]
    pub fn to_u32(self) -> NonZero<u32> {
        self.0
    }
}

impl TryFrom<u32> for IfIndex {
    type Error = ZeroIfIndex;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        IfIndex::try_new(value)
    }
}

impl From<IfIndex> for u32 {
    fn from(value: IfIndex) -> Self {
        value.to_u32().get()
    }
}

pub trait BasicNetworkInterface {
    fn index(&self) -> IfIndex;
    fn name(&self) -> &InterfaceName;
}

pub trait ChildInterface: BasicNetworkInterface {
    fn parent(&self) -> Option<IfIndex>;
}

pub trait ParentInterface {
    fn children(&self) -> &BTreeSet<IfIndex>;
}

pub trait EthernetInterface: BasicNetworkInterface {
    fn mac(&self) -> Option<SourceMac>;
}

/// Fields common to all network interfaces in Linux.
struct NetworkInterfaceCommon {
    index: IfIndex,
    name: InterfaceName,
}

struct EthernetInterfaceCommon {
    common: NetworkInterfaceCommon,
    mac: SourceMac,
    mtu: u16,
}

struct VlanInterfaceCommon {
    ethernet: EthernetInterfaceCommon,
    vlan: Vlan,
}

impl BasicNetworkInterface for NetworkInterfaceCommon {
    fn index(&self) -> IfIndex {
        self.index
    }

    fn name(&self) -> &InterfaceName {
        &self.name
    }
}

impl<T: AsRef<NetworkInterfaceCommon>> BasicNetworkInterface for T {
    fn index(&self) -> IfIndex {
        self.as_ref().index()
    }

    fn name(&self) -> &InterfaceName {
        self.as_ref().name()
    }
}

impl AsRef<NetworkInterfaceCommon> for VlanInterfaceCommon {
    fn as_ref(&self) -> &NetworkInterfaceCommon {
        &self.ethernet.common
    }
}

impl VlanInterfaceCommon {
    fn vlan(&self) -> &Vlan {
        &self.vlan
    }
}

enum NetworkInterfaceInner {
    Eth(EthernetInterfaceCommon),
    Vlan(VlanInterfaceCommon),
}

#[repr(transparent)]
pub struct NetworkInterface(NetworkInterfaceInner);

impl BasicNetworkInterface for NetworkInterface {
    fn index(&self) -> IfIndex {
        match &self.0 {
            NetworkInterfaceInner::Eth(i) => i.common.index,
            NetworkInterfaceInner::Vlan(i) => i.ethernet.common.index,
        }
    }

    fn name(&self) -> &InterfaceName {
        match &self.0 {
            NetworkInterfaceInner::Eth(i) => &i.common.name,
            NetworkInterfaceInner::Vlan(i) => &i.ethernet.common.name,
        }
    }
}
