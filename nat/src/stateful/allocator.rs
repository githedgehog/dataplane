// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use super::NatIp;
use super::port::{NatPort, NatPortError};
use std::collections::HashSet;
use std::fmt::Debug;

pub trait NatPool<I: NatIp> {
    fn allocate(&self) -> Result<(I, I, Option<NatPort>, Option<NatPort>), NatPortError>;
}

#[derive(Debug, Clone)]
pub struct NatDefaultPool<I: NatIp> {
    ips: HashSet<I>,
    allocated: NatAllocations,
}

impl<I: NatIp> NatPool<I> for NatDefaultPool<I> {
    fn allocate(&self) -> Result<(I, I, Option<NatPort>, Option<NatPort>), NatPortError> {
        todo!()
    }
}

#[derive(Debug, Clone)]
struct NatAllocations {}
