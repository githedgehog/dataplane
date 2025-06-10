// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use super::NatIp;
use std::collections::HashSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
pub enum AllocatorError {
    #[error("reserved port ({0})")]
    ReservedPort(u16),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NatPort(u16);

impl NatPort {
    const MIN: u16 = 1024 + 1;

    fn new_checked(port: u16) -> Result<NatPort, AllocatorError> {
        if port < Self::MIN {
            return Err(AllocatorError::ReservedPort(port));
        }
        Ok(Self(port))
    }

    #[must_use]
    fn as_u16(self) -> u16 {
        self.0
    }
}

pub trait NatPool<I: NatIp> {
    fn allocate(&self) -> Result<(I, NatPort), AllocatorError>;
}

#[derive(Debug, Clone)]
pub struct NatDefaultPool<I: NatIp> {
    ips: HashSet<I>,
    allocated: NatAllocations,
}

impl<I: NatIp> NatPool<I> for NatDefaultPool<I> {
    fn allocate(&self) -> Result<(I, NatPort), AllocatorError> {
        todo!()
    }
}

#[derive(Debug, Clone)]
struct NatAllocations {}
