// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! SFF-8472 (SFP) memory; not decoded yet.

use crate::capture::DecodeError;
use crate::memory::Bytes;
use crate::memory::{I2cAddress, Image, Region};
use crate::module::Module;
use crate::sff8024::Identifier;

/// What only this memory map says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Detail {}

pub(crate) fn wanted(_image: &Image) -> Vec<Region> {
    vec![]
}

pub(crate) fn live(_image: &Image) -> Vec<Region> {
    vec![Region::Lower(I2cAddress::A0)]
}

pub(crate) fn decode(image: &Image) -> Result<Module, DecodeError> {
    let lower = image
        .lower(I2cAddress::A0)
        .ok_or(DecodeError::Missing(Region::Lower(I2cAddress::A0)))?;
    Err(DecodeError::Unsupported(Identifier::from_raw(lower.u8(0))))
}
