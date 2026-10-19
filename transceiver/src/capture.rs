// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Deciding what to read from a module, without doing the reading.
//!
//! Which pages exist depends on what earlier pages say, so reading is a conversation: [`Capture`]
//! names the next [`Region`] it wants, the caller reads it however it can (netlink, a DPDK port, a
//! file) and hands the result back, until [`Capture`] wants nothing more.
//! Keeping I/O out lets one decoder serve blocking and async readers alike.

use std::collections::BTreeSet;

use crate::memory::{Block, I2cAddress, Image, Region};
use crate::module::Module;
use crate::sff8024::{Identifier, MemoryMap};
use crate::{cmis, sff8472, sff8636};

/// Why a module's memory could not be decoded.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DecodeError {
    /// A region the decoder cannot do without was not read.
    #[error("module memory region {0:?} was not read")]
    Missing(Region),
    /// The module uses a memory map this crate does not decode.
    #[error("modules with identifier {0} are not supported")]
    Unsupported(Identifier),
}

/// A read of one module's memory in progress.
#[derive(Debug, Clone, Default)]
pub struct Capture {
    image: Image,
    stale: BTreeSet<Region>,
}

impl Capture {
    /// Start reading a module from scratch.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Start re-reading only the regions of a known module whose contents change: monitors and flags.
    ///
    /// This trusts that the module has not been swapped since `image` was read; re-read from scratch
    /// whenever the link or module state says it may have been.
    #[must_use]
    pub fn refresh(image: Image) -> Self {
        let stale = match identify(&image).map(Identifier::memory_map) {
            Some(Some(MemoryMap::Sff8472)) => sff8472::live(&image),
            Some(Some(MemoryMap::Sff8636)) => sff8636::live(&image),
            Some(Some(MemoryMap::Cmis)) => cmis::live(&image),
            Some(None) | None => vec![Region::Lower(I2cAddress::A0)],
        };
        Self {
            image,
            stale: stale.into_iter().collect(),
        }
    }

    /// The next region to read, or [`None`] when there is nothing more to ask for.
    #[must_use]
    pub fn next_region(&self) -> Option<Region> {
        if let Some(region) = self.stale.first() {
            return Some(*region);
        }
        let lower = Region::Lower(I2cAddress::A0);
        if !self.image.attempted(lower) {
            return Some(lower);
        }
        let wanted = match identify(&self.image)?.memory_map()? {
            MemoryMap::Sff8472 => sff8472::wanted(&self.image),
            MemoryMap::Sff8636 => sff8636::wanted(&self.image),
            MemoryMap::Cmis => cmis::wanted(&self.image),
        };
        wanted
            .into_iter()
            .find(|region| !self.image.attempted(*region))
    }

    /// Hand over the contents of a region.
    pub fn provide(&mut self, region: Region, block: Block) {
        self.stale.remove(&region);
        self.image.insert(region, block);
    }

    /// Report that a region could not be read.
    pub fn unreadable(&mut self, region: Region) {
        self.stale.remove(&region);
        self.image.mark_unreadable(region);
    }

    /// The memory read so far.
    #[must_use]
    pub fn image(&self) -> &Image {
        &self.image
    }

    /// Decode what was read.
    ///
    /// The [`Image`] comes back so it can seed a later [`Capture::refresh`].
    ///
    /// # Errors
    ///
    /// Fails if the module's memory map is not supported, or a region it cannot do without was not
    /// read.
    pub fn finish(self) -> Result<(Module, Image), DecodeError> {
        let module = decode(&self.image)?;
        Ok((module, self.image))
    }
}

/// Decode a module from memory already read.
///
/// # Errors
///
/// Fails if the module's memory map is not supported, or a region it cannot do without is absent.
pub fn decode(image: &Image) -> Result<Module, DecodeError> {
    let lower = Region::Lower(I2cAddress::A0);
    let identifier = identify(image).ok_or(DecodeError::Missing(lower))?;
    match identifier.memory_map() {
        Some(MemoryMap::Sff8472) => sff8472::decode(image),
        Some(MemoryMap::Sff8636) => sff8636::decode(image),
        Some(MemoryMap::Cmis) => cmis::decode(image),
        None => Err(DecodeError::Unsupported(identifier)),
    }
}

/// A source of module memory that blocks until each read completes.
pub trait Eeprom {
    /// Why a read failed.
    type Error;

    /// Read one region.
    ///
    /// # Errors
    ///
    /// Whatever stopped the read; the module may be absent, or may not implement the region.
    fn read(&mut self, region: Region) -> Result<Block, Self::Error>;
}

/// Why [`read`] failed.
#[derive(Debug, thiserror::Error)]
pub enum ReadError<E> {
    /// The identifying first half page could not be read, so there is nothing to decode.
    #[error("could not read the module's identity")]
    Identity(#[source] E),
    /// What was read could not be decoded.
    #[error(transparent)]
    Decode(#[from] DecodeError),
}

/// Drive `capture` to completion against a blocking source.
///
/// Regions other than the identifying first half page that fail to read are recorded as unreadable
/// rather than failing the whole read: modules routinely lack optional pages.
///
/// # Errors
///
/// Fails if the module's identity could not be read or the result could not be decoded.
pub fn read<E: Eeprom>(
    eeprom: &mut E,
    mut capture: Capture,
) -> Result<(Module, Image), ReadError<E::Error>> {
    while let Some(region) = capture.next_region() {
        match eeprom.read(region) {
            Ok(block) => capture.provide(region, block),
            Err(error) if region == Region::Lower(I2cAddress::A0) => {
                return Err(ReadError::Identity(error));
            }
            Err(_) => capture.unreadable(region),
        }
    }
    Ok(capture.finish()?)
}

fn identify(image: &Image) -> Option<Identifier> {
    use crate::memory::Bytes;
    image
        .lower(I2cAddress::A0)
        .map(|lower| Identifier::from_raw(lower.u8(0)))
}
