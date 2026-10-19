// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! How module memory is addressed, and the bytes read from it so far.
//!
//! Every memory map in scope splits a 256 byte window into a lower half, which never pages, and an
//! upper half selected by page (and, in CMIS, bank) number. The kernel's `ETHTOOL_MSG_MODULE_EEPROM_GET`
//! addresses memory the same way, so a [`Region`] is exactly one request to it.

use std::collections::{BTreeMap, BTreeSet};

/// Bytes in one half of a page.
pub const HALF: usize = 128;

/// One half page of module memory.
pub type Block = [u8; HALF];

/// The two-wire serial bus address a region lives behind.
///
/// Only SFF-8472 uses [`I2cAddress::A2`]; SFF-8636 and CMIS page everything behind
/// [`I2cAddress::A0`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum I2cAddress {
    /// Serial ID memory, 8-bit address A0h (7-bit 0x50).
    A0,
    /// SFF-8472 diagnostics, 8-bit address A2h (7-bit 0x51).
    A2,
}

impl I2cAddress {
    /// The 7-bit bus address, as the kernel's netlink interface takes it.
    #[must_use]
    pub const fn seven_bit(self) -> u8 {
        match self {
            Self::A0 => 0x50,
            Self::A2 => 0x51,
        }
    }
}

/// A half page of module memory: the unit read from a module.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Region {
    /// Bytes 0 to 127, the same whatever page is selected.
    Lower(I2cAddress),
    /// Bytes 128 to 255 of one page.
    Upper {
        /// The bus address.
        address: I2cAddress,
        /// The bank; always 0 outside CMIS.
        bank: u8,
        /// The page.
        page: u8,
    },
}

impl Region {
    /// The upper half of page `page` in bank 0 behind A0h.
    #[must_use]
    pub const fn upper(page: u8) -> Self {
        Self::Upper {
            address: I2cAddress::A0,
            bank: 0,
            page,
        }
    }

    /// The upper half of a banked CMIS page behind A0h.
    #[must_use]
    pub const fn banked(bank: u8, page: u8) -> Self {
        Self::Upper {
            address: I2cAddress::A0,
            bank,
            page,
        }
    }

    /// The bus address the region lives behind.
    #[must_use]
    pub const fn address(self) -> I2cAddress {
        match self {
            Self::Lower(address) | Self::Upper { address, .. } => address,
        }
    }

    /// The offset of the region's first byte within the 256 byte window.
    #[must_use]
    pub const fn offset(self) -> u8 {
        match self {
            Self::Lower(_) => 0,
            Self::Upper { .. } => 128,
        }
    }
}

/// The memory read from one module: every region asked for, and the ones that could not be read.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Image {
    blocks: BTreeMap<Region, Block>,
    unreadable: BTreeSet<Region>,
}

impl Image {
    /// An image holding nothing.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a region's contents, replacing any earlier read of it.
    pub fn insert(&mut self, region: Region, block: Block) {
        self.unreadable.remove(&region);
        self.blocks.insert(region, block);
    }

    /// Record that a region could not be read.
    pub fn mark_unreadable(&mut self, region: Region) {
        self.blocks.remove(&region);
        self.unreadable.insert(region);
    }

    /// Whether the region has been asked for, readable or not.
    #[must_use]
    pub fn attempted(&self, region: Region) -> bool {
        self.blocks.contains_key(&region) || self.unreadable.contains(&region)
    }

    /// The contents of a region, if it was read.
    #[must_use]
    pub fn block(&self, region: Region) -> Option<&Block> {
        self.blocks.get(&region)
    }

    /// The regions read, in order.
    pub fn regions(&self) -> impl Iterator<Item = (Region, &Block)> {
        self.blocks.iter().map(|(region, block)| (*region, block))
    }

    /// The regions that could not be read.
    pub fn unreadable(&self) -> impl Iterator<Item = Region> + '_ {
        self.unreadable.iter().copied()
    }

    /// The lower half behind `address`, viewed with spec byte numbering.
    #[must_use]
    pub fn lower(&self, address: I2cAddress) -> Option<Lower<'_>> {
        self.block(Region::Lower(address)).map(Lower)
    }

    /// The upper half of a page, viewed with spec byte numbering.
    #[must_use]
    pub fn upper(&self, region: Region) -> Option<Upper<'_>> {
        match region {
            Region::Lower(_) => None,
            Region::Upper { .. } => self.block(region).map(Upper),
        }
    }
}

/// Reading big-endian fields out of a half page, by the byte numbers the specifications use.
///
/// Offsets are compile-time constants from the specifications, so an offset outside the half is a
/// programmer error and panics.
pub trait Bytes {
    /// The byte at `offset`.
    fn u8(&self, offset: u8) -> u8;

    /// The big-endian 16-bit field starting at `offset`.
    fn u16(&self, offset: u8) -> u16 {
        u16::from_be_bytes([self.u8(offset), self.u8(offset + 1)])
    }

    /// The big-endian signed 16-bit field starting at `offset`.
    fn i16(&self, offset: u8) -> i16 {
        i16::from_be_bytes([self.u8(offset), self.u8(offset + 1)])
    }

    /// The big-endian IEEE 754 single starting at `offset`.
    fn f32(&self, offset: u8) -> f32 {
        f32::from_be_bytes([
            self.u8(offset),
            self.u8(offset + 1),
            self.u8(offset + 2),
            self.u8(offset + 3),
        ])
    }

    /// Bit `bit` of the byte at `offset`.
    fn bit(&self, offset: u8, bit: u8) -> bool {
        self.u8(offset) & (1 << bit) != 0
    }

    /// `len` bytes starting at `offset`.
    fn slice(&self, offset: u8, len: u8) -> Vec<u8> {
        (0..len).map(|i| self.u8(offset + i)).collect()
    }

    /// A space-padded ASCII field, trimmed, with anything unprintable replaced.
    fn text(&self, offset: u8, len: u8) -> String {
        self.slice(offset, len)
            .into_iter()
            .map(|b| {
                if b.is_ascii_graphic() || b == b' ' {
                    char::from(b)
                } else {
                    '\u{fffd}'
                }
            })
            .collect::<String>()
            .trim_end_matches([' ', '\0'])
            .to_owned()
    }
}

/// The lower half of a page: bytes 0 to 127.
#[derive(Debug, Clone, Copy)]
pub struct Lower<'a>(&'a Block);

impl Bytes for Lower<'_> {
    fn u8(&self, offset: u8) -> u8 {
        self.0[usize::from(offset)]
    }
}

/// The upper half of a page: bytes 128 to 255.
#[derive(Debug, Clone, Copy)]
pub struct Upper<'a>(&'a Block);

impl Bytes for Upper<'_> {
    fn u8(&self, offset: u8) -> u8 {
        self.0[usize::from(offset) - HALF]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn views_use_spec_numbering() {
        let mut block = [0u8; HALF];
        block[0] = 0xab;
        block[14] = 0x27;
        block[15] = 0xcb;
        let mut image = Image::new();
        image.insert(Region::Lower(I2cAddress::A0), block);
        image.insert(Region::upper(0), block);
        let lower = image.lower(I2cAddress::A0).unwrap();
        let upper = image.upper(Region::upper(0)).unwrap();
        assert_eq!(lower.u8(0), 0xab);
        assert_eq!(lower.u16(14), 0x27cb);
        assert_eq!(upper.u8(128), 0xab);
        assert_eq!(upper.u16(142), 0x27cb);
    }

    #[test]
    fn text_is_trimmed_and_sanitized() {
        let mut block = [b' '; HALF];
        block[..4].copy_from_slice(b"FS\x01 ");
        let mut image = Image::new();
        image.insert(Region::upper(0), block);
        assert_eq!(
            image.upper(Region::upper(0)).unwrap().text(128, 16),
            "FS\u{fffd}"
        );
    }

    #[test]
    fn a_reread_clears_unreadable() {
        let mut image = Image::new();
        image.mark_unreadable(Region::upper(3));
        assert!(image.attempted(Region::upper(3)));
        image.insert(Region::upper(3), [0; HALF]);
        assert_eq!(image.unreadable().count(), 0);
    }
}
