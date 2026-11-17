// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Reading module memory from a flat image, as older interfaces expose it.
//!
//! The legacy ethtool ioctl (`ETHTOOL_GMODULEEEPROM`), and DPDK's `rte_eth_dev_get_module_eeprom`
//! which mirrors it, do not address memory by page and bank: they return one flat image whose
//! layout depends on the module type. These layouts only cover SFF modules, so CMIS modules,
//! whose banked pages cannot be addressed this way, cannot be read through them.

use crate::capture::Eeprom;
use crate::memory::{Block, HALF, I2cAddress, Region};

/// How a flat image lays out module memory, as the module type the interface reports says.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FlatLayout {
    /// SFF-8079: 256 bytes, A0h only.
    Sff8079,
    /// SFF-8472: 512 bytes, A0h then A2h.
    Sff8472,
    /// SFF-8436 or SFF-8636: the lower half, then the upper half of pages 0, 1, 2 and so on, for
    /// `len` bytes in all (256, or 640 with pages 1 to 3).
    Sff8636 {
        /// The length of the image.
        len: usize,
    },
}

impl FlatLayout {
    /// Where `region` starts in the image, if the image holds it.
    #[must_use]
    pub fn offset(self, region: Region) -> Option<usize> {
        let upper = |page: u8| HALF + HALF * usize::from(page);
        match (self, region) {
            (_, Region::Lower(I2cAddress::A0)) => Some(0),
            (
                FlatLayout::Sff8079 | FlatLayout::Sff8472,
                Region::Upper {
                    address: I2cAddress::A0,
                    bank: 0,
                    page: 0,
                },
            ) => Some(HALF),
            (FlatLayout::Sff8472, Region::Lower(I2cAddress::A2)) => Some(2 * HALF),
            (
                FlatLayout::Sff8472,
                Region::Upper {
                    address: I2cAddress::A2,
                    bank: 0,
                    page: 0,
                },
            ) => Some(3 * HALF),
            (
                FlatLayout::Sff8636 { len },
                Region::Upper {
                    address: I2cAddress::A0,
                    bank: 0,
                    page,
                },
            ) => Some(upper(page)).filter(|offset| offset + HALF <= len),
            _ => None,
        }
    }
}

/// A source of flat module memory, such as DPDK's module EEPROM read.
pub trait FlatEeprom {
    /// Why a read failed.
    type Error;

    /// Fill `buf` with the image's bytes starting at `offset`.
    ///
    /// # Errors
    ///
    /// Whatever stopped the read; the module may be absent.
    fn read_at(&mut self, offset: usize, buf: &mut [u8]) -> Result<(), Self::Error>;
}

/// Why a read from a flat image failed.
#[derive(Debug, thiserror::Error)]
pub enum FlatError<E> {
    /// The image does not hold the region.
    #[error("region {0:?} is not in a flat module image")]
    NotInImage(Region),
    /// The read failed.
    #[error(transparent)]
    Read(E),
}

/// Module memory read from a flat image laid out as `layout`.
#[derive(Debug)]
pub struct Flat<F> {
    source: F,
    layout: FlatLayout,
}

impl<F> Flat<F> {
    /// Read module memory from `source`, laid out as `layout`.
    #[must_use]
    pub fn new(source: F, layout: FlatLayout) -> Self {
        Self { source, layout }
    }
}

impl<F: FlatEeprom> Eeprom for Flat<F> {
    type Error = FlatError<F::Error>;

    fn read(&mut self, region: Region) -> Result<Block, Self::Error> {
        let offset = self
            .layout
            .offset(region)
            .ok_or(FlatError::NotInImage(region))?;
        let mut block = [0; HALF];
        self.source
            .read_at(offset, &mut block)
            .map_err(FlatError::Read)?;
        Ok(block)
    }
}

#[cfg(test)]
mod tests {
    use super::{Flat, FlatEeprom, FlatError, FlatLayout};
    use crate::capture::{Capture, Eeprom, read};
    use crate::memory::{HALF, I2cAddress, Region};

    /// A flat image in memory.
    struct Image(Vec<u8>);

    impl FlatEeprom for Image {
        type Error = ();

        fn read_at(&mut self, offset: usize, buf: &mut [u8]) -> Result<(), ()> {
            let bytes = self.0.get(offset..offset + buf.len()).ok_or(())?;
            buf.copy_from_slice(bytes);
            Ok(())
        }
    }

    #[test]
    fn sff8472_puts_a2_after_a0() {
        let layout = FlatLayout::Sff8472;
        assert_eq!(layout.offset(Region::Lower(I2cAddress::A0)), Some(0));
        assert_eq!(layout.offset(Region::upper(0)), Some(HALF));
        assert_eq!(layout.offset(Region::Lower(I2cAddress::A2)), Some(2 * HALF));
        let a2_upper = Region::Upper {
            address: I2cAddress::A2,
            bank: 0,
            page: 0,
        };
        assert_eq!(layout.offset(a2_upper), Some(3 * HALF));
        assert_eq!(layout.offset(Region::upper(1)), None);
    }

    #[test]
    fn sff8079_has_no_a2() {
        assert_eq!(
            FlatLayout::Sff8079.offset(Region::Lower(I2cAddress::A2)),
            None
        );
    }

    #[test]
    fn sff8636_pages_follow_page_zero_up_to_the_length() {
        let short = FlatLayout::Sff8636 { len: 256 };
        assert_eq!(short.offset(Region::upper(0)), Some(HALF));
        assert_eq!(short.offset(Region::upper(1)), None);
        let long = FlatLayout::Sff8636 { len: 640 };
        assert_eq!(long.offset(Region::upper(3)), Some(4 * HALF));
        assert_eq!(long.offset(Region::upper(4)), None);
        assert_eq!(long.offset(Region::banked(1, 0)), None);
        assert_eq!(long.offset(Region::Lower(I2cAddress::A2)), None);
    }

    #[test]
    fn regions_out_of_the_image_are_refused() {
        let mut flat = Flat::new(Image(vec![0; 256]), FlatLayout::Sff8636 { len: 256 });
        assert!(matches!(
            flat.read(Region::banked(0, 0x11)),
            Err(FlatError::NotInImage(_))
        ));
    }

    /// A flat SFF-8636 image reads like the paged one it was cut from.
    #[test]
    fn a_flat_qsfp_image_decodes() {
        // Read the crate's location at run time, as in tests/fixtures.rs: test archives built in
        // the nix sandbox run on the host, where the build path does not exist.
        let manifest_dir = std::env::var_os("CARGO_MANIFEST_DIR").map_or_else(
            || std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")),
            std::path::PathBuf::from,
        );
        let fixture = |name: &str| {
            std::fs::read(
                manifest_dir
                    .join("tests/fixtures/qsfp28-cwdm4-intel-port0")
                    .join(name),
            )
            .unwrap()
        };
        let mut image = fixture("lower.bin");
        for page in ["page-00.bin", "page-01.bin", "page-02.bin", "page-03.bin"] {
            image.extend(fixture(page));
        }
        let len = image.len();
        let mut flat = Flat::new(Image(image), FlatLayout::Sff8636 { len });
        let (module, _) = read(&mut flat, Capture::new()).unwrap();
        assert_eq!(module.inventory.vendor, "INTEL CORP");
    }
}
