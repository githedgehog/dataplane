// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Code tables shared by every memory map, from SFF-8024 (rev 4.14).

use core::fmt;

/// What kind of module this is, and so which memory map it uses (SFF-8024 Table 4-1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Identifier(u8);

/// The memory maps this crate decodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MemoryMap {
    /// SFF-8472: SFP and its descendants.
    Sff8472,
    /// SFF-8636 (and the older SFF-8436): QSFP+ and QSFP28.
    Sff8636,
    /// CMIS: QSFP-DD, OSFP, and QSFP112 and later.
    Cmis,
}

impl Identifier {
    /// An identifier from its code.
    #[must_use]
    pub const fn from_raw(raw: u8) -> Self {
        Self(raw)
    }

    /// The code.
    #[must_use]
    pub const fn raw(self) -> u8 {
        self.0
    }

    /// The memory map a module with this identifier uses, if this crate decodes it.
    #[must_use]
    pub const fn memory_map(self) -> Option<MemoryMap> {
        match self.0 {
            0x02 | 0x03 => Some(MemoryMap::Sff8472),
            0x0c | 0x0d | 0x11 => Some(MemoryMap::Sff8636),
            0x18 | 0x19 | 0x1e | 0x1f | 0x20 | 0x21 | 0x22 => Some(MemoryMap::Cmis),
            _ => None,
        }
    }

    /// The name SFF-8024 gives the code.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self.0 {
            0x00 => "unknown",
            0x01 => "GBIC",
            0x02 => "soldered",
            0x03 => "SFP",
            0x04 => "300 pin XBI",
            0x05 => "XENPAK",
            0x06 => "XFP",
            0x07 => "XFF",
            0x08 => "XFP-E",
            0x09 => "XPAK",
            0x0a => "X2",
            0x0b => "DWDM-SFP",
            0x0c => "QSFP",
            0x0d => "QSFP+",
            0x0e => "CXP",
            0x0f => "HD4X",
            0x10 => "HD8X",
            0x11 => "QSFP28",
            0x12 => "CXP2",
            0x13 => "CDFP",
            0x14 => "HD4X fanout",
            0x15 => "HD8X fanout",
            0x16 => "CDFP style 3",
            0x17 => "microQSFP",
            0x18 => "QSFP-DD",
            0x19 => "OSFP",
            0x1a => "SFP-DD",
            0x1b => "DSFP",
            0x1c => "x4 MiniLink/OcuLink",
            0x1d => "x8 MiniLink",
            0x1e => "QSFP+ (CMIS)",
            0x1f => "SFP-DD (CMIS)",
            0x20 => "SFP+ (CMIS)",
            0x21 => "OSFP-XD",
            0x22 => "OIF-ELSFP",
            0x23 => "CDFP x4 PCIe",
            0x24 => "CDFP x8 PCIe",
            0x25 => "CDFP x16 PCIe",
            0x26 => "XPO",
            0x27..=0x7f => "reserved",
            0x80..=0xff => "vendor specific",
        }
    }
}

impl fmt::Display for Identifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#04x} ({})", self.0, self.name())
    }
}

/// The media connector (SFF-8024 Table 4-3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Connector(u8);

impl Connector {
    /// A connector from its code.
    #[must_use]
    pub const fn from_raw(raw: u8) -> Self {
        Self(raw)
    }

    /// The code.
    #[must_use]
    pub const fn raw(self) -> u8 {
        self.0
    }

    /// The name SFF-8024 gives the code.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self.0 {
            0x00 => "unknown",
            0x01 => "SC",
            0x02 => "Fibre Channel style 1 copper",
            0x03 => "Fibre Channel style 2 copper",
            0x04 => "BNC/TNC",
            0x05 => "Fibre Channel coax",
            0x06 => "Fiber Jack",
            0x07 => "LC",
            0x08 => "MT-RJ",
            0x09 => "MU",
            0x0a => "SG",
            0x0b => "optical pigtail",
            0x0c => "MPO 1x12",
            0x0d => "MPO 2x16",
            0x20 => "HSSDC II",
            0x21 => "copper pigtail",
            0x22 => "RJ45",
            0x23 => "no separable connector",
            0x24 => "MXC 2x16",
            0x25 => "CS optical",
            0x26 => "SN optical",
            0x27 => "MPO 2x12",
            0x28 => "MPO 1x16",
            0x80..=0xff => "vendor specific",
            _ => "reserved",
        }
    }
}

impl fmt::Display for Connector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#04x} ({})", self.0, self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_identifier_has_a_name() {
        bolero::check!().with_type::<u8>().for_each(|raw| {
            assert_ne!(Identifier::from_raw(*raw).name(), "");
            assert_ne!(Connector::from_raw(*raw).name(), "");
        });
    }
}
