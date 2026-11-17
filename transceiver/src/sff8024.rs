// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Code tables shared by every memory map, from SFF-8024 (rev 4.14).
//!
//! The names of host interfaces, media interfaces and extended compliance codes were checked
//! against the tables in sonic-platform-common, which follow the same revision:
//! <https://github.com/sonic-net/sonic-platform-common/blob/7ff32c1f645b839a6924679bd6f863b12945fa3f/sonic_platform_base/sonic_xcvr/codes/public/sff8024.py>

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

/// The electrical interface between host and module that an application runs (SFF-8024
/// Table 4-5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HostInterface(u8);

impl HostInterface {
    /// A host interface from its code.
    #[must_use]
    pub const fn from_raw(raw: u8) -> Self {
        Self(raw)
    }

    /// The code.
    #[must_use]
    pub const fn raw(self) -> u8 {
        self.0
    }

    /// A short name for the interface, without its clause reference, for the codes describing
    /// Ethernet and InfiniBand.
    #[must_use]
    pub const fn name(self) -> Option<&'static str> {
        Some(match self.0 {
            0x01 => "1000BASE-CX",
            0x02 => "XAUI",
            0x03 => "XFI",
            0x04 => "SFI",
            0x05 => "25GAUI",
            0x06 => "XLAUI",
            0x07 => "XLPPI",
            0x08 => "LAUI-2",
            0x09 => "50GAUI-2",
            0x0a => "50GAUI-1",
            0x0b | 0x41 | 0x42 => "CAUI-4",
            0x0c => "100GAUI-4",
            0x0d => "100GAUI-2",
            0x0e => "200GAUI-8",
            0x0f => "200GAUI-4",
            0x10 => "400GAUI-16",
            0x11 => "400GAUI-8",
            0x13 => "10GBASE-CX4",
            0x14..=0x16 => "25GBASE-CR",
            0x17 => "40GBASE-CR4",
            0x18 => "50GBASE-CR",
            0x19 => "100GBASE-CR10",
            0x1a => "100GBASE-CR4",
            0x1b => "100GBASE-CR2",
            0x1c => "200GBASE-CR4",
            0x1d => "400GBASE-CR8",
            0x1e => "200GBASE-CR1",
            0x1f => "400GBASE-CR2",
            0x2c => "IB SDR",
            0x2d => "IB DDR",
            0x2e => "IB QDR",
            0x2f => "IB FDR",
            0x30 => "IB EDR",
            0x31 => "IB HDR",
            0x32 => "IB NDR",
            0x43..=0x45 => "50GBASE-CR2",
            0x46 => "100GBASE-CR1",
            0x47 => "200GBASE-CR2",
            0x48 => "400GBASE-CR4",
            0x49 => "800G-ETC-CR8",
            0x4b | 0x4c => "100GAUI-1",
            0x4d | 0x4e => "200GAUI-2",
            0x4f | 0x50 => "400GAUI-4",
            0x51 | 0x52 => "800GAUI-8",
            0x57 => "800GBASE-CR4",
            0x58 => "1.6TBASE-CR8",
            0x80 => "200GAUI-1",
            0x81 => "400GAUI-2",
            0x82 => "800GAUI-4",
            0x83 => "1.6TAUI-8",
            0xa0 => "IB XDR",
            _ => return None,
        })
    }

    /// The rate of each lane, in whole Gb/s, rounded down, for the codes [`Self::name`] knows.
    #[must_use]
    pub const fn lane_gbps(self) -> Option<u16> {
        Some(match self.0 {
            0x01 => 1,
            0x02 | 0x13 | 0x2c => 3,
            0x2d => 5,
            0x03 | 0x04 | 0x06 | 0x07 | 0x17 | 0x19 | 0x2e => 10,
            0x2f => 14,
            0x05 | 0x08 | 0x09 | 0x0b | 0x0c | 0x0e | 0x10 | 0x14 | 0x15 | 0x16 | 0x1a | 0x30
            | 0x41 | 0x42 | 0x43 | 0x44 | 0x45 => 25,
            0x0a | 0x0d | 0x0f | 0x11 | 0x18 | 0x1b | 0x1c | 0x1d | 0x31 => 50,
            0x32 | 0x46 | 0x47 | 0x48 | 0x49 | 0x4b | 0x4c | 0x4d | 0x4e | 0x4f | 0x50 | 0x51
            | 0x52 => 100,
            0x1e | 0x1f | 0x57 | 0x58 | 0x80 | 0x81 | 0x82 | 0x83 | 0xa0 => 200,
            _ => return None,
        })
    }
}

/// The media interface code table an application uses, from CMIS 00h:85 (SFF-8024 Table 4-6 to
/// Table 4-10).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MediaType {
    /// Multimode fibre, 850 nm (Table 4-6).
    MultimodeFibre,
    /// Single mode fibre (Table 4-7).
    SingleModeFibre,
    /// Passive or linear active copper cable (Table 4-8).
    PassiveCopper,
    /// Limiting or retimed active cable, copper or optical (Table 4-9).
    ActiveCable,
    /// BASE-T (Table 4-10).
    BaseT,
    /// Undefined or reserved.
    Other(u8),
}

impl MediaType {
    /// A media type from its code.
    #[must_use]
    pub const fn from_raw(raw: u8) -> Self {
        match raw {
            0x01 => Self::MultimodeFibre,
            0x02 => Self::SingleModeFibre,
            0x03 => Self::PassiveCopper,
            0x04 => Self::ActiveCable,
            0x05 => Self::BaseT,
            other => Self::Other(other),
        }
    }
}

/// The interface on the media side that an application runs, whose meaning depends on the
/// [`MediaType`] (SFF-8024 Table 4-6 to Table 4-10).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MediaInterface {
    /// The table the code comes from.
    pub media_type: MediaType,
    /// The code.
    pub code: u8,
}

impl MediaInterface {
    /// A short name for the interface, without its clause reference, if the code is known.
    ///
    /// Cables have no media interface of their own to name: an application on a cable is
    /// described by its host interface.
    #[allow(clippy::too_many_lines)] // a code table
    #[must_use]
    pub const fn name(self) -> Option<&'static str> {
        Some(match self.media_type {
            MediaType::MultimodeFibre => match self.code {
                0x01 => "10GBASE-SW",
                0x02 => "10GBASE-SR",
                0x03 => "25GBASE-SR",
                0x04 => "40GBASE-SR4",
                0x05 => "40GE SWDM4",
                0x06 => "40GE BiDi",
                0x07 => "50GBASE-SR",
                0x08 => "100GBASE-SR10",
                0x09 => "100GBASE-SR4",
                0x0a => "100GE SWDM4",
                0x0b => "100GE BiDi",
                0x0c => "100GBASE-SR2",
                0x0d => "100G-SR",
                0x0e => "200GBASE-SR4",
                0x0f => "400GBASE-SR16",
                0x10 => "400GBASE-SR8",
                0x11 => "400G-SR4",
                0x12 => "800G-SR8",
                0x13 => "8GFC-MM",
                0x14 => "10GFC-MM",
                0x15 => "16GFC-MM",
                0x16 => "32GFC-MM",
                0x17 => "64GFC-MM",
                0x18 => "128GFC-MM4",
                0x19 => "256GFC-MM4",
                0x1a => "400GBASE-SR4.2",
                0x1b => "200G-SR2",
                0x1c => "128GFC-MM",
                0x1d => "100G-VR1",
                0x1e => "200G-VR2",
                0x1f => "400G-VR4",
                0x20 => "800G-VR8",
                0x21 => "800G-VR4.2",
                0x22 => "800G-SR4.2",
                0x23 => "1.6T-VR8.2",
                0x24 => "1.6T-SR8.2",
                _ => return None,
            },
            MediaType::SingleModeFibre => match self.code {
                0x01 => "10GBASE-LW",
                0x02 => "10GBASE-EW",
                0x03 => "10G-ZW",
                0x04 => "10GBASE-LR",
                0x05 => "10GBASE-ER",
                0x06 => "10G-ZR",
                0x07 => "25GBASE-LR",
                0x08 => "25GBASE-ER",
                0x09 => "40GBASE-LR4",
                0x0a => "40GBASE-FR",
                0x0b => "50GBASE-FR",
                0x0c => "50GBASE-LR",
                0x0d => "100GBASE-LR4",
                0x0e => "100GBASE-ER4",
                0x0f => "100G PSM4",
                0x10 => "100G CWDM4",
                0x11 => "100G 4WDM-10",
                0x12 => "100G 4WDM-20",
                0x13 => "100G 4WDM-40",
                0x14 => "100GBASE-DR",
                0x15 => "100G-FR/100GBASE-FR1",
                0x16 => "100G-LR/100GBASE-LR1",
                0x17 => "200GBASE-DR4",
                0x18 => "200GBASE-FR4",
                0x19 => "200GBASE-LR4",
                0x1a => "400GBASE-FR8",
                0x1b => "400GBASE-LR8",
                0x1c => "400GBASE-DR4",
                0x1d => "400G-FR4/400GBASE-FR4",
                0x1e => "400G-LR4-10",
                0x1f => "8GFC-SM",
                0x20 => "10GFC-SM",
                0x21 => "16GFC-SM",
                0x22 => "32GFC-SM",
                0x23 => "64GFC-SM",
                0x24 => "128GFC-PSM4",
                0x26 => "128GFC-CWDM4",
                0x2c => "4I1-9D1F",
                0x2d => "4L1-9C1F",
                0x2e => "4L1-9D1F",
                0x2f => "C4S1-9D1F",
                0x30 => "C4S1-4D1F",
                0x31 => "4I1-4D1F",
                0x32 => "8R1-4D1F",
                0x33 => "8I1-4D1F",
                0x34 => "100G CWDM4-OCP",
                0x35 => "ZR400-OFEC-16QAM-HA",
                0x36 => "ZR400-OFEC-16QAM-HB",
                0x37 => "ZR400-OFEC-8QAM-HA",
                0x38 => "10G-SR",
                0x39 => "10G-LR",
                0x3a => "25G-SR",
                0x3b => "25G-LR",
                0x3c => "10G-LR-BiDi",
                0x3d => "25G-LR-BiDi",
                0x3e => "400ZR, DWDM, amplified",
                0x3f => "400ZR, Single Wavelength, Unamplified",
                0x40 => "50GBASE-ER",
                0x41 => "200GBASE-ER4",
                0x42 => "400GBASE-ER8",
                0x43 => "400GBASE-LR4-6",
                0x44 => "100GBASE-ZR",
                0x45 => "128GFC-SM",
                0x46 => "ZR400-OFEC-16QAM",
                0x47 => "ZR300-OFEC-8QAM",
                0x48 => "ZR200-OFEC-QPSK",
                0x49 => "ZR100-OFEC-QPSK",
                0x4a => "100G-LR1-20",
                0x4b => "100G-ER1-30",
                0x4c => "100G-ER1-40",
                0x4d => "400GBASE-ZR",
                0x4e => "10GBASE-BR",
                0x4f => "25GBASE-BR",
                0x50 => "50GBASE-BR",
                0x51 => "FOIC1.4-DO",
                0x52 => "FOIC2.8-DO",
                0x53 => "FOIC4.8-DO",
                0x54 => "FOIC2.4-DO",
                0x55 => "400GBASE-DR4-2",
                0x56 => "800GBASE-DR8",
                0x57 => "800GBASE-DR8-2",
                0x58 => "ZR400-OFEC-8QAM-HB",
                0x59 => "ZR300-OFEC-8QAM-HA",
                0x5a => "ZR300-OFEC-8QAM-HB",
                0x5b => "ZR200-OFEC-QPSK-HA",
                0x5c => "ZR200-OFEC-QPSK-HB",
                0x5d => "ZR100-OFEC-QPSK-HA",
                0x5e => "ZR100-OFEC-QPSK-HB",
                0x5f => "FLEXO-4-DO-16QAM/FOIC4.8-DO",
                0x60 => "FLEXO-3-DO-8QAM/FOIC3.6-DO",
                0x61 => "FLEXO-2-DO-QPSK/FOIC2.4-DO",
                0x62 => "FLEXO-2-DO-16QAM/FOIC2.8-DO",
                0x63 => "FLEXO-1-DO-QPSK/FOIC1.4-DO",
                0x64 => "FLEXO-4e-DO-QPSK/FOIC4e.4-DO",
                0x65 => "FLEXO-4-DO-QPSK/FOIC4.4-DO",
                0x66 => "FLEXO-8e-DO-16QAM/FOIC8e.8-DO",
                0x67 => "FLEXO-8-DO-16QAM/FOIC8.8-DO",
                0x68 => "FLEXO-8e-DPO-16QAM/FOIC8e.8-DPO",
                0x69 => "FLEXO-8-DPO-16QAM/FOIC8.8-DPO",
                0x6a => "FLEXO-6e-DPO-16QAM/FOIC6e.8-DPO",
                0x6b => "FLEXO-6-DPO-16QAM/FOIC6.8-DPO",
                0x6c => "800ZR-A 150 GHz DWDM",
                0x6d => "800ZR-B 150 GHz DWDM",
                0x6e => "800ZR-C 150 GHz DWDM",
                0x73 => "200GBASE-DR1",
                0x74 => "200GBASE-DR1-2",
                0x75 => "400GBASE-DR2",
                0x76 => "400GBASE-DR2-2",
                0x77 => "800GBASE-DR4",
                0x78 => "800GBASE-DR4-2",
                0x79 => "800GBASE-FR4-500",
                0x7a => "800GBASE-FR4",
                0x7b => "800GBASE-LR4",
                0x7f => "1.6TBASE-DR8",
                0x80 => "1.6TBASE-DR8-2",
                0x8f => "100G-DR1-LPO",
                0x90 => "200G-DR2-LPO",
                0x91 => "400G-DR4-LPO",
                0x92 => "800G-DR8-LPO",
                0x93 => "800G-FR4-LPO",
                _ => return None,
            },
            MediaType::BaseT => match self.code {
                0x01 => "1000BASE-T",
                0x02 => "2.5GBASE-T",
                0x03 => "5GBASE-T",
                0x04 => "10GBASE-T",
                0x05 => "25GBASE-T",
                0x06 => "40GBASE-T",
                0x07 => "50GBASE-T",
                _ => return None,
            },
            MediaType::PassiveCopper | MediaType::ActiveCable | MediaType::Other(_) => {
                return None;
            }
        })
    }
}

/// The extended specification compliance code of SFF modules (SFF-8024 Table 4-4), found in
/// SFF-8472 A0h:36 and SFF-8636 00h:192.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ExtendedCompliance(u8);

impl ExtendedCompliance {
    /// A compliance code from its code.
    #[must_use]
    pub const fn from_raw(raw: u8) -> Self {
        Self(raw)
    }

    /// The code.
    #[must_use]
    pub const fn raw(self) -> u8 {
        self.0
    }

    /// A short name for the medium, for the Ethernet codes.
    ///
    /// Several codes cover both a four-lane and a one-lane variant ("100GBASE-SR4 or
    /// 25GBASE-SR"); `multi_lane` picks the first for QSFP modules and the second for SFP.
    #[must_use]
    pub const fn name(self, multi_lane: bool) -> Option<&'static str> {
        let (multi, single) = match self.0 {
            0x01 | 0x18 => ("100G-AOC", "25G-AOC"),
            0x02 => ("100GBASE-SR4", "25GBASE-SR"),
            0x03 => ("100GBASE-LR4", "25GBASE-LR"),
            0x04 => ("100GBASE-ER4", "25GBASE-ER"),
            0x05 => ("100GBASE-SR10", "100GBASE-SR10"),
            0x06 => ("100GBASE-CWDM4", "100GBASE-CWDM4"),
            0x07 => ("100G-PSM4", "100G-PSM4"),
            0x08 | 0x19 => ("100G-ACC", "25G-ACC"),
            0x0b => ("100GBASE-CR4", "25GBASE-CR"),
            0x0c | 0x0d => ("25GBASE-CR", "25GBASE-CR"),
            0x10 => ("40GBASE-ER4", "40GBASE-ER4"),
            0x11 => ("4x10GBASE-SR", "4x10GBASE-SR"),
            0x12 => ("40G-PSM4", "40G-PSM4"),
            0x16 | 0x1c => ("10GBASE-T", "10GBASE-T"),
            0x17 => ("100G-CLR4", "100G-CLR4"),
            0x1a => ("100GE-DWDM2", "100GE-DWDM2"),
            0x1b => ("100G-1550nm-WDM", "100G-1550nm-WDM"),
            0x1d => ("5GBASE-T", "5GBASE-T"),
            0x1e => ("2.5GBASE-T", "2.5GBASE-T"),
            0x1f => ("40G-SWDM4", "40G-SWDM4"),
            0x20 => ("100G-SWDM4", "100G-SWDM4"),
            0x21 => ("100G-PAM4-BiDi", "100G-PAM4-BiDi"),
            0x22 => ("100G-4WDM-10", "100G-4WDM-10"),
            0x23 => ("100G-4WDM-20", "100G-4WDM-20"),
            0x24 => ("100G-4WDM-40", "100G-4WDM-40"),
            0x25 => ("100GBASE-DR", "100GBASE-DR"),
            0x26 | 0x2a => ("100GBASE-FR1", "100GBASE-FR1"),
            0x27 | 0x2b => ("100GBASE-LR1", "100GBASE-LR1"),
            0x28 => ("100G-SR1", "100G-SR1"),
            0x29 => ("400GBASE-SR4", "100GBASE-SR1"),
            0x30 | 0x32 => ("200G-ACC", "50G-ACC"),
            0x31 | 0x33 => ("200G-AOC", "50G-AOC"),
            0x3f => ("400GBASE-CR4", "100GBASE-CR1"),
            0x40 => ("200GBASE-CR4", "50GBASE-CR"),
            0x41 => ("200GBASE-SR4", "50GBASE-SR"),
            0x42 => ("200GBASE-DR4", "50GBASE-FR"),
            0x43 => ("200GBASE-FR4", "200GBASE-FR4"),
            0x44 => ("200G-PSM4", "200G-PSM4"),
            0x45 => ("50GBASE-LR", "50GBASE-LR"),
            0x46 => ("200GBASE-LR4", "200GBASE-LR4"),
            0x47 => ("400GBASE-DR4", "400GBASE-DR4"),
            0x48 => ("400GBASE-FR4", "400GBASE-FR4"),
            0x49 => ("400GBASE-LR4-6", "400GBASE-LR4-6"),
            0x4b => ("400GBASE-LR4-10", "400GBASE-LR4-10"),
            _ => return None,
        };
        Some(if multi_lane { multi } else { single })
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

    #[test]
    fn every_named_host_interface_has_a_lane_rate() {
        bolero::check!().with_type::<u8>().for_each(|raw| {
            let host = HostInterface::from_raw(*raw);
            assert_eq!(host.name().is_some(), host.lane_gbps().is_some());
        });
    }

    #[test]
    fn interface_names_drop_clause_references() {
        let names = (0..=u8::MAX).flat_map(|code| {
            [
                HostInterface::from_raw(code).name(),
                ExtendedCompliance::from_raw(code).name(true),
                ExtendedCompliance::from_raw(code).name(false),
            ]
            .into_iter()
            .chain((1..=5).map(move |media| {
                MediaInterface {
                    media_type: MediaType::from_raw(media),
                    code,
                }
                .name()
            }))
            .flatten()
        });
        for name in names {
            assert!(!name.contains('('), "{name}");
        }
    }

    #[test]
    fn interfaces_are_named_as_sff_8024_says() {
        assert_eq!(HostInterface::from_raw(0x4f).name(), Some("400GAUI-4"));
        assert_eq!(HostInterface::from_raw(0x4f).lane_gbps(), Some(100));
        assert_eq!(HostInterface::from_raw(0x48).name(), Some("400GBASE-CR4"));
        let vr4 = MediaInterface {
            media_type: MediaType::MultimodeFibre,
            code: 0x1f,
        };
        assert_eq!(vr4.name(), Some("400G-VR4"));
        let dr4 = MediaInterface {
            media_type: MediaType::SingleModeFibre,
            code: 0x1c,
        };
        assert_eq!(dr4.name(), Some("400GBASE-DR4"));
        let sr4 = ExtendedCompliance::from_raw(0x02);
        assert_eq!(sr4.name(true), Some("100GBASE-SR4"));
        assert_eq!(sr4.name(false), Some("25GBASE-SR"));
    }
}
