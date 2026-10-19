// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! The quantities a module monitors, kept in the fixed-point units the memory maps encode them in.
//!
//! SFF-8472, SFF-8636 and CMIS agree on these encodings, so a raw monitor value never needs
//! converting until something displays it, and two readings compare exactly.

use core::fmt;

/// A temperature in 1/256 degrees Celsius, two's complement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Temperature(i16);

impl Temperature {
    /// A temperature from its raw encoding.
    #[must_use]
    pub const fn from_raw(raw: i16) -> Self {
        Self(raw)
    }

    /// The raw encoding, in 1/256 degrees Celsius.
    #[must_use]
    pub const fn raw(self) -> i16 {
        self.0
    }

    /// The temperature in degrees Celsius.
    #[must_use]
    pub fn celsius(self) -> f64 {
        f64::from(self.0) / 256.0
    }
}

impl fmt::Display for Temperature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:.2} C", self.celsius())
    }
}

/// A supply voltage in units of 100 microvolts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Voltage(u16);

impl Voltage {
    /// A voltage from its raw encoding.
    #[must_use]
    pub const fn from_raw(raw: u16) -> Self {
        Self(raw)
    }

    /// The raw encoding, in 100 microvolt units.
    #[must_use]
    pub const fn raw(self) -> u16 {
        self.0
    }

    /// The voltage in volts.
    #[must_use]
    pub fn volts(self) -> f64 {
        f64::from(self.0) / 10_000.0
    }
}

impl fmt::Display for Voltage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:.4} V", self.volts())
    }
}

/// A laser bias current in microamps.
///
/// The memory maps encode bias in 2 microamp units, and CMIS lets a module scale that by a
/// multiplier of 1, 2 or 4, so a `u16` of the raw encoding cannot hold every legal value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Current(u32);

impl Current {
    /// A current from a raw 2 microamp encoding and the multiplier the module advertises.
    #[must_use]
    pub fn from_raw(raw: u16, multiplier: BiasMultiplier) -> Self {
        Self(u32::from(raw) * 2 * multiplier.factor())
    }

    /// A current in microamps.
    #[must_use]
    pub const fn from_microamps(microamps: u32) -> Self {
        Self(microamps)
    }

    /// The current in microamps.
    #[must_use]
    pub const fn microamps(self) -> u32 {
        self.0
    }

    /// The current in milliamps.
    #[must_use]
    pub fn milliamps(self) -> f64 {
        f64::from(self.0) / 1_000.0
    }
}

impl fmt::Display for Current {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:.3} mA", self.milliamps())
    }
}

/// The scale CMIS modules may apply to their bias current monitors (CMIS 5.2 Table 8-47, byte 160).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum BiasMultiplier {
    /// The plain 2 microamp encoding; the only option in SFF-8472 and SFF-8636.
    #[default]
    One,
    /// Each count is 4 microamps.
    Two,
    /// Each count is 8 microamps.
    Four,
}

impl BiasMultiplier {
    /// The factor applied to each count.
    #[must_use]
    pub const fn factor(self) -> u32 {
        match self {
            Self::One => 1,
            Self::Two => 2,
            Self::Four => 4,
        }
    }
}

/// An optical power in units of 0.1 microwatts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Power(u16);

impl Power {
    /// A power from its raw encoding.
    #[must_use]
    pub const fn from_raw(raw: u16) -> Self {
        Self(raw)
    }

    /// The raw encoding, in 0.1 microwatt units.
    #[must_use]
    pub const fn raw(self) -> u16 {
        self.0
    }

    /// The power in milliwatts.
    #[must_use]
    pub fn milliwatts(self) -> f64 {
        f64::from(self.0) / 10_000.0
    }

    /// The power in dBm, or negative infinity when no light is measured.
    #[must_use]
    pub fn dbm(self) -> f64 {
        10.0 * self.milliwatts().log10()
    }
}

impl fmt::Display for Power {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:.4} mW ({:.2} dBm)", self.milliwatts(), self.dbm())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conversions_match_the_specified_resolutions() {
        assert!((Temperature::from_raw(0x2780).celsius() - 39.5).abs() < f64::EPSILON);
        assert!((Temperature::from_raw(-256).celsius() + 1.0).abs() < f64::EPSILON);
        assert!((Voltage::from_raw(32_374).volts() - 3.2374).abs() < 1e-12);
        assert_eq!(
            Current::from_raw(3_427, BiasMultiplier::One).microamps(),
            6_854
        );
        assert_eq!(
            Current::from_raw(3_427, BiasMultiplier::Four).microamps(),
            27_416
        );
        assert!((Power::from_raw(10_000).dbm()).abs() < 1e-12);
        assert!(Power::from_raw(0).dbm().is_infinite());
    }

    #[test]
    fn the_largest_bias_fits() {
        bolero::check!().with_type::<u16>().for_each(|raw| {
            let current = Current::from_raw(*raw, BiasMultiplier::Four);
            assert_eq!(current.microamps(), u32::from(*raw) * 8);
        });
    }
}
