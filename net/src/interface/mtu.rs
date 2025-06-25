// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use linux_raw_sys::if_ether;
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use std::fmt::{Display, Formatter};
use std::num::NonZero;
use std::ops;

/// The MTU of a network interface.
#[derive(Copy, Clone, Debug, Hash, Ord, PartialOrd, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "u32", into = "u32")]
#[repr(transparent)]
pub struct Mtu(NonZero<u32>);

impl Mtu {
    pub(crate) const MIN_U32: u32 = 1280; // 1280 IPv6 minimum MTU
    pub(crate) const MAX_U32: u32 = if_ether::ETH_MAX_MTU;
    pub(crate) const DEFAULT_U32: u32 = 1500;

    /// The minimum legal MTU for an IPv6 interface is 1280 bytes.
    pub const MIN: Mtu = Mtu(NonZero::new(Self::MIN_U32).unwrap());
    /// The max legal MTU is 2^16 - 1 bytes.
    pub const MAX: Mtu = Mtu(NonZero::new(Self::MAX_U32).unwrap());
    /// The typical MTU for an ethernet interface
    pub const DEFAULT: Mtu = Mtu(NonZero::new(Self::DEFAULT_U32).unwrap());

    /// Return the `Mtu` represented as a u32
    #[must_use]
    pub fn to_u32(&self) -> u32 {
        self.0.get()
    }

    /// Return the `Mtu` represented as a u16
    #[must_use]
    pub fn to_u16(&self) -> u16 {
        #[allow(clippy::cast_possible_truncation)] // known to be safe by bounds on type
        {
            self.to_u32() as u16
        }
    }
}

impl Default for Mtu {
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl TryFrom<u32> for Mtu {
    type Error = MtuError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        if !(Self::MIN_U32..=Self::MAX_U32).contains(&value) {
            return Err(MtuError::InvalidMtu(value));
        }
        Ok(Mtu(NonZero::new(value).unwrap_or_else(|| unreachable!())))
    }
}

impl TryFrom<NonZero<u32>> for Mtu {
    type Error = MtuError;

    fn try_from(value: NonZero<u32>) -> Result<Self, Self::Error> {
        TryFrom::try_from(value.get())
    }
}

impl From<Mtu> for u32 {
    fn from(value: Mtu) -> Self {
        value.0.get()
    }
}

impl Display for Mtu {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0.get())
    }
}

impl ops::Add<u32> for Mtu {
    type Output = Result<Mtu, MtuError>;

    fn add(self, rhs: u32) -> Self::Output {
        Mtu::try_from(self.to_u32().saturating_add(rhs))
    }
}

impl ops::Sub<u32> for Mtu {
    type Output = Result<Mtu, MtuError>;

    fn sub(self, rhs: u32) -> Self::Output {
        Mtu::try_from(self.to_u32().saturating_sub(rhs))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, thiserror::Error)]
pub enum MtuError {
    /// The MTU is not within the valid range.
    #[error("mtu {0} is not within the valid range of {min} to {max}", min = Mtu::MIN_U32, max = Mtu::MAX_U32)]
    InvalidMtu(u32),
}

#[cfg(any(test, feature = "bolero"))]
mod contract {
    use crate::interface::Mtu;
    use bolero::{Driver, TypeGenerator};

    impl TypeGenerator for Mtu {
        fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
            let mtu = driver.gen_u32(
                std::ops::Bound::Included(&Mtu::MIN_U32),
                std::ops::Bound::Included(&Mtu::MAX_U32),
            )?;
            Some(Self::try_from(mtu).unwrap_or_else(|_| unreachable!()))
        }
    }
}

#[cfg(test)]
pub mod test {
    use super::*;

    #[test]
    fn mtu_is_constrained() {
        bolero::check!().with_type().for_each(|x: &Mtu| {
            assert!(
                x.to_u32() >= Mtu::MIN_U32,
                "mtu {} is less than minimum {}",
                x.to_u32(),
                Mtu::MIN_U32
            );
            assert!(
                x.to_u32() <= Mtu::MAX_U32,
                "mtu {} is greater than maximum {}",
                x.to_u32(),
                Mtu::MAX_U32
            );
        });
    }

    #[test]
    fn mtu_oob_rejects() {
        assert!(Mtu::try_from(Mtu::MIN_U32 - 1).is_err());
        assert!(Mtu::try_from(Mtu::MAX_U32 + 1).is_err());
    }
}
