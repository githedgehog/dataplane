// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use arrayvec::ArrayVec;
use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Display, Formatter, LowerHex};

const SWITCH_ID_MAX_LEN: usize = 32;

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[repr(transparent)]
pub struct SwitchId(ArrayVec<u8, SWITCH_ID_MAX_LEN>);

#[derive(thiserror::Error, Debug)]
pub enum SwitchIdError {
    #[error("SwitchId is empty")]
    Empty,
    #[error("Maximum length of an ESwitchId is 32 bytes, received {0} bytes")]
    InvalidLength(usize),
}

impl SwitchId {
    /// The maximum length of an [`SwitchId`] in bytes
    pub const MAX_LEN: usize = SWITCH_ID_MAX_LEN;

    /// Create a new [`SwitchId`] from a raw byte slice
    ///
    /// # Errors
    ///
    /// Returns an error if the raw byte slice is empty or if it is longer than
    /// [`SwitchId::MAX_LEN`] bytes
    pub fn new(raw: impl AsRef<[u8]>) -> Result<Self, SwitchIdError> {
        let raw = raw.as_ref();
        if raw.is_empty() {
            return Err(SwitchIdError::Empty);
        }
        if raw.len() > Self::MAX_LEN {
            return Err(SwitchIdError::InvalidLength(raw.len()));
        }
        let mut bytes = ArrayVec::default();
        for byte in raw {
            bytes.push(*byte); // safe because we checked the length above
        }
        Ok(Self(bytes))
    }
}

impl LowerHex for SwitchId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let as_str = self
            .0
            .iter()
            .fold(String::with_capacity(self.0.len() * 2), |acc, byte| {
                acc + &format!("{byte:<02x}")
            });
        write!(f, "{as_str}")
    }
}

impl Debug for SwitchId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:x}")
    }
}

impl Display for SwitchId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:x}")
    }
}

#[cfg(any(test, feature = "bolero"))]
mod contract {
    use crate::interface::switch::{SWITCH_ID_MAX_LEN, SwitchId};
    use arrayvec::ArrayVec;
    use bolero::generator::bolero_generator::bounded::BoundedValue;
    use bolero::{Driver, TypeGenerator};
    use std::collections::Bound;

    impl TypeGenerator for SwitchId {
        fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
            let len = usize::gen_bounded(
                driver,
                Bound::Included(&1),
                Bound::Excluded(&SWITCH_ID_MAX_LEN),
            )?;
            let mut bytes = ArrayVec::new();
            for _ in 0..len {
                bytes.push(driver.produce()?);
            }
            Some(SwitchId(bytes))
        }
    }
}
