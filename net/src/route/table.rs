// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Display, Formatter};
use std::num::{NonZero, TryFromIntError};

/// A numeric id for route table.
///
/// Any `NonZero<u32>` is valid.
/// This type exists only to provide "units"
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
#[repr(transparent)]
pub struct RouteTableId(NonZero<u32>);

impl Debug for RouteTableId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

impl TryFrom<u32> for RouteTableId {
    type Error = TryFromIntError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        Ok(RouteTableId(NonZero::try_from(value)?))
    }
}

impl From<RouteTableId> for u32 {
    fn from(value: RouteTableId) -> Self {
        value.0.into()
    }
}

impl Display for RouteTableId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(any(test, feature = "arbitrary"))]
mod contracts {
    use crate::route::RouteTableId;
    use bolero::{Driver, TypeGenerator};

    impl TypeGenerator for RouteTableId {
        fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
            Some(Self(driver.produce()?))
        }
    }
}
