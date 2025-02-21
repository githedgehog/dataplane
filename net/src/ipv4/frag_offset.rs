// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors
//

//! IP fragmentation offset

use etherparse::IpFragOffset;

/// A 13-bit number which describes the position of the packet payload relative to the
/// original (fragmented) payload
#[repr(transparent)]
#[derive(Copy, Clone, Default, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct FragOffset(pub(crate) IpFragOffset);

/// Errors which can occur when creating a [`FragOffset`]
#[derive(Debug, thiserror::Error)]
pub enum IllegalFragOffset {
    /// Error returned when the value won't fit in a 13-bit field
    #[error("Value too large for 13-bit frag-offset: {0:?}")]
    TooBig(u16),
}

impl FragOffset {
    /// The maximum possible [`FragOffset`]
    pub const MIN: FragOffset = FragOffset(IpFragOffset::ZERO);

    /// The maximum possible [`FragOffset`]
    #[allow(unsafe_code)] // trivially safe const-eval
    pub const MAX: FragOffset =
        FragOffset(unsafe { IpFragOffset::new_unchecked(IpFragOffset::MAX_U16) });

    /// Map a raw 16-bit value to an [`FragOffset`]
    ///
    /// # Errors
    ///
    /// Returns an [`IllegalFragOffset`] if the value is not valid (i.e., if the value is larger
    /// than 13-bits)
    pub fn new(raw: u16) -> Result<FragOffset, IllegalFragOffset> {
        Ok(FragOffset(
            IpFragOffset::try_new(raw).map_err(|e| IllegalFragOffset::TooBig(e.actual))?,
        ))
    }
}

#[cfg(any(test, feature = "arbitrary"))]
mod contract {
    use crate::ipv4::frag_offset::FragOffset;
    use bolero::{Driver, TypeGenerator};

    impl TypeGenerator for FragOffset {
        fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
            Some(
                FragOffset::new(driver.r#gen::<u16>()? & FragOffset::MAX.0.value())
                    .unwrap_or_else(|e| unreachable!("{e:?}")),
            )
        }
    }
}
