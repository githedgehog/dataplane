// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors
//

//! [`Ipv6`] [flow label] type and generation
//!
//! [flow label]: https://www.rfc-editor.org/rfc/rfc6437.html
//! [`Ipv6`]: crate::ipv6::Ipv6

use etherparse::Ipv6FlowLabel;

/// An [`Ipv6`] [flow label]
///
/// [flow label]: https://www.rfc-editor.org/rfc/rfc6437.html
/// [`Ipv6`]: crate::ipv6::Ipv6
#[allow(clippy::unsafe_derive_deserialize)] // safety: no (non-const eval) unsafe code used
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "u32", into = "u32"))]
#[derive(Copy, Clone, Default, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct FlowLabel(pub(crate) Ipv6FlowLabel);

/// Errors which can occur when creating a [`FlowLabel`]
#[derive(Debug, thiserror::Error)]
pub enum FlowLabelError {
    /// The flow label exceeds a 20-bit max
    #[error("flow label {0} is too big (20-bit maximum)")]
    TooBig(u32),
}

impl FlowLabel {
    /// The "minimum" legal [`FlowLabel`]
    pub const MIN: FlowLabel = FlowLabel(Ipv6FlowLabel::ZERO);

    /// The "maximum" legal [`FlowLabel`]
    #[allow(unsafe_code)] // trivially safe const eval
    pub const MAX: FlowLabel =
        FlowLabel(unsafe { Ipv6FlowLabel::new_unchecked(Ipv6FlowLabel::MAX_U32) });

    /// Create a new [`FlowLabel`] from a raw value.
    ///
    /// # Errors
    ///
    /// Returns a [`FlowLabelError`] if the supplied `value` is larger than 20-bit.
    pub fn new(value: u32) -> Result<FlowLabel, FlowLabelError> {
        Ok(FlowLabel(
            Ipv6FlowLabel::try_new(value).map_err(|e| FlowLabelError::TooBig(e.actual))?,
        ))
    }

    /// Get the raw `u32` used to represent this [`FlowLabel`] (native endian)
    #[must_use]
    pub const fn raw(&self) -> u32 {
        self.0.value()
    }
}

impl From<FlowLabel> for u32 {
    fn from(value: FlowLabel) -> Self {
        value.raw()
    }
}

impl TryFrom<u32> for FlowLabel {
    type Error = FlowLabelError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        FlowLabel::new(value)
    }
}

#[cfg(any(test, feature = "arbitrary"))]
mod contract {
    use crate::ipv6::flow_label::FlowLabel;
    use bolero::{Driver, TypeGenerator};

    impl TypeGenerator for FlowLabel {
        fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
            Some(
                FlowLabel::new(driver.r#gen::<u32>()? & FlowLabel::MAX.0.value())
                    .unwrap_or_else(|_| unreachable!()),
            )
        }
    }
}
