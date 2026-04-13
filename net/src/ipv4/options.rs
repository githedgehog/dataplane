// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! IPv4 options type.

/// IPv4 header options.
///
/// Wraps the raw options byte buffer from the IPv4 header. Options must be
/// a multiple of 4 bytes in length and at most 40 bytes (constrained by
/// the 4-bit IHL field).
///
// TODO: implement Parse/DeParse for standalone options parsing/serialization
// TODO: add typed Ipv4Option enum and iterator (etherparse has no element types)
// TODO: add mutation API (add/remove/modify individual options)
#[repr(transparent)]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Ipv4Options(pub(in crate::ipv4) etherparse::Ipv4Options);

impl Ipv4Options {
    /// Maximum number of bytes that can be stored in IPv4 options.
    pub const MAX_LEN: usize = 40;

    /// Borrow from an inner etherparse options reference.
    ///
    /// # Safety
    ///
    /// Safe because `Ipv4Options` is `#[repr(transparent)]` over
    /// `etherparse::Ipv4Options`.
    #[must_use]
    pub(in crate::ipv4) fn from_inner_ref(inner: &etherparse::Ipv4Options) -> &Self {
        #[allow(unsafe_code)]
        // SAFETY: Ipv4Options is repr(transparent) over etherparse::Ipv4Options.
        unsafe {
            &*std::ptr::from_ref::<etherparse::Ipv4Options>(inner).cast::<Self>()
        }
    }

    /// Returns the options as a byte slice.
    ///
    /// Returns an empty slice if no options are present.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }

    /// Returns true if there are no options.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Number of bytes in the options.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

#[cfg(any(test, feature = "bolero"))]
mod contract {
    use super::Ipv4Options;
    use bolero::{Driver, TypeGenerator};

    impl TypeGenerator for Ipv4Options {
        fn generate<D: Driver>(u: &mut D) -> Option<Self> {
            // IPv4 options must be a multiple of 4 bytes, max 40 bytes.
            // Generate a length: 0, 4, 8, ..., 40 (11 possible values).
            let len = u.produce::<u8>()? % 11 * 4;
            if len == 0 {
                return Some(Ipv4Options(etherparse::Ipv4Options::new()));
            }
            let mut buf = [0u8; 40];
            for byte in buf.iter_mut().take(len as usize) {
                *byte = u.produce()?;
            }
            // etherparse::Ipv4Options requires length to be a multiple of 4.
            // try_from validates this and returns BadOptionsLen on failure.
            let inner = etherparse::Ipv4Options::try_from(&buf[..len as usize])
                .unwrap_or_else(|_| unreachable!());
            Some(Ipv4Options(inner))
        }
    }
}
