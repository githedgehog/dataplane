// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! TCP options collection type.

use crate::tcp::option::{TcpOption, TcpOptionParseError};

/// TCP header options.
///
/// Wraps [`etherparse::TcpOptions`] and provides an iterator over typed
/// [`TcpOption`] elements.
///
// TODO: implement Parse/DeParse for standalone options parsing/serialization
// TODO: add mutation API (add/remove/modify individual options)
// TODO: add construction from a list of TcpOption values
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TcpOptions(pub(in crate::tcp) etherparse::TcpOptions);

impl TcpOptions {
    /// Maximum number of bytes that can be stored in TCP options.
    pub const MAX_LEN: usize = 40;

    /// Returns the options as a byte slice, or `None` if empty.
    #[must_use]
    pub fn as_bytes(&self) -> Option<&[u8]> {
        if self.0.is_empty() {
            return None;
        }
        Some(self.0.as_slice())
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

    /// Iterate over the individual [`TcpOption`] elements.
    #[must_use]
    pub fn iter(&self) -> TcpOptionIter<'_> {
        TcpOptionIter {
            inner: self.0.elements_iter(),
        }
    }
}

/// Iterator over the [`TcpOption`] elements in a [`TcpOptions`].
pub struct TcpOptionIter<'a> {
    inner: etherparse::TcpOptionsIterator<'a>,
}

impl Iterator for TcpOptionIter<'_> {
    type Item = Result<TcpOption, TcpOptionParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(|result| match result {
            Ok(ref element) => TcpOption::from_etherparse(element),
            Err(ref e) => Err(TcpOptionParseError::from_etherparse_read(e)),
        })
    }
}

impl<'a> IntoIterator for &'a TcpOptions {
    type Item = Result<TcpOption, TcpOptionParseError>;
    type IntoIter = TcpOptionIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

#[cfg(any(test, feature = "bolero"))]
mod contract {
    use super::TcpOptions;
    use crate::tcp::option::TcpOption;
    use bolero::{Driver, TypeGenerator};

    impl TypeGenerator for TcpOptions {
        fn generate<D: Driver>(u: &mut D) -> Option<Self> {
            let num_options = u.produce::<u8>()? % 11;
            let mut elements = Vec::new();
            let mut remaining = TcpOptions::MAX_LEN;

            for _ in 0..num_options {
                let option: TcpOption = u.produce()?;
                let size = option.wire_size();
                if remaining >= size {
                    remaining -= size;
                    elements.push(option.to_etherparse());
                }
            }

            let inner = if elements.is_empty() {
                etherparse::TcpOptions::default()
            } else {
                // Size tracking mirrors try_from_elements exactly, so this cannot fail.
                etherparse::TcpOptions::try_from_elements(&elements)
                    .unwrap_or_else(|_| unreachable!())
            };

            Some(TcpOptions(inner))
        }
    }
}

