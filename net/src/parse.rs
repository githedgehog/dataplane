// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Packet parsing traits
#![allow(missing_docs)] // temporary allowance (block merge)

use std::num::NonZero;

use tracing::trace;

pub trait Parse: Sized {
    type Error: core::error::Error;
    /// Parse from a buffer.
    ///
    /// # Errors
    ///
    /// Returns an error in the event that parsing fails.
    fn parse(buf: &[u8]) -> Result<(Self, NonZero<u16>), ParseError<Self::Error>>;
}

pub trait DeParse {
    type Error;

    fn size(&self) -> NonZero<u16>;
    /// Write a data structure (e.g., a packet header) to a buffer.
    ///
    /// Returns the number of bytes written in the event of success.
    ///
    /// # Errors
    ///
    /// Will return an error if there is not enough space in the buffer
    /// or if serialization fails from some other (implementation-dependent) reason.
    fn deparse(&self, buf: &mut [u8]) -> Result<NonZero<u16>, DeParseError<Self::Error>>;
}

pub trait ParseWith {
    type Error: core::error::Error;
    type Param;
    /// This function is spiritually similar to [`Parse::parse`] but is used in cases
    /// where parsing must be parameterized.
    ///
    /// # Errors
    ///
    /// Will return an error if parsing fails.
    fn parse_with(
        param: Self::Param,
        raw: &[u8],
    ) -> Result<(Self, NonZero<u16>), ParseError<Self::Error>>
    where
        Self: Sized;
}

pub trait ParseHeader {
    fn parse_header<T: Parse, O: From<T>>(&mut self) -> Option<O>;
    fn parse_header_with<T: ParseWith, O: From<T>>(&mut self, param: T::Param) -> Option<O>;
}

impl ParseHeader for Reader<'_> {
    fn parse_header<T: Parse, O: From<T>>(&mut self) -> Option<O> {
        self.parse::<T>()
            .map_err(|e| {
                trace!("failed to parse {}: {e:?}", core::any::type_name::<T>());
            })
            .map(|v| O::from(v.0))
            .ok()
    }
    fn parse_header_with<T: ParseWith, O: From<T>>(&mut self, param: T::Param) -> Option<O> {
        self.parse_with::<T>(param)
            .map_err(|e| {
                trace!("failed to parse {}: {e:?}", core::any::type_name::<T>());
            })
            .map(|v| O::from(v.0))
            .ok()
    }
}

// Trait ParseHeader above requires its second generic parameter to implement From<T>, leading in
// many implementations of the From trait for the multiple variants of enum objects. Let's make it
// less verbose with a dedicated macro. Usage:
//
//     // Let's consider an enum:
//     enum Foo {
//         Bar(Bar),
//         Baz(Foobarbaz),
//     }
//
//     // Calling the macro such as this:
//     impl_from_for_enum!(Foo, Bar(Bar), Baz(Foobarbaz));
//
//     // ... comes down to implementing all of the following:
//     impl From<Bar> for Foo {
//         fn from(value: Bar) -> Self {
//             Foo::Bar(value)
//         }
//     }
//     impl From<Foobarbaz> for Foo {
//         fn from(value: Foobarbaz) -> Self {
//             Foo::Baz(value)
//         }
//     }
#[macro_export]
macro_rules! impl_from_for_enum {
    ($target:ty, $($variant:ident($ty:ty)),* $(,)?) => {
        $(
            impl From<$ty> for $target {
                fn from(value: $ty) -> Self {
                    <$target>::$variant(value)
                }
            }

        )*
    };
}

#[derive(thiserror::Error, Debug)]
#[error("Maximum legal packet buffer size is 2^16 (requested {0})")]
pub struct IllegalBufferLength(pub usize);

#[derive(thiserror::Error, Debug)]
#[error("expected at least {expected} bytes, got {actual}")]
pub struct LengthError {
    pub(crate) expected: NonZero<usize>,
    pub(crate) actual: usize,
}

#[derive(Debug)]
pub(crate) struct Reader<'buf> {
    pub(crate) inner: &'buf [u8],
    pub(crate) remaining: u16,
}

#[derive(Debug)]
pub(crate) struct Writer<'buf> {
    pub(crate) inner: &'buf mut [u8],
    pub(crate) remaining: u16,
}

impl Reader<'_> {
    pub(crate) fn new(buf: &[u8]) -> Result<Reader<'_>, IllegalBufferLength> {
        if buf.len() > u16::MAX as usize {
            return Err(IllegalBufferLength(buf.len()));
        }
        Ok(Reader {
            inner: buf,
            #[allow(clippy::cast_possible_truncation)] // checked above
            remaining: buf.len() as u16,
        })
    }

    pub(crate) fn consume(&mut self, n: NonZero<u16>) -> Result<(), LengthError> {
        if n.get() > self.remaining {
            return Err(LengthError {
                expected: n.into_non_zero_usize(),
                actual: self.remaining as usize,
            });
        }
        self.remaining -= n.get();
        Ok(())
    }

    pub(crate) fn parse<T: Parse>(&mut self) -> Result<(T, NonZero<usize>), ParseError<T::Error>> {
        let current = self.inner.len() - self.remaining as usize;
        let (value, len_consumed) = T::parse(&self.inner[current..])?;
        match self.consume(len_consumed) {
            Ok(()) => Ok((value, len_consumed.into_non_zero_usize())),
            Err(e) => Err(ParseError::Length(e)),
        }
    }

    pub(crate) fn parse_with<T: ParseWith>(
        &mut self,
        param: <T as ParseWith>::Param,
    ) -> Result<(T, NonZero<usize>), ParseError<T::Error>> {
        let current = self.inner.len() - self.remaining as usize;
        let (value, len_consumed) = T::parse_with(param, &self.inner[current..])?;
        match self.consume(len_consumed) {
            Ok(()) => Ok((value, len_consumed.into_non_zero_usize())),
            Err(e) => Err(ParseError::Length(e)),
        }
    }
}

impl Writer<'_> {
    pub(crate) fn new(buf: &mut [u8]) -> Result<Writer<'_>, IllegalBufferLength> {
        if buf.len() > u16::MAX as usize {
            return Err(IllegalBufferLength(buf.len()));
        }
        #[allow(clippy::cast_possible_truncation)] // checked above
        let len = buf.len() as u16;
        Ok(Writer {
            inner: buf,
            remaining: len,
        })
    }

    fn consume(&mut self, n: NonZero<u16>) -> Result<(), LengthError> {
        if n.get() > self.remaining {
            return Err(LengthError {
                expected: n.into_non_zero_usize(),
                actual: self.remaining as usize,
            });
        }
        self.remaining -= n.get();
        Ok(())
    }

    pub(crate) fn write<T: DeParse>(
        &mut self,
        val: &T,
    ) -> Result<NonZero<u16>, DeParseError<T::Error>> {
        let current = self.inner.len() - self.remaining as usize;
        let consumed = val.deparse(&mut self.inner[current..])?;
        self.consume(consumed).map_err(DeParseError::Length)?;
        Ok(consumed)
    }
}

#[derive(thiserror::Error, Debug)]
pub enum ParseError<E: core::error::Error> {
    #[error("Deserialization buffer longer than 2^16 bytes ({0} bytes given)")]
    BufferTooLong(usize),
    #[error(transparent)]
    Length(LengthError),
    #[error(transparent)]
    Invalid(E),
}

#[derive(thiserror::Error, Debug)]
pub enum DeParseError<E> {
    #[error("Deserialization buffer longer than 2^16 bytes ({0} bytes given)")]
    BufferTooLong(usize),
    #[error(transparent)]
    Length(LengthError),
    #[error(transparent)]
    Invalid(E),
}

pub trait IntoNonZeroUSize {
    fn into_non_zero_usize(self) -> NonZero<usize>;
}

impl IntoNonZeroUSize for NonZero<u16> {
    fn into_non_zero_usize(self) -> NonZero<usize> {
        #[allow(unsafe_code)] // trivially sound since input is already non-zero
        unsafe {
            NonZero::new_unchecked(self.get() as usize)
        }
    }
}
