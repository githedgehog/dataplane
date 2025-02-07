// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Packet parsing traits
#![allow(missing_docs)] // temporary allowance (block merge)

use std::num::NonZero;

pub trait Parse: Sized {
    type Error: core::error::Error;
    /// Parse from a buffer.
    ///
    /// # Errors
    ///
    /// Returns an error in the event that parsing fails.
    fn parse(buf: &[u8]) -> Result<(Self, NonZero<usize>), ParseError<Self::Error>>;
}

pub trait DeParse {
    type Error;

    fn size(&self) -> NonZero<usize>;
    /// Write a data structure (e.g., a packet header) to a buffer.
    ///
    /// Returns the number of bytes written in the event of success.
    ///
    /// # Errors
    ///
    /// Will return an error if there is not enough space in the buffer
    /// or if serialization fails from some other (implementation-dependent) reason.
    fn deparse(&self, buf: &mut [u8]) -> Result<NonZero<usize>, DeParseError<Self::Error>>;
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
    ) -> Result<(Self, NonZero<usize>), ParseError<Self::Error>>
    where
        Self: Sized;
}

pub(crate) trait ParsePayload {
    type Next;
    fn parse_payload(&self, cursor: &mut Reader) -> Option<Self::Next>;
}

pub(crate) trait ParsePayloadWith {
    type Param;
    type Next;
    fn parse_payload_with(&self, param: &Self::Param, cursor: &mut Reader) -> Option<Self::Next>;
}

#[derive(thiserror::Error, Debug)]
#[error("expected at least {expected} bytes, got {actual}")]
pub struct LengthError {
    pub(crate) expected: NonZero<usize>,
    pub(crate) actual: usize,
}

#[derive(Debug)]
pub(crate) struct Reader<'buf> {
    pub(crate) inner: &'buf [u8],
    pub(crate) remaining: usize,
}

#[derive(Debug)]
pub(crate) struct Writer<'buf> {
    pub(crate) inner: &'buf mut [u8],
    pub(crate) remaining: usize,
}

impl Reader<'_> {
    pub(crate) fn new(buf: &[u8]) -> Reader {
        Reader {
            inner: buf,
            remaining: buf.len(),
        }
    }

    fn consume(&mut self, n: NonZero<usize>) -> Result<(), LengthError> {
        if n.get() >= self.remaining {
            return Err(LengthError {
                expected: n,
                actual: self.remaining,
            });
        }
        self.remaining -= n.get();
        Ok(())
    }

    pub(crate) fn parse<T: Parse>(&mut self) -> Result<(T, NonZero<usize>), ParseError<T::Error>> {
        let current = self.inner.len() - self.remaining;
        let (value, len_consumed) = T::parse(&self.inner[current..])?;
        match self.consume(len_consumed) {
            Ok(()) => Ok((value, len_consumed)),
            Err(e) => Err(ParseError::Length(e)),
        }
    }

    pub(crate) fn parse_with<T: ParseWith>(
        &mut self,
        param: <T as ParseWith>::Param,
    ) -> Result<(T, NonZero<usize>), ParseError<T::Error>> {
        let current = self.inner.len() - self.remaining;
        let (value, len_consumed) = T::parse_with(param, &self.inner[current..])?;
        match self.consume(len_consumed) {
            Ok(()) => Ok((value, len_consumed)),
            Err(e) => Err(ParseError::Length(e)),
        }
    }
}

impl Writer<'_> {
    pub(crate) fn new(buf: &mut [u8]) -> Writer {
        let len = buf.len();
        Writer {
            inner: buf,
            remaining: len,
        }
    }

    fn consume(&mut self, n: NonZero<usize>) -> Result<(), LengthError> {
        if n.get() >= self.remaining {
            return Err(LengthError {
                expected: n,
                actual: self.remaining,
            });
        }
        self.remaining -= n.get();
        Ok(())
    }

    pub(crate) fn write<T: DeParse>(
        &mut self,
        val: &T,
    ) -> Result<NonZero<usize>, DeParseError<T::Error>> {
        let current = self.inner.len() - self.remaining;
        let consumed = val.deparse(&mut self.inner[current..])?;
        self.consume(consumed).map_err(DeParseError::Length)?;
        Ok(consumed)
    }
}

#[derive(thiserror::Error, Debug)]
pub enum ParseError<E: core::error::Error> {
    #[error(transparent)]
    Length(LengthError),
    #[error(transparent)]
    Invalid(E),
}

#[derive(thiserror::Error, Debug)]
pub enum DeParseError<E> {
    #[error(transparent)]
    Length(LengthError),
    #[error(transparent)]
    Invalid(E),
}
