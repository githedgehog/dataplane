use std::num::NonZero;
use std::ptr::NonNull;

pub trait Parse: Sized {
    type Error: core::error::Error;
    fn parse(buf: &[u8]) -> Result<(Self, NonZero<usize>), ParseError<Self::Error>>;
}

pub trait DeParse {
    type Error: core::error::Error;

    fn size(&self) -> NonZero<usize>;
    fn write(&self, buf: &mut [u8]) -> Result<NonZero<usize>, DeParseError<Self::Error>>;
}

pub trait ParseWith {
    type Error: core::error::Error;
    type Param;
    fn parse_with(
        param: Self::Param,
        raw: &[u8],
    ) -> Result<(Self, NonZero<usize>), ParseError<Self::Error>>
    where
        Self: Sized;
}

#[derive(thiserror::Error, Debug)]
#[error("expected at least {expected} bytes, got {actual}")]
pub struct LengthError {
    pub(crate) expected: NonZero<usize>,
    pub(crate) actual: usize,
}

#[derive(Debug)]
#[repr(transparent)]
pub(crate) struct Cursor {
    pub(crate) inner: NonNull<[u8]>,
}

impl Cursor {
    #[allow(unsafe_code)] // TODO: explain how to use this type safely
    pub(crate) fn new(buf: &[u8]) -> Cursor {
        let range = buf.as_ptr_range();
        let inner = NonNull::from(unsafe { core::slice::from_raw_parts(range.start, buf.len()) });
        Cursor { inner }
    }

    #[allow(unsafe_code)] // TODO: explain how to use this type safely
    fn consume(&mut self, n: NonZero<usize>) -> Result<(), LengthError> {
        if n.get() >= self.inner.len() {
            return Err(LengthError {
                expected: n,
                actual: self.inner.len(),
            });
        };
        let start = unsafe { self.inner.as_mut() }.as_mut_ptr();
        let split = unsafe { start.byte_add(n.get()) };
        let inner = NonNull::from(unsafe {
            core::slice::from_raw_parts_mut(split, self.inner.len() - n.get())
        });
        self.inner = inner;
        Ok(())
    }

    #[allow(unsafe_code)] // TODO: document safe usage
    pub(crate) fn parse<T: Parse>(&mut self) -> Result<(T, NonZero<usize>), ParseError<T::Error>> {
        let (value, len_consumed) = T::parse(unsafe { self.inner.as_mut() })?;
        match self.consume(len_consumed) {
            Ok(()) => Ok((value, len_consumed)),
            Err(e) => Err(ParseError::LengthError(e)),
        }
    }

    #[allow(unsafe_code)] // TODO: document safe usage
    pub(crate) fn parse_with<T: ParseWith>(
        &mut self,
        param: <T as ParseWith>::Param,
    ) -> Result<(T, NonZero<usize>), ParseError<T::Error>> {
        let (value, len_consumed) = T::parse_with(param, unsafe { self.inner.as_mut() })?;
        match self.consume(len_consumed) {
            Ok(()) => Ok((value, len_consumed)),
            Err(e) => Err(ParseError::LengthError(e)),
        }
    }

    pub(crate) fn write<T: DeParse>(&mut self, header: &T) -> Result<(), DeParseError<T::Error>> {
        #[allow(unsafe_code)] // TODO: document safety requirements
        let len_written = header.write(unsafe { self.inner.as_mut() })?;
        self.consume(len_written).map_err(DeParseError::LengthError)
    }
}

#[derive(thiserror::Error, Debug)]
pub enum ParseError<E: core::error::Error> {
    #[error(transparent)]
    LengthError(LengthError),
    #[error(transparent)]
    FailedToParse(E),
}

#[derive(thiserror::Error, Debug)]
pub enum DeParseError<E: core::error::Error> {
    #[error(transparent)]
    LengthError(LengthError),
    #[error(transparent)]
    FailedToDeParse(E),
}
