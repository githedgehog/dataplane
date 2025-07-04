// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! TCP header type and logic.

mod checksum;
pub mod port;

pub use checksum::*;
pub use port::*;

use crate::parse::{
    DeParse, DeParseError, IntoNonZeroUSize, LengthError, Parse, ParseError, ParsePayload, Reader,
};
use etherparse::TcpHeader;
use etherparse::err::tcp::{HeaderError, HeaderSliceError};
use std::num::NonZero;

use crate::ipv4::Ipv4;
use crate::ipv6::Ipv6;
#[allow(unused_imports)] // re-export
#[cfg(any(test, feature = "bolero"))]
pub use contract::*;

/// A TCP header.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Tcp(TcpHeader);

impl Tcp {
    /// The minimum length of a [`Tcp`]
    #[allow(clippy::unwrap_used)] // trivially sound const eval
    pub const MIN_LENGTH: NonZero<u16> = NonZero::new(20).unwrap();
    /// The maximum length of a [`Tcp`]
    pub const MAX_LENGTH: usize = 60;

    fn compute_checksum_ipv4(&self, net: &Ipv4, payload: impl AsRef<[u8]>) -> TcpChecksum {
        #[allow(clippy::expect_used)] // DPDK should exclude payload greater than 2^16 bytes
        self.0
            .calc_checksum_ipv4(&net.0, payload.as_ref())
            .expect("unreasonable payload")
            .into()
    }

    fn compute_checksum_ipv6(&self, net: &Ipv6, payload: impl AsRef<[u8]>) -> TcpChecksum {
        #[allow(clippy::expect_used)] // DPDK should exclude payload greater than 2^16 bytes
        self.0
            .calc_checksum_ipv6(&net.0, payload.as_ref())
            .expect("unreasonable payload")
            .into()
    }

    /// Get the source port
    #[must_use]
    pub const fn source(&self) -> TcpPort {
        debug_assert!(self.0.source_port != 0);
        #[allow(unsafe_code)] // non-zero checked in [`Parse`] and `new`.
        unsafe {
            TcpPort::new_unchecked(self.0.source_port)
        }
    }

    /// Set the source port
    pub fn set_source(&mut self, port: TcpPort) -> &mut Self {
        self.0.source_port = port.into();
        self
    }

    /// Get the destination port
    #[must_use]
    pub const fn destination(&self) -> TcpPort {
        debug_assert!(self.0.destination_port != 0);
        #[allow(unsafe_code)] // non-zero checked in [`Parse`] and `new`.
        unsafe {
            TcpPort::new_unchecked(self.0.destination_port)
        }
    }

    /// Set the destination port
    pub fn set_destination(&mut self, port: TcpPort) -> &mut Self {
        self.0.destination_port = port.into();
        self
    }

    /// The number of 32-bit words in the TCP Header & TCP header options
    #[must_use]
    pub fn data_offset(&self) -> u8 {
        self.0.data_offset()
    }

    // TODO: safety proof, this should never panic (use no_panic crate)
    /// Get the header length
    #[must_use]
    pub fn header_len(&self) -> NonZero<usize> {
        #[allow(clippy::unwrap_used)] // trivially sound as `header_len` is const and non-zero
        NonZero::new(self.0.header_len()).unwrap_or_else(|| unreachable!())
    }

    /// get the checksum of the header as a `u16`
    #[must_use]
    pub const fn checksum(&self) -> TcpChecksum {
        TcpChecksum::new(self.0.checksum)
    }

    /// Get the sequence number of the header.
    #[must_use]
    pub const fn sequence_number(&self) -> u32 {
        self.0.sequence_number
    }

    /// Returns true if the syn flag is set in this header
    #[must_use]
    pub const fn syn(&self) -> bool {
        self.0.syn
    }

    /// Returns true if the ack flag is set in this header
    #[must_use]
    pub const fn ack(&self) -> bool {
        self.0.ack
    }

    /// Returns the acknowledgment number of the header.
    #[must_use]
    pub const fn ack_number(&self) -> u32 {
        self.0.acknowledgment_number
    }

    /// Returns true if the fin flag is set in this header
    #[must_use]
    pub const fn fin(&self) -> bool {
        self.0.fin
    }

    /// Returns true if the rst flag is set in this header
    #[must_use]
    pub const fn rst(&self) -> bool {
        self.0.rst
    }

    /// Returns true if the psh flag is set in this header
    #[must_use]
    pub const fn psh(&self) -> bool {
        self.0.psh
    }

    /// Returns true if the urg flag is set in this header
    #[must_use]
    pub const fn urg(&self) -> bool {
        self.0.urg
    }

    /// Returns true if the ece flag is set in this header
    #[must_use]
    pub const fn ece(&self) -> bool {
        self.0.ece
    }

    /// Returns true if the cwr flag is set in this header
    #[must_use]
    pub const fn cwr(&self) -> bool {
        self.0.cwr
    }

    /// Returns true if the (experimental) nonce-sum is set in this header
    ///
    /// See [rfc3540](https://datatracker.ietf.org/doc/html/rfc3540) for details.
    #[must_use]
    pub const fn ns(&self) -> bool {
        self.0.ns
    }

    /// Returns the window size of the tcp header.
    #[must_use]
    pub const fn window_size(&self) -> u16 {
        self.0.window_size
    }

    /// Returns the urgent pointer of the tcp header.
    ///
    /// This value is only relevant if the urg flag is set (see [`Tcp::urg`]).
    #[must_use]
    pub const fn urgent_pointer(&self) -> u16 {
        self.0.urgent_pointer
    }

    /// Returns any tcp options present in this header as a slice.
    ///
    /// Returns `None` if no such options exist.
    #[must_use]
    pub fn options(&self) -> Option<&[u8]> {
        if self.0.options.is_empty() {
            return None;
        }
        Some(&self.0.options.as_slice()[..self.0.options.len()])
    }

    /// Set the syn flag
    pub fn set_syn(&mut self, syn: bool) -> &mut Self {
        self.0.syn = syn;
        self
    }

    /// Set the ack flag
    pub fn set_ack(&mut self, ack: bool) -> &mut Self {
        self.0.ack = ack;
        self
    }

    /// Set the fin flag
    pub fn set_fin(&mut self, fin: bool) -> &mut Self {
        self.0.fin = fin;
        self
    }

    /// Set the rst flag
    pub fn set_rst(&mut self, rst: bool) -> &mut Self {
        self.0.rst = rst;
        self
    }

    /// Set the psh flag
    pub fn set_psh(&mut self, psh: bool) -> &mut Self {
        self.0.psh = psh;
        self
    }

    /// Set the urg flag
    pub fn set_urg(&mut self, urg: bool) -> &mut Self {
        self.0.urg = urg;
        self
    }

    /// Set the ece flag
    pub fn set_ece(&mut self, ece: bool) -> &mut Self {
        self.0.ece = ece;
        self
    }

    /// Set the cwr flag
    pub fn set_cwr(&mut self, cwr: bool) -> &mut Self {
        self.0.cwr = cwr;
        self
    }

    /// Set the window size
    ///
    /// # Note
    ///
    /// It is easy to use this method in a way that is unreasonable (if sound).
    ///
    /// Generally, only a tcp implementation should edit the window size.
    /// This method is supplied mostly for packet generation.
    pub fn set_window_size(&mut self, window_size: u16) -> &mut Self {
        self.0.window_size = window_size;
        self
    }

    /// Set the urgent pointer.
    ///
    /// # Note
    ///
    /// It is easy to use this method in a way that is unreasonable (if sound).
    ///
    /// Generally, only a tcp implementation should edit the urgent pointer.
    /// This method is supplied mostly for packet generation.
    pub fn set_urgent_pointer(&mut self, urgent_pointer: u16) -> &mut Self {
        self.0.urgent_pointer = urgent_pointer;
        self
    }

    /// Set the checksum
    pub fn set_checksum(&mut self, checksum: TcpChecksum) -> &mut Self {
        self.0.checksum = checksum.0;
        self
    }

    /// Set the sequence number
    ///
    /// # Note
    ///
    /// It is easy to use this method in a way that is unreasonable (if sound).
    ///
    /// Generally, only a tcp implementation should edit the sequence number.
    /// This method is supplied mostly for packet generation.
    pub fn set_sequence_number(&mut self, sequence_number: u32) -> &mut Self {
        self.0.sequence_number = sequence_number;
        self
    }

    /// Set the ack number
    ///
    /// # Note
    ///
    /// It is easy to use this method in a way that is unreasonable (if sound).
    ///
    /// Generally, only a tcp implementation should edit the ack number.
    /// This method is supplied mostly for packet generation.
    pub fn set_ack_number(&mut self, ack_number: u32) -> &mut Self {
        self.0.acknowledgment_number = ack_number;
        self
    }
}

/// Errors which can occur when attempting to parse arbitrary bytes into a [`Tcp`] header.
#[derive(Debug, thiserror::Error)]
pub enum TcpError {
    /// Zero is not legal as a source port.
    #[error("zero source port")]
    ZeroSourcePort,
    /// Zero is not legal as a destination port.
    #[error("zero dest port")]
    ZeroDestPort,
    /// Valid tcp headers have data offsets which are at least large enough to include the header
    /// itself.
    #[error("data offset too small: {0}")]
    DataOffsetTooSmall(u8),
}

impl Parse for Tcp {
    type Error = TcpError;

    fn parse(buf: &[u8]) -> Result<(Self, NonZero<u16>), ParseError<Self::Error>> {
        if buf.len() > u16::MAX as usize {
            return Err(ParseError::BufferTooLong(buf.len()));
        }
        let (inner, rest) = TcpHeader::from_slice(buf).map_err(|e| match e {
            HeaderSliceError::Len(len) => ParseError::Length(LengthError {
                expected: NonZero::new(len.required_len).unwrap_or_else(|| unreachable!()),
                actual: buf.len(),
            }),
            HeaderSliceError::Content(content) => match content {
                HeaderError::DataOffsetTooSmall { data_offset } => {
                    ParseError::Invalid(TcpError::DataOffsetTooSmall(data_offset))
                }
            },
        })?;
        assert!(
            rest.len() < buf.len(),
            "rest.len() >= buf.len() ({rest} >= {buf})",
            rest = rest.len(),
            buf = buf.len()
        );
        #[allow(clippy::cast_possible_truncation)] // buffer length bounded above
        let consumed =
            NonZero::new((buf.len() - rest.len()) as u16).ok_or_else(|| unreachable!())?;
        if inner.source_port == 0 {
            return Err(ParseError::Invalid(TcpError::ZeroSourcePort));
        }
        if inner.destination_port == 0 {
            return Err(ParseError::Invalid(TcpError::ZeroDestPort));
        }
        let parsed = Self(inner);
        Ok((parsed, consumed))
    }
}

impl DeParse for Tcp {
    type Error = ();

    fn size(&self) -> NonZero<u16> {
        #[allow(clippy::cast_possible_truncation)] // bounded header length
        NonZero::new(self.0.header_len() as u16).unwrap_or_else(|| unreachable!())
    }

    fn deparse(&self, buf: &mut [u8]) -> Result<NonZero<u16>, DeParseError<Self::Error>> {
        let len = buf.len();
        if len < self.size().into_non_zero_usize().get() {
            return Err(DeParseError::Length(LengthError {
                expected: self.size().into_non_zero_usize(),
                actual: len,
            }));
        }
        buf[..self.size().into_non_zero_usize().get()].copy_from_slice(&self.0.to_bytes());
        Ok(self.size())
    }
}

impl ParsePayload for Tcp {
    type Next = ();

    /// We don't currently support parsing below the TCP layer
    fn parse_payload(&self, _cursor: &mut Reader) -> Option<Self::Next> {
        None
    }
}

#[cfg(any(test, feature = "bolero"))]
mod contract {
    use crate::tcp::Tcp;
    use bolero::{Driver, TypeGenerator};
    use etherparse::TcpHeader;

    impl TypeGenerator for Tcp {
        fn generate<D: Driver>(u: &mut D) -> Option<Self> {
            let mut header = Tcp(TcpHeader::default());
            header
                .set_source(u.produce()?)
                .set_destination(u.produce()?)
                .set_checksum(u.produce()?)
                .set_sequence_number(u.produce()?)
                .set_ack(u.produce()?)
                .set_ack_number(u.produce()?)
                .set_cwr(u.produce()?)
                .set_ece(u.produce()?)
                .set_fin(u.produce()?)
                .set_psh(u.produce()?)
                .set_rst(u.produce()?)
                .set_syn(u.produce()?)
                .set_urg(u.produce()?)
                .set_window_size(u.produce()?)
                .set_urgent_pointer(u.produce()?);
            Some(header)
        }
    }
}

#[cfg(test)]
mod test {
    use crate::parse::{DeParse, IntoNonZeroUSize, Parse, ParseError};
    use crate::tcp::Tcp;

    const MIN_LEN: usize = Tcp::MIN_LENGTH.get() as usize;

    #[test]
    #[cfg_attr(kani, kani::proof)]
    fn parse_back() {
        bolero::check!().with_type().for_each(|tcp: &Tcp| {
            let mut buffer = [0u8; 64];
            let consumed = match tcp.deparse(&mut buffer) {
                Ok(consumed) => consumed,
                Err(err) => {
                    unreachable!("failed to write tcp: {err:?}");
                }
            };
            assert!(consumed.into_non_zero_usize().get() <= buffer.len());
            let (parsed, consumed2) =
                Tcp::parse(&buffer[..consumed.into_non_zero_usize().get()]).unwrap();
            assert_eq!(tcp.source(), parsed.source());
            assert_eq!(tcp.destination(), parsed.destination());
            assert_eq!(tcp.checksum(), parsed.checksum());
            assert_eq!(tcp.sequence_number(), parsed.sequence_number());
            assert_eq!(tcp.ack_number(), parsed.ack_number());
            assert_eq!(tcp.ack(), parsed.ack());
            assert_eq!(tcp.ack(), parsed.ack());
            assert_eq!(tcp.cwr(), parsed.cwr());
            assert_eq!(tcp.ece(), parsed.ece());
            assert_eq!(tcp.fin(), parsed.fin());
            assert_eq!(tcp.psh(), parsed.psh());
            assert_eq!(tcp.rst(), parsed.rst());
            assert_eq!(tcp.syn(), parsed.syn());
            assert_eq!(tcp.urg(), parsed.urg());
            assert_eq!(tcp.window_size(), parsed.window_size());
            assert_eq!(tcp.urgent_pointer(), parsed.urgent_pointer());
            #[cfg(not(kani))] // remove after fixing options
            assert_eq!(tcp, &parsed);
            assert_eq!(consumed, consumed2);
        });
    }

    #[test]
    #[cfg_attr(kani, kani::proof)]
    fn parse_noise() {
        bolero::check!()
            .with_type()
            .for_each(|slice: &[u8; MIN_LEN]| {
                let (parsed, consumed1) = match Tcp::parse(slice) {
                    Ok((parsed, consumed)) => (parsed, consumed),
                    Err(err) => match err {
                        ParseError::Length(l) => {
                            assert_eq!(l.actual, slice.len());
                            assert!(l.expected.get() > slice.len());
                            return;
                        }
                        ParseError::Invalid(_invalid) => {
                            /* I'm not sure that I can assert much in this case */
                            return;
                        }
                        ParseError::BufferTooLong(_) => unreachable!(),
                    },
                };
                let mut slice2 = [0u8; Tcp::MAX_LENGTH];
                let consumed2 = match parsed.deparse(&mut slice2) {
                    Ok(consumed) => consumed,
                    Err(err) => {
                        unreachable!("failed to write tcp: {err:?}");
                    }
                };
                assert_eq!(consumed2, consumed1);
                let (parsed_back, consumed3) =
                    Tcp::parse(&slice2[..consumed2.into_non_zero_usize().get()]).unwrap();
                assert_eq!(consumed2, consumed3);
                #[cfg(not(kani))] // remove after fixing options
                assert_eq!(parsed, parsed_back);
                assert_eq!(&slice[..12], &slice2[..12]);
                // check for reserved bits getting zeroed by `write` (regardless of inputs)
                assert_eq!(slice[12] & 0b1111_0001, slice2[12]);
                assert_eq!(&slice[13..MIN_LEN], &slice2[13..MIN_LEN]);
                #[cfg(not(kani))] // remove after fixing options
                assert_eq!(
                    &slice[MIN_LEN..consumed1.into_non_zero_usize().get()],
                    &slice2[MIN_LEN..consumed1.into_non_zero_usize().get()]
                );
            });
    }
}
