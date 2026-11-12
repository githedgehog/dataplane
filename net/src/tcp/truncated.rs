// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! TCP header type and logic, for potentially truncated datagrams.

use std::num::NonZero;

use crate::parse::{DeParse, DeParseError, LengthError, Parse, ParseError};
use crate::tcp::{Tcp, TcpFlags, TcpParseError, TcpPort};

/// A truncated TCP header.
///
/// This truncated header is built from the start of a regular TCP header, down to the last byte of
/// the packet, but does not contain a full header. The only fields that are guaranteed to be
/// present are the source and destination ports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TruncatedTcpHeader {
    source_port: TcpPort,
    destination_port: TcpPort,
    // The rest of the header, as a byte vector, for de-parsing
    everything_else: Vec<u8>,
}

// Offsets of fields in the bytes that follow the ports
const SEQ_OFFSET: usize = 0;
const ACK_OFFSET: usize = 4;
const FLAGS_OFFSET: usize = 9;

impl TruncatedTcpHeader {
    pub(crate) const MIN_HEADER_LEN: usize = 4;

    fn new(source_port: TcpPort, destination_port: TcpPort, everything_else: Vec<u8>) -> Self {
        Self {
            source_port,
            destination_port,
            everything_else,
        }
    }

    /// Get the length of the truncated header
    #[must_use]
    pub fn header_len(&self) -> NonZero<usize> {
        let len = self.everything_else.len() + Self::MIN_HEADER_LEN;
        NonZero::new(len).unwrap_or_else(|| unreachable!())
    }

    /// Get the source port
    #[must_use]
    pub const fn source(&self) -> TcpPort {
        self.source_port
    }

    /// Get the destination port
    #[must_use]
    pub const fn destination(&self) -> TcpPort {
        self.destination_port
    }

    /// Set the source port
    pub fn set_source(&mut self, source_port: TcpPort) -> &mut Self {
        self.source_port = source_port;
        self
    }

    /// Set the destination port
    pub fn set_destination(&mut self, destination_port: TcpPort) -> &mut Self {
        self.destination_port = destination_port;
        self
    }

    fn word(&self, offset: usize) -> Option<u32> {
        let bytes = self.everything_else.get(offset..offset + 4)?;
        Some(u32::from_be_bytes(bytes.try_into().ok()?))
    }

    fn set_word(&mut self, offset: usize, value: u32) -> Option<()> {
        let bytes = self.everything_else.get_mut(offset..offset + 4)?;
        bytes.copy_from_slice(&value.to_be_bytes());
        Some(())
    }
}

impl Parse for TruncatedTcpHeader {
    type Error = TruncatedTcpError;

    fn parse(buf: &[u8]) -> Result<(Self, NonZero<u16>), ParseError<Self::Error>> {
        // We need at least four bytes to form our truncated header.
        // RFC 792 (ICMP) says embedded packets in ICMP Error messages contain the IP header plus at
        // least the first 64 bits from the datagram, so we should have these 4 bytes. Otherwise,
        // it's an error.
        if buf.len() < TruncatedTcpHeader::MIN_HEADER_LEN {
            return Err(ParseError::Length(LengthError {
                expected: NonZero::new(TruncatedTcpHeader::MIN_HEADER_LEN)
                    .unwrap_or_else(|| unreachable!()),
                actual: buf.len(),
            }));
        }

        let parsed_source_port = u16::from_be_bytes([buf[0], buf[1]]);
        let parsed_destination_port = u16::from_be_bytes([buf[2], buf[3]]);

        // buf.len() is always non-zero and lower than u16::MAX
        #[allow(clippy::unwrap_used, clippy::cast_possible_truncation)]
        let consumed = NonZero::new(buf.len() as u16).unwrap();

        let source_port = TcpPort::new_checked(parsed_source_port).map_err(|_| {
            ParseError::Invalid(TruncatedTcpError::TcpParseError(
                TcpParseError::ZeroSourcePort,
            ))
        })?;
        let destination_port = TcpPort::new_checked(parsed_destination_port).map_err(|_| {
            ParseError::Invalid(TruncatedTcpError::TcpParseError(
                TcpParseError::ZeroDestinationPort,
            ))
        })?;
        let parsed = Self::new(source_port, destination_port, buf[4..].to_vec());
        Ok((parsed, consumed))
    }
}

impl DeParse for TruncatedTcpHeader {
    type Error = ();

    fn size(&self) -> NonZero<u16> {
        let size_u16 = u16::try_from(self.header_len().get()).unwrap_or_else(|_| unreachable!());
        NonZero::new(size_u16).unwrap_or_else(|| unreachable!())
    }

    fn deparse(&self, buf: &mut [u8]) -> Result<NonZero<u16>, DeParseError<Self::Error>> {
        let buf_len = buf.len();
        let header_len = self.header_len().get();
        if buf_len < header_len {
            return Err(DeParseError::Length(LengthError {
                expected: NonZero::new(header_len).unwrap_or_else(|| unreachable!()),
                actual: buf_len,
            }));
        }
        buf[0..2].copy_from_slice(&self.source_port.as_u16().to_be_bytes());
        buf[2..4].copy_from_slice(&self.destination_port.as_u16().to_be_bytes());
        buf[4..header_len].copy_from_slice(&self.everything_else);

        let header_len_u16 = u16::try_from(header_len).unwrap_or_else(|_| unreachable!());
        let written = NonZero::new(header_len_u16).unwrap_or_else(|| unreachable!());
        Ok(written)
    }
}

/// A TCP header, possibly truncated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TruncatedTcp {
    /// A full TCP header, whether payload is full or not
    FullHeader(Tcp),
    /// A truncated TCP header (< 20 bytes)
    PartialHeader(TruncatedTcpHeader),
}

impl TruncatedTcp {
    /// Get the source port
    #[must_use]
    pub const fn source(&self) -> TcpPort {
        match self {
            TruncatedTcp::FullHeader(tcp) => tcp.source(),
            TruncatedTcp::PartialHeader(tcp) => tcp.source(),
        }
    }

    /// Set the source port
    pub fn set_source(&mut self, port: TcpPort) {
        match self {
            TruncatedTcp::FullHeader(tcp) => {
                tcp.set_source(port);
            }
            TruncatedTcp::PartialHeader(tcp) => {
                tcp.set_source(port);
            }
        }
    }

    /// Get the destination port
    #[must_use]
    pub const fn destination(&self) -> TcpPort {
        match self {
            TruncatedTcp::FullHeader(tcp) => tcp.destination(),
            TruncatedTcp::PartialHeader(tcp) => tcp.destination(),
        }
    }

    /// Set the destination port
    pub fn set_destination(&mut self, port: TcpPort) {
        match self {
            TruncatedTcp::FullHeader(tcp) => {
                tcp.set_destination(port);
            }
            TruncatedTcp::PartialHeader(tcp) => {
                tcp.set_destination(port);
            }
        }
    }

    /// Get the sequence number, if the header is long enough to hold it
    #[must_use]
    pub fn sequence_number(&self) -> Option<u32> {
        match self {
            TruncatedTcp::FullHeader(tcp) => Some(tcp.sequence_number()),
            TruncatedTcp::PartialHeader(tcp) => tcp.word(SEQ_OFFSET),
        }
    }

    /// Set the sequence number, if the header is long enough to hold it. The checksum is left
    /// unchanged.
    pub fn set_sequence_number(&mut self, seq: u32) -> Option<()> {
        match self {
            TruncatedTcp::FullHeader(tcp) => {
                tcp.set_sequence_number(seq);
                Some(())
            }
            TruncatedTcp::PartialHeader(tcp) => tcp.set_word(SEQ_OFFSET, seq),
        }
    }

    /// Get the acknowledgment number, if the header is long enough to hold it
    #[must_use]
    pub fn ack_number(&self) -> Option<u32> {
        match self {
            TruncatedTcp::FullHeader(tcp) => Some(tcp.ack_number()),
            TruncatedTcp::PartialHeader(tcp) => tcp.word(ACK_OFFSET),
        }
    }

    /// Set the acknowledgment number, if the header is long enough to hold it. The checksum is
    /// left unchanged.
    pub fn set_ack_number(&mut self, ack: u32) -> Option<()> {
        match self {
            TruncatedTcp::FullHeader(tcp) => {
                tcp.set_ack_number(ack);
                Some(())
            }
            TruncatedTcp::PartialHeader(tcp) => tcp.set_word(ACK_OFFSET, ack),
        }
    }

    /// Get the control bits, if the header is long enough to hold them
    #[must_use]
    pub fn flags(&self) -> Option<TcpFlags> {
        match self {
            TruncatedTcp::FullHeader(tcp) => Some(tcp.flags()),
            TruncatedTcp::PartialHeader(tcp) => tcp
                .everything_else
                .get(FLAGS_OFFSET)
                .map(|&bits| TcpFlags::from_bits_retain(bits)),
        }
    }
}

/// Errors which can occur when attempting to parse arbitrary bytes into a `TruncatedTcp` header.
#[derive(Debug, thiserror::Error)]
pub enum TruncatedTcpError {
    /// A transparent error from [`Tcp::parse`].
    #[error("transparent")]
    TcpParseError(TcpParseError),
}

impl Parse for TruncatedTcp {
    type Error = TruncatedTcpError;

    fn parse(buf: &[u8]) -> Result<(Self, NonZero<u16>), ParseError<Self::Error>> {
        let parse_attempt = Tcp::parse(buf);
        match parse_attempt {
            // If we can parse the full header, return it
            Ok((tcp, consumed)) => Ok((TruncatedTcp::FullHeader(tcp), consumed)),
            // If we encounter an unexpected issue, return the error
            Err(ParseError::BufferTooLong(len)) => Err(ParseError::BufferTooLong(len)),
            Err(ParseError::Invalid(e)) => {
                Err(ParseError::Invalid(TruncatedTcpError::TcpParseError(e)))
            }
            // If we failed to parse because the header is too short, carry on and build a truncated
            // header
            Err(ParseError::Length(_)) => {
                let (header, consumed) = TruncatedTcpHeader::parse(buf)?;
                Ok((TruncatedTcp::PartialHeader(header), consumed))
            }
        }
    }
}

impl DeParse for TruncatedTcp {
    type Error = ();

    fn size(&self) -> NonZero<u16> {
        match self {
            TruncatedTcp::FullHeader(tcp) => tcp.size(),
            TruncatedTcp::PartialHeader(tcp) => tcp.size(),
        }
    }

    fn deparse(&self, buf: &mut [u8]) -> Result<NonZero<u16>, DeParseError<Self::Error>> {
        match self {
            TruncatedTcp::FullHeader(tcp) => tcp.deparse(buf),
            TruncatedTcp::PartialHeader(tcp) => tcp.deparse(buf),
        }
    }
}

impl From<Tcp> for TruncatedTcp {
    fn from(tcp: Tcp) -> Self {
        TruncatedTcp::FullHeader(tcp)
    }
}

impl From<TruncatedTcpHeader> for TruncatedTcp {
    fn from(header: TruncatedTcpHeader) -> Self {
        TruncatedTcp::PartialHeader(header)
    }
}

#[cfg(any(test, feature = "bolero"))]
mod contract {
    use super::{Tcp, TruncatedTcp, TruncatedTcpHeader};
    use crate::parse::{DeParse, Parse};
    use bolero::{Driver, TypeGenerator};

    impl TypeGenerator for TruncatedTcp {
        // Generate either full or partial TCP header
        fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
            let full_header = TruncatedTcp::FullHeader(driver.produce()?);
            if driver.produce::<bool>()? {
                Some(full_header)
            } else {
                let mut buffer = [0u8; Tcp::MAX_LENGTH];
                #[allow(clippy::unwrap_used)] // We want to catch errors when deparsing, if any
                full_header.deparse(&mut buffer).unwrap();

                // We can have up to 15 extra bytes for the header, in addition to the 4 bytes for
                // the ports. Beyond that, we'd have at least 20 bytes and that would make our
                // header a full TCP header.
                let size = driver.produce::<u8>()? % 16 + 4;
                let truncated_buffer = &buffer[..size as usize];
                #[allow(clippy::unwrap_used)] // We want to catch errors when parsing, if any
                let tcp = TruncatedTcpHeader::parse(truncated_buffer).ok().unwrap().0;

                Some(TruncatedTcp::PartialHeader(tcp))
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::{TruncatedTcp, TruncatedTcpHeader};
    use crate::parse::{DeParse, Parse};
    use crate::tcp::TcpFlags;

    // The first `len` bytes of a TCP header from port 1234 to port 80, with sequence number
    // 0x01020304, acknowledgment number 0x05060708 and flags ACK and PSH.
    fn partial(len: usize) -> TruncatedTcp {
        let header = [
            0x04, 0xd2, 0x00, 0x50, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x50, 0x18,
            0xff, 0xff, 0x00, 0x00,
        ];
        let (parsed, _) = TruncatedTcpHeader::parse(&header[..len]).unwrap();
        TruncatedTcp::PartialHeader(parsed)
    }

    #[test]
    fn partial_header_fields() {
        let tcp = partial(18);
        assert_eq!(tcp.sequence_number(), Some(0x0102_0304));
        assert_eq!(tcp.ack_number(), Some(0x0506_0708));
        assert_eq!(tcp.flags(), Some(TcpFlags::ACK | TcpFlags::PSH));

        // ICMPv4 errors may quote only 8 bytes of the transport header
        let tcp = partial(8);
        assert_eq!(tcp.sequence_number(), Some(0x0102_0304));
        assert_eq!(tcp.ack_number(), None);
        assert_eq!(tcp.flags(), None);
    }

    #[test]
    fn partial_header_set_numbers() {
        let mut tcp = partial(18);
        assert_eq!(tcp.set_sequence_number(0x1111_1111), Some(()));
        assert_eq!(tcp.set_ack_number(0x2222_2222), Some(()));
        let mut buf = [0u8; 18];
        tcp.deparse(&mut buf).unwrap();
        assert_eq!(buf[4..12], [0x11, 0x11, 0x11, 0x11, 0x22, 0x22, 0x22, 0x22]);
        assert_eq!(buf[12..14], [0x50, 0x18]);

        let mut tcp = partial(8);
        assert_eq!(tcp.set_sequence_number(0x1111_1111), Some(()));
        assert_eq!(tcp.set_ack_number(0x2222_2222), None);
        assert_eq!(tcp.sequence_number(), Some(0x1111_1111));
    }
}
