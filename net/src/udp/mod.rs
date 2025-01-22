use crate::encap::Encap;
use crate::packet::Header;
use crate::parse::{DeParse, DeParseError, LengthError, Parse, ParseError, Reader, Step};
use crate::vxlan::Vxlan;
use core::num::NonZero;
use etherparse::UdpHeader;
use tracing::trace;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Udp {
    inner: UdpHeader,
}

// TODO: udp port type
impl Udp {
    pub fn src(&self) -> u16 {
        self.inner.source_port
    }

    pub fn dst(&self) -> u16 {
        self.inner.destination_port
    }
}

impl Parse for Udp {
    type Error = LengthError;

    fn parse(buf: &[u8]) -> Result<(Self, NonZero<usize>), ParseError<Self::Error>> {
        let (inner, rest) = UdpHeader::from_slice(buf).map_err(|e| {
            let expected = NonZero::new(e.required_len).unwrap_or_else(|| unreachable!());
            ParseError::LengthError(LengthError {
                expected,
                actual: buf.len(),
            })
        })?;
        assert!(
            rest.len() < buf.len(),
            "rest.len() >= buf.len() ({rest} >= {buf})",
            rest = rest.len(),
            buf = buf.len()
        );
        let consumed = NonZero::new(buf.len() - rest.len()).ok_or_else(|| unreachable!())?;
        Ok((Self { inner }, consumed))
    }
}

impl DeParse for Udp {
    type Error = ();

    fn size(&self) -> NonZero<usize> {
        NonZero::new(self.inner.header_len()).unwrap_or_else(|| unreachable!())
    }

    fn write(&self, buf: &mut [u8]) -> Result<NonZero<usize>, DeParseError<Self::Error>> {
        let len = buf.len();
        if len < self.size().get() {
            return Err(DeParseError::LengthError(LengthError {
                expected: self.size(),
                actual: len,
            }));
        };
        buf[..self.size().get()].copy_from_slice(&self.inner.to_bytes());
        Ok(self.size())
    }
}

pub(crate) enum UdpNext {
    Encap(Encap),
}

impl From<UdpNext> for Header {
    fn from(value: UdpNext) -> Self {
        match value {
            UdpNext::Encap(Encap::Vxlan(vxlan)) => Header::Vxlan(vxlan),
        }
    }
}

impl Step for Udp {
    type Next = UdpNext;

    fn step(&self, cursor: &mut Reader) -> Option<Self::Next> {
        match self.dst() {
            Vxlan::PORT => cursor
                .parse::<Vxlan>()
                .map_err(|e| {
                    trace!("failed to parse vxlan header: {e:?}");
                })
                .map(|(val, _)| UdpNext::Encap(Encap::Vxlan(val)))
                .ok(),
            _ => None,
        }
    }
}
