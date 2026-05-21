// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Common logic for TCP and UDP: the port-based transport protocols.

use crate::headers::Transport;
use crate::tcp::{Tcp, TcpPort};
use crate::udp::{Udp, UdpPort};
use std::num::NonZero;

/// Error type for [`TcpUdp`] and [`TcpUdpMut`].
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum TcpUdpError {
    /// The transport layer is neither TCP nor UDP.
    #[error("this transport layer is neither TCP nor UDP")]
    NotPortBased,
}

/// Enum representing an immutable reference to a port-based transport header
/// ([`Tcp`] or [`Udp`]).
#[derive(Debug)]
pub enum TcpUdp<'a> {
    /// A [`Tcp`] header.
    Tcp(&'a Tcp),
    /// A [`Udp`] header.
    Udp(&'a Udp),
}

impl<'a> TryFrom<&'a Transport> for TcpUdp<'a> {
    type Error = TcpUdpError;
    fn try_from(value: &'a Transport) -> Result<Self, Self::Error> {
        match value {
            Transport::Tcp(tcp) => Ok(TcpUdp::Tcp(tcp)),
            Transport::Udp(udp) => Ok(TcpUdp::Udp(udp)),
            _ => Err(TcpUdpError::NotPortBased),
        }
    }
}

impl TcpUdp<'_> {
    /// Returns the source port.
    #[must_use]
    pub fn src_port(&self) -> NonZero<u16> {
        match self {
            TcpUdp::Tcp(tcp) => tcp.source().into(),
            TcpUdp::Udp(udp) => udp.source().into(),
        }
    }

    /// Returns the destination port.
    #[must_use]
    pub fn dst_port(&self) -> NonZero<u16> {
        match self {
            TcpUdp::Tcp(tcp) => tcp.destination().into(),
            TcpUdp::Udp(udp) => udp.destination().into(),
        }
    }
}

/// Enum representing a mutable reference to a port-based transport header
/// ([`Tcp`] or [`Udp`]).
#[derive(Debug)]
pub enum TcpUdpMut<'a> {
    /// A [`Tcp`] header.
    Tcp(&'a mut Tcp),
    /// A [`Udp`] header.
    Udp(&'a mut Udp),
}

impl<'a> TryFrom<&'a mut Transport> for TcpUdpMut<'a> {
    type Error = TcpUdpError;
    fn try_from(value: &'a mut Transport) -> Result<Self, Self::Error> {
        match value {
            Transport::Tcp(tcp) => Ok(TcpUdpMut::Tcp(tcp)),
            Transport::Udp(udp) => Ok(TcpUdpMut::Udp(udp)),
            _ => Err(TcpUdpError::NotPortBased),
        }
    }
}

impl TcpUdpMut<'_> {
    /// Returns the source port.
    #[must_use]
    pub fn src_port(&self) -> NonZero<u16> {
        match self {
            TcpUdpMut::Tcp(tcp) => tcp.source().into(),
            TcpUdpMut::Udp(udp) => udp.source().into(),
        }
    }

    /// Returns the destination port.
    #[must_use]
    pub fn dst_port(&self) -> NonZero<u16> {
        match self {
            TcpUdpMut::Tcp(tcp) => tcp.destination().into(),
            TcpUdpMut::Udp(udp) => udp.destination().into(),
        }
    }

    /// Sets the source port.
    pub fn set_src_port(&mut self, port: NonZero<u16>) {
        match self {
            TcpUdpMut::Tcp(tcp) => {
                tcp.set_source(TcpPort::new(port));
            }
            TcpUdpMut::Udp(udp) => {
                udp.set_source(UdpPort::new(port));
            }
        }
    }

    /// Sets the destination port.
    pub fn set_dst_port(&mut self, port: NonZero<u16>) {
        match self {
            TcpUdpMut::Tcp(tcp) => {
                tcp.set_destination(TcpPort::new(port));
            }
            TcpUdpMut::Udp(udp) => {
                udp.set_destination(UdpPort::new(port));
            }
        }
    }
}

#[cfg(test)]
mod property_tests {
    //! Property tests for the [`TcpUdp`] / [`TcpUdpMut`] wrappers.
    //!
    //! The wrappers' raison d'etre is to make "this transport is definitely
    //! port-based" a type-level fact. These tests pin the invariants that
    //! claim rests on:
    //!
    //!  * `try_from` succeeds iff the underlying [`Transport`] is TCP or UDP.
    //!  * The wrapper's getters agree with what you'd read directly from the
    //!    underlying [`Transport`] (no value drift).
    //!  * `TcpUdpMut::set_*_port` round-trips through `*_port` and propagates
    //!    back to the underlying [`Transport`] (the wrapper is a *view*, not
    //!    a copy), and setting one direction does not perturb the other.
    //!
    //! All four invariants hold across the full domain via
    //! [`bolero`] generators for [`Transport`] (see
    //! `net::headers::transport_typegen_smoke`) and [`NonZero<u16>`].

    use super::{TcpUdp, TcpUdpError, TcpUdpMut};
    use crate::headers::Transport;
    use std::num::NonZero;

    fn is_port_based(t: &Transport) -> bool {
        matches!(t, Transport::Tcp(_) | Transport::Udp(_))
    }

    #[test]
    fn try_from_succeeds_iff_port_based() {
        bolero::check!().with_type::<Transport>().for_each(|t| {
            let mut t_mut = t.clone();
            let immut_ok = TcpUdp::try_from(t).is_ok();
            let mut_ok = TcpUdpMut::try_from(&mut t_mut).is_ok();
            assert_eq!(immut_ok, is_port_based(t));
            assert_eq!(mut_ok, is_port_based(t));
            if !is_port_based(t) {
                assert_eq!(TcpUdp::try_from(t).unwrap_err(), TcpUdpError::NotPortBased,);
            }
        });
    }

    #[test]
    fn view_reads_agree_with_transport() {
        bolero::check!().with_type::<Transport>().for_each(|t| {
            let Ok(tu) = TcpUdp::try_from(t) else {
                return;
            };
            assert_eq!(Some(tu.src_port()), t.src_port());
            assert_eq!(Some(tu.dst_port()), t.dst_port());
        });
    }

    #[test]
    fn mut_set_get_roundtrips_and_directions_are_independent() {
        bolero::check!()
            .with_type::<(Transport, NonZero<u16>, NonZero<u16>)>()
            .for_each(|(t, src, dst)| {
                let mut t = t.clone();
                let Ok(mut tu) = TcpUdpMut::try_from(&mut t) else {
                    return;
                };
                tu.set_src_port(*src);
                tu.set_dst_port(*dst);
                // The view sees what we just wrote.
                assert_eq!(tu.src_port(), *src);
                assert_eq!(tu.dst_port(), *dst);
                // Swap order in the second pass to catch any setter that
                // accidentally touches both ports.
                tu.set_dst_port(*src);
                tu.set_src_port(*dst);
                assert_eq!(tu.src_port(), *dst);
                assert_eq!(tu.dst_port(), *src);
            });
    }

    #[test]
    fn mut_writes_propagate_to_transport() {
        bolero::check!()
            .with_type::<(Transport, NonZero<u16>, NonZero<u16>)>()
            .for_each(|(t, src, dst)| {
                let mut t = t.clone();
                {
                    let Ok(mut tu) = TcpUdpMut::try_from(&mut t) else {
                        return;
                    };
                    tu.set_src_port(*src);
                    tu.set_dst_port(*dst);
                }
                // After the borrow ends, the underlying Transport reflects the writes.
                assert_eq!(t.src_port(), Some(*src));
                assert_eq!(t.dst_port(), Some(*dst));
            });
    }
}
