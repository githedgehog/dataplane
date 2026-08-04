// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use std::net::{Ipv4Addr, Ipv6Addr};

use fixed_size::{FixedSize, MaskBits};

use crate::ip::NextHeader;
use crate::ipv4::UnicastIpv4Addr;
use crate::ipv6::UnicastIpv6Addr;
use crate::tcp::TcpPort;
use crate::udp::UdpPort;
use crate::vxlan::Vni;

/// One byte, and exactly the wire byte: an IP protocol number is 8 bits wherever it appears.
/// (Contrast [`Vni`] below, whose key encoding is padded.)
impl FixedSize for NextHeader {
    const SIZE: usize = 1;
    fn write_be(&self, out: &mut [u8]) {
        self.as_u8().write_be(out);
    }
}

/// Every 8-bit pattern is a valid protocol number, which is what makes `NextHeader` sound to mask.
/// Neither constant is a protocol: they let a rule say "every bit" or "no bit" without a caller
/// writing `NextHeader::new(0xff)` and implying protocol 255.
impl MaskBits for NextHeader {
    const ALL_BITS: Self = NextHeader::new(u8::MAX);
    const NO_BITS: Self = NextHeader::new(0);
}

impl FixedSize for TcpPort {
    const SIZE: usize = 2;
    fn write_be(&self, out: &mut [u8]) {
        self.as_u16().write_be(out);
    }
}

impl FixedSize for UdpPort {
    const SIZE: usize = 2;
    fn write_be(&self, out: &mut [u8]) {
        self.as_u16().write_be(out);
    }
}

impl FixedSize for UnicastIpv4Addr {
    const SIZE: usize = Ipv4Addr::SIZE;
    fn write_be(&self, out: &mut [u8]) {
        self.inner().write_be(out);
    }
}

impl FixedSize for UnicastIpv6Addr {
    const SIZE: usize = Ipv6Addr::SIZE;

    fn write_be(&self, out: &mut [u8]) {
        self.inner().write_be(out);
    }
}

/// The VNI right-aligned in **4** big-endian bytes, leading byte always zero.
///
/// # Note
///
/// This is deliberately *not* the VXLAN wire encoding, which is 24 bits (3 bytes). `FixedSize`
/// exists to lay values out as classifier (match/action) key fields, and a classifier field must
/// be 1, 2, or 4 bytes wide -- `rte_acl` rejects anything else when the table is built -- so there
/// is no 3-byte option to pick. Do not reach for [`FixedSize::write_be`] to serialize a VXLAN
/// header: it will write a byte too many.
impl FixedSize for Vni {
    const SIZE: usize = 4;
    fn write_be(&self, out: &mut [u8]) {
        self.as_u32().write_be(out);
    }
}

#[cfg(test)]
mod tests {
    use core::net::Ipv4Addr;

    use super::*;

    #[test]
    fn ports_write_two_big_endian_bytes() {
        assert_eq!(<TcpPort as FixedSize>::SIZE, 2);
        assert_eq!(<UdpPort as FixedSize>::SIZE, 2);
        let mut buf = [0u8; 2];
        TcpPort::new_checked(443).unwrap().write_be(&mut buf);
        assert_eq!(buf, 443u16.to_be_bytes());
        UdpPort::new_checked(4789).unwrap().write_be(&mut buf);
        assert_eq!(buf, 4789u16.to_be_bytes());
    }

    #[test]
    fn unicast_v4_writes_four_octets() {
        assert_eq!(<UnicastIpv4Addr as FixedSize>::SIZE, 4);
        let mut buf = [0u8; 4];
        UnicastIpv4Addr::new(Ipv4Addr::new(10, 0, 1, 2))
            .unwrap()
            .write_be(&mut buf);
        assert_eq!(buf, [10, 0, 1, 2]);
    }

    #[test]
    fn next_header_writes_one_wire_byte() {
        assert_eq!(<NextHeader as FixedSize>::SIZE, 1);
        let mut buf = [0u8; 1];
        NextHeader::TCP.write_be(&mut buf);
        assert_eq!(buf, [NextHeader::TCP.as_u8()]);
    }

    #[test]
    fn vni_writes_four_bytes_with_zero_high_byte() {
        assert_eq!(<Vni as FixedSize>::SIZE, 4);
        let mut buf = [0u8; 4];
        Vni::new_checked(0x00AB_CDEF).unwrap().write_be(&mut buf);
        assert_eq!(buf, [0x00, 0xAB, 0xCD, 0xEF]);
    }
}
