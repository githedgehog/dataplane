// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use fixed_size::FixedSize;

use crate::ipv4::UnicastIpv4Addr;
use crate::tcp::TcpPort;
use crate::udp::UdpPort;
use crate::vxlan::Vni;

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
    const SIZE: usize = 4;
    fn write_be(&self, out: &mut [u8]) {
        self.inner().write_be(out);
    }
}

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
    fn vni_writes_four_bytes_with_zero_high_byte() {
        assert_eq!(<Vni as FixedSize>::SIZE, 4);
        let mut buf = [0u8; 4];
        Vni::new_checked(0x00AB_CDEF).unwrap().write_be(&mut buf);
        assert_eq!(buf, [0x00, 0xAB, 0xCD, 0xEF]);
    }
}
