//! Packet headers

use crate::parse::{DeParse, Parse, ParseWith, Step, StepWith};

#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[cfg(test)]
pub mod test {
    use super::*;

    // #[test]
    // #[traced_test]
    // fn check_serialize() {
    //     let eth = Eth::new(
    //         Mac([1, 2, 3, 4, 5, 6]),
    //         Mac([6, 5, 4, 3, 2, 1]),
    //         EtherType::VLAN_TAGGED_FRAME,
    //     );
    //     let vlan = [
    //         Vlan::new(Vid::new(17).unwrap(), EtherType::VLAN_TAGGED_FRAME),
    //         Vlan::new(Vid::new(27).unwrap(), EtherType::VLAN_TAGGED_FRAME),
    //         Vlan::new(Vid::new(2).unwrap(), EtherType::IPV4),
    //     ];
    //     let ipv4 = Ipv4::new();
    //     let mut buffer = [0_u8; 128];
    //     {
    //         let mut cursor = std::io::Cursor::new(&mut buffer[..]);
    //         eth.inner.write(&mut cursor).unwrap();
    //         vlan[0].inner.write(&mut cursor).unwrap();
    //         vlan[1].inner.write(&mut cursor).unwrap();
    //         vlan[2].inner.write(&mut cursor).unwrap();
    //         ipv4.inner.write(&mut cursor).unwrap();
    //     }
    //     let (packet, _) = Packet::parse(&buffer).unwrap();
    //     debug!("packet: {packet:?}");
    //     let mut buffer2 = [0_u8; 128];
    //     {
    //         let mut cursor = Writer::new(&mut buffer2[..]);
    //         cursor.write(&eth).unwrap();
    //         cursor.write(&vlan[0]).unwrap();
    //         cursor.write(&vlan[1]).unwrap();
    //         cursor.write(&vlan[2]).unwrap();
    //         cursor.write(&ipv4).unwrap();
    //     }
    //     let mut cursor = Reader::new(&buffer2[..]);
    //     let (packet2, size) = cursor.parse::<Packet>().unwrap();
    //     assert_eq!(packet, packet2);
    //     debug!("size: {size}");
    //     debug!("sizeof vlan: {size}", size = size_of::<Vlan>());
    //     debug!("sizeof packet: {size}", size = size_of::<Packet>());
    // }
}
