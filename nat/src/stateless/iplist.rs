// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Static NAT address mapping

use routing::prefix::Prefix;
use std::collections::BTreeSet;
use std::net::IpAddr;
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone)]
struct IpListPrefix {
    prefix: Prefix,
    size: u128,
}

impl IpListPrefix {
    pub fn new(prefix: Prefix) -> Self {
        let size = prefix.size();
        Self { prefix, size }
    }
}

#[derive(Debug, Clone)]
pub struct IpList {
    blocks_v4: Vec<IpListPrefix>,
    blocks_v6: Vec<IpListPrefix>,
}

#[derive(Debug, Clone)]
enum IpVersion {
    V4,
    V6,
}

/// Encapsulates the offset of an address within an [`IpList`], to ensure it is only manipulated
/// with [`IpList`] methods.
#[derive(Debug, Clone)]
pub struct IpListOffset {
    offset: u128,
    ip_version: IpVersion,
}

impl IpList {
    pub fn new(prefixes: &BTreeSet<Prefix>) -> Self {
        let mut list = Self {
            blocks_v4: Vec::new(),
            blocks_v6: Vec::new(),
        };
        for prefix in prefixes {
            match prefix {
                Prefix::IPV4(_) => {
                    let ilp = IpListPrefix::new(*prefix);
                    list.blocks_v4.push(ilp);
                }
                Prefix::IPV6(_) => {
                    let ilp = IpListPrefix::new(*prefix);
                    list.blocks_v6.push(ilp);
                }
            }
        }
        list
    }

    fn get_addr_within_block(prefix: &Prefix, offset: u128) -> IpAddr {
        let start_addr = prefix.as_address();
        match start_addr {
            IpAddr::V4(start) => {
                let Ok(offset_u32) = u32::try_from(offset) else {
                    unreachable!("Offset {offset} too big, bug in IpList");
                };
                // Now we form and return the address, by adding the offset to the start address.
                let bits = start.to_bits() + offset_u32;
                IpAddr::V4(Ipv4Addr::from(bits))
            }
            IpAddr::V6(start) => {
                let bits = start.to_bits() + offset;
                IpAddr::V6(Ipv6Addr::from(bits))
            }
        }
    }

    pub fn addr_from_prefix_offset(&self, list_offset: &IpListOffset) -> IpAddr {
        let offset = list_offset.offset;
        let mut block_offset: u128 = 0;
        match list_offset.ip_version {
            IpVersion::V4 => {
                for block in &self.blocks_v4 {
                    // If our address is in this block, go find it an return it
                    if block_offset + block.size > offset {
                        return Self::get_addr_within_block(&block.prefix, offset - block_offset);
                    }
                    // Otherwise, keep incrementing the offset and keep looking
                    block_offset += block.size;
                }
                unreachable!("Failed to find address in IpList at offset {offset}")
            }
            IpVersion::V6 => {
                for block in &self.blocks_v6 {
                    if block_offset + block.size > offset {
                        return Self::get_addr_within_block(&block.prefix, offset - block_offset);
                    }
                    block_offset += block.size;
                }
                unreachable!("Failed to find address in IpList at offset {offset}")
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct IpListSubset {
    offset: u128,
    prefix: Prefix,
}

impl IpListSubset {
    pub fn new(offset: u128, prefix: Prefix) -> Self {
        Self { offset, prefix }
    }

    fn get_offset_within_block(&self, addr: &IpAddr) -> u128 {
        match (addr, self.prefix.as_address()) {
            (IpAddr::V4(ip), IpAddr::V4(start)) => {
                // We want the offset of the address within the block: the address converted to
                // bits, minus the address of the start of the block
                u128::from(ip.to_bits() - start.to_bits())
            }
            // See comments for v4
            (IpAddr::V6(ip), IpAddr::V6(start)) => ip.to_bits() - start.to_bits(),
            _ => {
                let bad_prefix = self.prefix;
                unreachable!(
                    "IpList comparing address and prefix of different IP versions ({addr}, {bad_prefix})"
                );
            }
        }
    }

    pub fn addr_offset_in_prefix(&self, addr: &IpAddr) -> IpListOffset {
        let offset_within_block = self.get_offset_within_block(addr);
        IpListOffset {
            offset: self.offset + offset_within_block,
            ip_version: match addr {
                IpAddr::V4(_) => IpVersion::V4,
                IpAddr::V6(_) => IpVersion::V6,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::net::{IpAddr, Ipv4Addr};
    use std::str::FromStr;

    fn addr_v4(s: &str) -> IpAddr {
        #[allow(clippy::expect_fun_call)]
        IpAddr::V4(Ipv4Addr::from_str(s).expect(format!("Invalid IPv4 address: {s}").as_str()))
    }

    #[test]
    fn test_iplist_subset() {
        let ipls = IpListSubset::new(0, "1.1.0.0/16".into());

        let offset = ipls.addr_offset_in_prefix(&addr_v4("1.1.0.0"));
        assert_eq!(offset.offset, 0);

        let offset = ipls.addr_offset_in_prefix(&addr_v4("1.1.0.1"));
        assert_eq!(offset.offset, 1);

        let offset = ipls.addr_offset_in_prefix(&addr_v4("1.1.0.2"));
        assert_eq!(offset.offset, 2);

        let offset = ipls.addr_offset_in_prefix(&addr_v4("1.1.0.255"));
        assert_eq!(offset.offset, 255);

        let offset = ipls.addr_offset_in_prefix(&addr_v4("1.1.1.0"));
        assert_eq!(offset.offset, 256);

        let offset = ipls.addr_offset_in_prefix(&addr_v4("1.1.255.255"));
        assert_eq!(offset.offset, 65535);

        // We should probably return an error in this case, but at the moment we don't
        let offset = ipls.addr_offset_in_prefix(&addr_v4("1.2.0.0"));
        assert_eq!(offset.offset, 65536);
    }

    #[test]
    fn test_iplist() {
        let target_prefixes = BTreeSet::from([
            "2.1.0.0/16".into(),
            "2.2.0.0/16".into(),
            "2.3.0.0/16".into(),
            "2.4.0.0/17".into(),
            "2.5.0.0/17".into(),
        ]);
        let iplist = IpList::new(&target_prefixes);

        assert_eq!(
            iplist.addr_from_prefix_offset(&IpListOffset {
                offset: 0,
                ip_version: IpVersion::V4
            }),
            addr_v4("2.1.0.0")
        );

        assert_eq!(
            iplist.addr_from_prefix_offset(&IpListOffset {
                offset: 1,
                ip_version: IpVersion::V4
            }),
            addr_v4("2.1.0.1")
        );

        assert_eq!(
            iplist.addr_from_prefix_offset(&IpListOffset {
                offset: 256 * 4 + 1,
                ip_version: IpVersion::V4
            }),
            addr_v4("2.1.4.1")
        );

        assert_eq!(
            iplist.addr_from_prefix_offset(&IpListOffset {
                offset: 65536,
                ip_version: IpVersion::V4
            }),
            addr_v4("2.2.0.0")
        );

        assert_eq!(
            iplist.addr_from_prefix_offset(&IpListOffset {
                offset: 2 * 65536 + 256 * 5 + 1,
                ip_version: IpVersion::V4
            }),
            addr_v4("2.3.5.1")
        );

        assert_eq!(
            iplist.addr_from_prefix_offset(&IpListOffset {
                offset: 3 * 65536 + 256 * (128 + 72) + 1,
                ip_version: IpVersion::V4
            }),
            addr_v4("2.5.72.1")
        );
    }
}
