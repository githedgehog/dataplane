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

    fn get_offset_within_block(prefix: &Prefix, addr: &IpAddr) -> u128 {
        match (addr, prefix.as_address()) {
            (IpAddr::V4(ip), IpAddr::V4(start)) => {
                // We want the offset of the address within the block: the address converted to
                // bits, minus the address of the start of the block
                u128::from(ip.to_bits() - start.to_bits())
            }
            // See comments for v4
            (IpAddr::V6(ip), IpAddr::V6(start)) => ip.to_bits() - start.to_bits(),
            _ => unreachable!(
                "IpList comparing address and prefix of different IP versions ({addr}, {prefix})"
            ),
        }
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

    /// Returns the offset of the given address within the list of prefixes (adjusted to take
    /// excluded prefixes into account).
    pub fn addr_offset_in_prefix(&self, addr: &IpAddr) -> IpListOffset {
        match addr {
            IpAddr::V4(_) => {
                // Loop over blocks. If the address is not in that block, add the size of the block
                // to the offset and keep looking. When we find the block containing the address,
                // return the total offset: size of blocks skipped plus offset within current block.
                let mut offset_skipped = 0;
                for block in &self.blocks_v4 {
                    if block.prefix.covers_addr(addr) {
                        let offset_within_block =
                            Self::get_offset_within_block(&block.prefix, addr);
                        return IpListOffset {
                            offset: offset_skipped + offset_within_block,
                            ip_version: IpVersion::V4,
                        };
                    }
                    offset_skipped += block.size;
                }
                // Unless we have a bug in the construction of the NAT tables or IpList, we should
                // always find a block for the given IP
                unreachable!("Failed to find IpList block for IP {addr}")
            }
            // See comments for v4
            IpAddr::V6(_) => {
                let mut offset_skipped = 0;
                for block in &self.blocks_v6 {
                    if block.prefix.covers_addr(addr) {
                        let offset_within_block =
                            Self::get_offset_within_block(&block.prefix, addr);
                        return IpListOffset {
                            offset: offset_skipped + offset_within_block,
                            ip_version: IpVersion::V6,
                        };
                    }
                    offset_skipped += block.size;
                }
                unreachable!("Failed to find IpList block for IP {addr}")
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
    fn test_stuff() {
        let orig_prefixes = BTreeSet::from([
            "1.1.0.0/16".into(),
            "1.2.0.0/16".into(),
            "1.3.0.0/16".into(),
            "1.4.0.0/16".into(),
        ]);
        let target_prefixes = BTreeSet::from([
            "2.1.0.0/16".into(),
            "2.2.0.0/16".into(),
            "2.3.0.0/16".into(),
            "2.4.0.0/17".into(),
            "2.5.0.0/17".into(),
        ]);
        let orig_iplist = IpList::new(&orig_prefixes);
        let target_iplist = IpList::new(&target_prefixes);

        let test_data = [
            (addr_v4("1.1.0.1"), 1, addr_v4("2.1.0.1")),
            (addr_v4("1.1.4.1"), 256 * 4 + 1, addr_v4("2.1.4.1")),
            (
                addr_v4("1.3.5.1"),
                2 * 65536 + 256 * 5 + 1,
                addr_v4("2.3.5.1"),
            ),
            // prefixes with different sizes
            (
                addr_v4("1.4.200.1"),
                3 * 65536 + 256 * (128 + 72) + 1,
                addr_v4("2.5.72.1"),
            ),
        ];

        for tuple in test_data {
            println!("Tuple {tuple:?}");
            let offset = orig_iplist.addr_offset_in_prefix(&tuple.0);
            assert_eq!(offset.offset, tuple.1);

            println!("{offset:?}");
            let addr = target_iplist.addr_from_prefix_offset(&offset);
            assert_eq!(addr, tuple.2);
        }
    }
}
