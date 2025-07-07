// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Static NAT address mapping

use routing::prefix::{Prefix, PrefixSize};
use std::collections::BTreeSet;
use std::net::IpAddr;
use std::net::{Ipv4Addr, Ipv6Addr};

/// Error type for [`IpList`] operations.
#[derive(thiserror::Error, Debug)]
pub enum IpListError {
    #[error("IP address {0} not in prefix {1}")]
    IpNotInPrefix(IpAddr, Prefix),
    #[error("Offset {0} too big for prefix {1}")]
    OffsetTooBig(u128, Prefix),
    #[error("Offset {0} not in list {1:?}")]
    OffsetNotInList(u128, IpList),
    #[error("IP version mismatch between address {0} and prefix {1}")]
    IpVersionMismatch(IpAddr, Prefix),
    #[error("Prefix {0} is malformed")]
    MalformedPrefix(Prefix),
    #[error("Offset {0} too big for list {1:?}")]
    MalformedIpList(u128, IpList),
}

#[derive(Debug, Clone)]
struct IpListPrefix {
    prefix: Prefix,
    size: PrefixSize,
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

    fn get_addr_within_block(prefix: &Prefix, offset: u128) -> Result<IpAddr, IpListError> {
        let start_addr = prefix.as_address();
        if let PrefixSize::U128(prefix_size) = prefix.size()
            && offset >= prefix_size
        {
            return Err(IpListError::OffsetTooBig(offset, *prefix));
        }
        match start_addr {
            IpAddr::V4(start) => {
                let Ok(offset_u32) = u32::try_from(offset) else {
                    return Err(IpListError::OffsetTooBig(offset, *prefix));
                };
                // Now we form and return the address, by adding the offset to the start address.
                let bits = start.to_bits() + offset_u32;
                Ok(IpAddr::V4(Ipv4Addr::from(bits)))
            }
            IpAddr::V6(start) => {
                let bits = start.to_bits() + offset;
                Ok(IpAddr::V6(Ipv6Addr::from(bits)))
            }
        }
    }

    pub fn addr_from_prefix_offset(
        &self,
        list_offset: &IpListOffset,
    ) -> Result<IpAddr, IpListError> {
        let offset = list_offset.offset;
        let mut block_offset: u128 = 0;
        match list_offset.ip_version {
            IpVersion::V4 => {
                for block in &self.blocks_v4 {
                    match block.size {
                        PrefixSize::U128(block_size) => {
                            // Make sure we don't overflow the IP space.
                            // The order of the terms for the addition and subtraction on the left
                            // side of the comparison is important, to avoid overflows.
                            if block_size > 0
                                && u128::from(u32::MAX) + 1 - block_size < block_offset
                            {
                                return Err(IpListError::MalformedIpList(offset, self.clone()));
                            }
                            // If our address is in this block, go find it an return it
                            if block_offset + block_size > offset {
                                return Self::get_addr_within_block(
                                    &block.prefix,
                                    offset - block_offset,
                                );
                            }
                            // Otherwise, increment the offset and keep looking
                            block_offset += block_size;
                        }
                        _ => {
                            return Err(IpListError::MalformedPrefix(block.prefix));
                        }
                    }
                }
                Err(IpListError::OffsetNotInList(
                    list_offset.offset,
                    self.clone(),
                ))
            }
            IpVersion::V6 => {
                for block in &self.blocks_v6 {
                    match block.size {
                        PrefixSize::U128(block_size) => {
                            // Make sure we don't overflow the IP space.
                            // The order of the terms in the addition and subtraction on the left
                            // side of the comparison is important, to avoid overflows.
                            if block_size > 0 && u128::MAX - block_size + 1 < block_offset {
                                return Err(IpListError::MalformedIpList(offset, self.clone()));
                            }
                            // If our address is in this block, go find it an return it
                            if block_offset + block_size > offset {
                                return Self::get_addr_within_block(
                                    &block.prefix,
                                    offset - block_offset,
                                );
                            }
                            // Otherwise, increment the offset and keep looking
                            block_offset += block_size;
                        }
                        PrefixSize::Ipv6MaxAddrs => {
                            if self.blocks_v6.len() > 1 {
                                return Err(IpListError::MalformedIpList(offset, self.clone()));
                            }
                            return Self::get_addr_within_block(&block.prefix, offset);
                        }
                        PrefixSize::Overflow => {
                            return Err(IpListError::MalformedPrefix(block.prefix));
                        }
                    }
                }
                Err(IpListError::OffsetNotInList(
                    list_offset.offset,
                    self.clone(),
                ))
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

    fn get_offset_within_block(&self, addr: &IpAddr) -> Result<u128, IpListError> {
        let prefix_size = self.prefix.size();
        match (addr, self.prefix.as_address()) {
            (IpAddr::V4(ip), IpAddr::V4(start)) => {
                let ip_bits = u128::from(ip.to_bits());
                let start_bits = u128::from(start.to_bits());

                if ip_bits < start_bits {
                    return Err(IpListError::IpNotInPrefix(*addr, self.prefix));
                }
                if ip_bits - start_bits >= prefix_size {
                    return Err(IpListError::IpNotInPrefix(*addr, self.prefix));
                }
                // We want the offset of the address within the block: the address converted to
                // bits, minus the address of the start of the block
                Ok(ip_bits - start_bits)
            }
            // See comments for v4
            (IpAddr::V6(ip), IpAddr::V6(start)) => {
                let ip_bits = ip.to_bits();
                let start_bits = start.to_bits();

                if ip_bits < start_bits {
                    return Err(IpListError::IpNotInPrefix(*addr, self.prefix));
                }
                if ip_bits - start_bits >= prefix_size {
                    return Err(IpListError::IpNotInPrefix(*addr, self.prefix));
                }
                Ok(ip_bits - start_bits)
            }
            _ => Err(IpListError::IpVersionMismatch(*addr, self.prefix)),
        }
    }

    pub fn addr_offset_in_prefix(&self, addr: &IpAddr) -> Result<IpListOffset, IpListError> {
        let offset_within_block = self.get_offset_within_block(addr)?;
        Ok(IpListOffset {
            offset: self.offset + offset_within_block,
            ip_version: match addr {
                IpAddr::V4(_) => IpVersion::V4,
                IpAddr::V6(_) => IpVersion::V6,
            },
        })
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

        let offset = ipls
            .addr_offset_in_prefix(&addr_v4("1.1.0.0"))
            .expect("Failed to get offset");
        assert_eq!(offset.offset, 0);

        let offset = ipls
            .addr_offset_in_prefix(&addr_v4("1.1.0.1"))
            .expect("Failed to get offset");
        assert_eq!(offset.offset, 1);

        let offset = ipls
            .addr_offset_in_prefix(&addr_v4("1.1.0.2"))
            .expect("Failed to get offset");
        assert_eq!(offset.offset, 2);

        let offset = ipls
            .addr_offset_in_prefix(&addr_v4("1.1.0.255"))
            .expect("Failed to get offset");
        assert_eq!(offset.offset, 255);

        let offset = ipls
            .addr_offset_in_prefix(&addr_v4("1.1.1.0"))
            .expect("Failed to get offset");
        assert_eq!(offset.offset, 256);

        let offset = ipls
            .addr_offset_in_prefix(&addr_v4("1.1.255.255"))
            .expect("Failed to get offset");
        assert_eq!(offset.offset, 65535);

        ipls.addr_offset_in_prefix(&addr_v4("1.2.0.0"))
            .expect_err("Address not in prefix");

        let ipls = IpListSubset::new(1, "0.0.0.0/1".into());

        let offset = ipls
            .addr_offset_in_prefix(&addr_v4("0.0.0.0"))
            .expect("Failed to get offset");
        assert_eq!(offset.offset, 1);

        let ipls = IpListSubset::new(0, "0.0.0.0/0".into());

        let offset = ipls
            .addr_offset_in_prefix(&addr_v4("0.0.0.0"))
            .expect("Failed to get offset");
        assert_eq!(offset.offset, 0);
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
            iplist
                .addr_from_prefix_offset(&IpListOffset {
                    offset: 0,
                    ip_version: IpVersion::V4
                })
                .expect("Failed to get address"),
            addr_v4("2.1.0.0")
        );

        assert_eq!(
            iplist
                .addr_from_prefix_offset(&IpListOffset {
                    offset: 1,
                    ip_version: IpVersion::V4
                })
                .expect("Failed to get address"),
            addr_v4("2.1.0.1")
        );

        assert_eq!(
            iplist
                .addr_from_prefix_offset(&IpListOffset {
                    offset: 256 * 4 + 1,
                    ip_version: IpVersion::V4
                })
                .expect("Failed to get address"),
            addr_v4("2.1.4.1")
        );

        assert_eq!(
            iplist
                .addr_from_prefix_offset(&IpListOffset {
                    offset: 65536,
                    ip_version: IpVersion::V4
                })
                .expect("Failed to get address"),
            addr_v4("2.2.0.0")
        );

        assert_eq!(
            iplist
                .addr_from_prefix_offset(&IpListOffset {
                    offset: 2 * 65536 + 256 * 5 + 1,
                    ip_version: IpVersion::V4
                })
                .expect("Failed to get address"),
            addr_v4("2.3.5.1")
        );

        assert_eq!(
            iplist
                .addr_from_prefix_offset(&IpListOffset {
                    offset: 3 * 65536 + 256 * (128 + 72) + 1,
                    ip_version: IpVersion::V4
                })
                .expect("Failed to get address"),
            addr_v4("2.5.72.1")
        );

        assert_eq!(
            iplist
                .addr_from_prefix_offset(&IpListOffset {
                    offset: 3 * 65536 + 256 * (128 + 127) + 255,
                    ip_version: IpVersion::V4
                })
                .expect("Failed to get address"),
            addr_v4("2.5.127.255")
        );

        iplist
            .addr_from_prefix_offset(&IpListOffset {
                offset: 3 * 65536 + 256 * (128 + 127) + 256,
                ip_version: IpVersion::V4,
            })
            .expect_err("Offset not in list");

        let target_prefixes = BTreeSet::from(["0.0.0.0/0".into()]);
        let iplist = IpList::new(&target_prefixes);
        assert_eq!(
            iplist
                .addr_from_prefix_offset(&IpListOffset {
                    offset: 0,
                    ip_version: IpVersion::V4,
                })
                .expect("Failed to get address"),
            addr_v4("0.0.0.0")
        );
    }
}
