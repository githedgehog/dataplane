// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use super::Nat;
use super::TrieValue;
use crate::nat::IpList;
use crate::nat::NatDirection;
use net::headers::Net;
use net::ipv4::UnicastIpv4Addr;
use net::ipv6::UnicastIpv6Addr;
use net::vxlan::Vni;
use std::net::IpAddr;

fn map_ip_src_nat(ranges: &TrieValue, current_ip: &IpAddr) -> IpAddr {
    let current_range = IpList::new(ranges.orig_prefixes(), ranges.orig_excludes());
    let target_range = IpList::new(ranges.target_prefixes(), ranges.target_excludes());
    let offset = current_range.addr_offset_in_prefix(current_ip);
    target_range.addr_from_prefix_offset(&offset)
}

fn map_ip_dst_nat(ranges: &TrieValue, current_ip: &IpAddr) -> IpAddr {
    let current_range = IpList::new(ranges.target_prefixes(), ranges.target_excludes());
    let target_range = IpList::new(ranges.orig_prefixes(), ranges.orig_excludes());
    let offset = current_range.addr_offset_in_prefix(current_ip);
    target_range.addr_from_prefix_offset(&offset)
}

impl Nat {
    fn find_src_nat_ranges(&self, net: &Net, vni: Vni) -> Option<&TrieValue> {
        let table = self.context.tables.get(&vni.as_u32())?;
        let src_ip = net.src_addr();
        table.lookup_src_prefixes(&src_ip)
    }

    fn find_dst_nat_ranges(&self, net: &Net, vni: Vni) -> Option<&TrieValue> {
        let table = self.context.tables.get(&vni.as_u32())?;
        let dst_ip = net.dst_addr();
        table.lookup_dst_prefixes(&dst_ip)
    }

    fn find_nat_ranges(&self, net: &mut Net, vni_opt: Option<Vni>) -> Option<&TrieValue> {
        let vni = vni_opt?;
        match self.direction {
            NatDirection::SrcNat => self.find_src_nat_ranges(net, vni),
            NatDirection::DstNat => self.find_dst_nat_ranges(net, vni),
        }
    }

    /// Applies network address translation to a packet, knowing the current and target ranges.
    fn translate(&self, net: &mut Net, ranges: &TrieValue) -> Option<()> {
        let target_ip = match self.direction {
            NatDirection::SrcNat => {
                let current_ip = net.src_addr();
                map_ip_src_nat(ranges, &current_ip)
            }
            NatDirection::DstNat => {
                let current_ip = net.dst_addr();
                map_ip_dst_nat(ranges, &current_ip)
            }
        };

        match self.direction {
            NatDirection::SrcNat => match (net, target_ip) {
                (Net::Ipv4(hdr), IpAddr::V4(ip)) => {
                    hdr.set_source(UnicastIpv4Addr::new(ip).ok()?);
                }
                (Net::Ipv6(hdr), IpAddr::V6(ip)) => {
                    hdr.set_source(UnicastIpv6Addr::new(ip).ok()?);
                }
                (_, _) => return None,
            },
            NatDirection::DstNat => match (net, target_ip) {
                (Net::Ipv4(hdr), IpAddr::V4(ip)) => {
                    hdr.set_destination(ip);
                }
                (Net::Ipv6(hdr), IpAddr::V6(ip)) => {
                    hdr.set_destination(ip);
                }
                (_, _) => return None,
            },
        }
        Some(())
    }

    pub(crate) fn stateless_nat(&self, net: &mut Net, vni: Option<Vni>) {
        let Some(ranges) = self.find_nat_ranges(net, vni) else {
            return;
        };
        self.translate(net, ranges);
    }
}
