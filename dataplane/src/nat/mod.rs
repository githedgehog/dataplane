// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![allow(dead_code)]

mod fabric;
mod iplist;
mod prefixtrie;

use crate::nat::fabric::{PeeringPolicy, Pif, Vpc};
use crate::nat::iplist::{IpList, IpListType};
use crate::nat::prefixtrie::PrefixTrie;
use crate::packet::Packet;

use net::buffer::PacketBufferMut;
use net::headers::Net;
use net::headers::{TryHeadersMut, TryIpMut};
use net::ipv4::UnicastIpv4Addr;
use net::ipv6::UnicastIpv6Addr;
use net::vxlan::Vni;
use std::collections::HashMap;
use std::fmt::Debug;
use std::net::IpAddr;

#[derive(Debug)]
#[allow(dead_code)]
struct GlobalContext {
    vpcs: HashMap<u32, Vpc>,
    global_pif_trie: PrefixTrie,
    peerings: HashMap<String, PeeringPolicy>,
}

impl GlobalContext {
    #[tracing::instrument(level = "trace")]
    fn new() -> Self {
        Self {
            vpcs: HashMap::new(),
            global_pif_trie: PrefixTrie::new(),
            peerings: HashMap::new(),
        }
    }

    #[tracing::instrument(level = "trace")]
    fn insert_vpc(&mut self, vni: Vni, vpc: Vpc) {
        vpc.iter_pifs().for_each(|pif| {
            pif.iter_ips().for_each(|prefix| {
                let _ = self.global_pif_trie.insert(prefix, pif.name().clone());
            });
        });
        let _ = self.vpcs.insert(vni.as_u32(), vpc);
    }

    #[tracing::instrument(level = "trace")]
    fn find_pif_by_ip(&self, ip: &IpAddr) -> Option<String> {
        self.global_pif_trie.find_ip(ip)
    }

    #[tracing::instrument(level = "trace")]
    fn get_vpc(&self, vni: Vni) -> Option<&Vpc> {
        self.vpcs.get(&vni.as_u32())
    }

    #[tracing::instrument(level = "trace")]
    fn find_pif_by_name(&self, name: &String) -> Option<&Pif> {
        self.vpcs.values().find_map(|vpc| vpc.get_pif(name))
    }

    #[tracing::instrument(level = "trace")]
    fn find_src_pif(&self, src_vpc_vni: Vni, dst_pif: &Pif, dst_ip: &IpAddr) -> Option<&Pif> {
        // Iterate on destination PIF's peering policies
        for peering_name in dst_pif.iter_peerings() {
            let peering = self.peerings.get(peering_name)?;
            let peer_pif_idx = peering.get_peer_index(dst_pif);
            let peer_pif_vni = peering.vnis()[peer_pif_idx];

            // Filter peering policies, discard if not attached to source VPC
            if peer_pif_vni != src_vpc_vni {
                continue;
            }

            // Retrieve destination PIF's peer PIF for the policy
            let src_vpc = self.get_vpc(src_vpc_vni)?;
            let peer_pif_name = &peering.pifs()[peer_pif_idx];
            let peer_pif = src_vpc.get_pif(peer_pif_name)?;

            // Search peer PIF's endpoints for packet's destination IP
            if peer_pif
                .iter_endpoints()
                .any(|endpoint| endpoint.covers_addr(dst_ip))
            {
                return Some(peer_pif);
            }
        }
        None
    }
}

#[tracing::instrument(level = "trace")]
fn get_src_addr(net: &Net) -> IpAddr {
    match net {
        Net::Ipv4(hdr) => IpAddr::V4(hdr.source().inner()),
        Net::Ipv6(hdr) => IpAddr::V6(hdr.source().inner()),
    }
}

#[tracing::instrument(level = "trace")]
fn get_dst_addr(net: &Net) -> IpAddr {
    match net {
        Net::Ipv4(hdr) => IpAddr::V4(hdr.destination()),
        Net::Ipv6(hdr) => IpAddr::V6(hdr.destination()),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum NatDirection {
    #[allow(dead_code)]
    SrcNat,
    #[allow(dead_code)]
    DstNat,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum NatMode {
    Stateless,
    #[allow(dead_code)]
    Stateful,
}

#[derive(Debug)]
pub struct Nat {
    context: GlobalContext,
    mode: NatMode,
    direction: NatDirection,
}

impl Nat {
    #[tracing::instrument(level = "trace")]
    pub fn new<Buf: PacketBufferMut>(direction: NatDirection, mode: NatMode) -> Self {
        let context = GlobalContext::new();
        Self {
            context,
            mode,
            direction,
        }
    }

    #[tracing::instrument(level = "trace")]
    pub fn add_vpc(&mut self, vni: Vni, vpc: Vpc) {
        self.context.insert_vpc(vni, vpc);
    }

    #[tracing::instrument(level = "trace")]
    pub fn add_peering_policy(&mut self, pp: PeeringPolicy) {
        self.context.peerings.insert(pp.name().clone(), pp);
    }

    #[tracing::instrument(level = "trace")]
    fn nat_supported(&self) -> bool {
        // We only support stateless NAT for now
        match self.mode {
            NatMode::Stateless => (),
            NatMode::Stateful => return false,
        }

        true
    }

    #[tracing::instrument(level = "trace")]
    fn nat_ranges_supported(&self, current_range: &IpList, target_range: &IpList) -> bool {
        // We only support NAT44 for now
        match (current_range.list_type(), target_range.list_type()) {
            (IpListType::Ipv4, IpListType::Ipv4) => (),
            _ => return false,
        }

        // Stateless NAT requires a 1:1 mapping, which means that both ranges
        // must include the same number of addresses.
        //
        // TODO: Move this check to configuration step.
        if self.mode == NatMode::Stateless && current_range.length() != target_range.length() {
            return false;
        }

        true
    }

    #[tracing::instrument(level = "trace")]
    fn find_dst_pif(&self, net: &Net) -> Option<&Pif> {
        self.context
            .find_pif_by_ip(&get_dst_addr(net))
            .and_then(|name| self.context.find_pif_by_name(&name))
    }

    #[tracing::instrument(level = "trace")]
    fn find_src_nat_ranges(&self, net: &Net, vni_opt: Option<Vni>) -> Option<(IpList, IpList)> {
        // For now we don't support NAT if we don't have a VNI
        let vni = vni_opt?;
        let dst_pif = self.find_dst_pif(net)?;
        let src_pif = self
            .context
            .find_src_pif(vni, dst_pif, &get_dst_addr(net))?;

        let current_range = IpList::from_prefixes(src_pif.iter_endpoints());
        let target_range = IpList::from_prefixes(src_pif.iter_ips());
        Some((current_range, target_range))
    }

    #[tracing::instrument(level = "trace")]
    fn find_dst_nat_ranges(&self, net: &Net) -> Option<(IpList, IpList)> {
        let dst_pif = self.find_dst_pif(net)?;
        let current_range = IpList::from_prefixes(dst_pif.iter_ips());
        let target_range = IpList::from_prefixes(dst_pif.iter_endpoints());
        Some((current_range, target_range))
    }

    #[tracing::instrument(level = "trace")]
    fn find_nat_ranges(&self, net: &mut Net, vni: Option<Vni>) -> Option<(IpList, IpList)> {
        match self.direction {
            NatDirection::SrcNat => self.find_src_nat_ranges(net, vni),
            NatDirection::DstNat => self.find_dst_nat_ranges(net),
        }
    }

    #[tracing::instrument(level = "trace")]
    fn translate(
        &self,
        net: &mut Net,
        current_range: &IpList,
        target_range: &IpList,
    ) -> Option<()> {
        let current_ip = match self.direction {
            NatDirection::SrcNat => get_src_addr(net),
            NatDirection::DstNat => get_dst_addr(net),
        };
        let offset = current_range.get_offset(&current_ip)?;
        let target_ip = target_range.get_addr(offset)?;

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

    fn process_packet<Buf: PacketBufferMut>(&self, packet: &mut Packet<Buf>) {
        if !self.nat_supported() {
            return;
        }

        // ----------------------------------------------------
        // TODO: Get VNI
        let vni = Vni::new_checked(100).ok();
        // ----------------------------------------------------
        let Some(net) = packet.headers_mut().try_ip_mut() else {
            return;
        };

        let ranges = self.find_nat_ranges(net, vni);
        let Some((current_range, target_range)) = ranges else {
            return;
        };

        if !self.nat_ranges_supported(&current_range, &target_range) {
            return;
        }

        self.translate(net, &current_range, &target_range);
    }
}
