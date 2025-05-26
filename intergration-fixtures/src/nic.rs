// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::ip::IpAssignment;
use derive_builder::Builder;
use futures_util::TryStreamExt;
use net::eth::mac::SourceMac;
use net::interface::{InterfaceIndex, InterfaceName};
use rtnetlink::packet_route::address::AddressAttribute;
use rtnetlink::packet_route::link::{InfoData, InfoKind, InfoVeth, LinkAttribute};
use rtnetlink::{Handle, LinkMessageBuilder, LinkVeth};
use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::sync::{Arc, Weak};
use test_utils::in_netns;

#[derive(Debug, Clone, Builder, PartialEq, Eq, Ord, PartialOrd, Hash)]
#[builder(public)]
pub struct NicSpec {
    name: InterfaceName,
    netns: PathBuf,
    #[builder(default = 1500)]
    mtu: u16,
    #[builder(default, setter(strip_option))]
    mac: Option<SourceMac>,
    #[builder(default)]
    #[builder(setter(into))]
    ipv4: BTreeSet<(Ipv4Addr, u8)>,
    #[builder(default)]
    #[builder(setter(into))]
    ipv6: BTreeSet<(Ipv6Addr, u8)>, // does not include link-local
}

#[derive(Debug, Clone, Builder, PartialEq, Eq, Ord, PartialOrd, Hash)]
#[builder(build_fn(skip), name = NicConnectionBuilder)]
pub struct NicConnectionSpec {
    from: NicSpec,
    to: NicSpec,
}

impl NicConnectionBuilder {
    pub fn new() -> NicConnectionBuilder {
        NicConnectionBuilder {
            from: None,
            to: None,
        }
    }
}

pub struct NicConnection {
    from: Arc<Nic>,
    to: Weak<Nic>,
}

impl NicConnection {
    fn specify() -> NicConnectionBuilder {
        NicConnectionBuilder::default()
    }
}

async fn get_addresses_for_interface(handle: Handle, name: InterfaceName) -> Vec<(IpAddr, u8)> {
    let link = {
        let mut req = handle.link().get().match_name(name.to_string()).execute();
        req.try_next().await.unwrap().unwrap()
    };
    let mut req = handle
        .address()
        .get()
        .set_link_index_filter(link.header.index)
        .execute();
    let mut addresses = vec![];
    while let Ok(Some(resp)) = req.try_next().await {
        for attr in resp.attributes {
            match attr {
                AddressAttribute::Address(ip) | AddressAttribute::Local(ip) => {
                    addresses.push((ip, resp.header.prefix_len))
                }
                _ => {}
            }
        }
    }
    addresses
}

impl NicConnectionBuilder {
    // #[fixin::wrap(with_caps([Capability::CAP_SYS_ADMIN, Capability::CAP_NET_ADMIN]))]
    pub fn build(self) -> Result<(NicConnection, NicConnection), ()> {
        match (self.from, self.to) {
            (Some(from), Some(to)) => {
                let from = from.clone();
                let to_clone = to.clone();
                let from_netns = PathBuf::from(from.netns.as_path());
                let from_netns_fd = std::fs::File::open(from.netns.as_path()).unwrap();
                let to_netns_fd = std::fs::File::open(to.netns.as_path()).unwrap();
                let from_nic = in_netns(from_netns.as_path(), move || async move {
                    let Ok((connection, handle, _)) = rtnetlink::new_connection() else {
                        panic!("failed to create connection");
                    };
                    tokio::spawn(connection);
                    let request =
                        LinkMessageBuilder::<LinkVeth>::new_with_info_kind(InfoKind::Veth)
                            .name(from.name.to_string())
                            .setns_by_fd(from_netns_fd.as_raw_fd())
                            .mtu(from.mtu as u32);
                    let peer_message = {
                        LinkMessageBuilder::<LinkVeth>::new_with_info_kind(InfoKind::Veth)
                            .name(to.name.to_string())
                            .mtu(to.mtu as u32)
                            .setns_by_fd(to_netns_fd.as_raw_fd())
                            .build()
                    };
                    let request = request
                        .set_info_data(InfoData::Veth(InfoVeth::Peer(peer_message)))
                        .build();
                    handle.link().add(request).execute().await.unwrap();
                    let mut response = handle
                        .link()
                        .get()
                        .match_name(from.name.to_string())
                        .execute();
                    let response = response.try_next().await.unwrap().unwrap();
                    let mut builder = NicBuilder::default();
                    builder
                        .index(response.header.index)
                        .netns(from.netns)
                        .name(from.name.clone())
                        .mtu(from.mtu);
                    for attr in &response.attributes {
                        match attr {
                            LinkAttribute::Address(addr) => {
                                builder.mac(SourceMac::try_from(addr).unwrap());
                            }
                            _ => continue,
                        }
                    }
                    for (ip, prefix) in from.ipv4.iter() {
                        handle
                            .address()
                            .add(response.header.index, (*ip).into(), *prefix)
                            .execute()
                            .await
                            .unwrap();
                    }
                    for (ip, prefix) in from.ipv6.iter() {
                        handle
                            .address()
                            .add(response.header.index, (*ip).into(), *prefix)
                            .execute()
                            .await
                            .unwrap();
                    }
                    let mut ipv4 = BTreeSet::new();
                    let mut ipv6 = BTreeSet::new();
                    for (addr, prefix) in
                        get_addresses_for_interface(handle, from.name.clone()).await
                    {
                        match addr {
                            IpAddr::V4(ip) => {
                                ipv4.insert((ip, prefix).into());
                            }
                            IpAddr::V6(ip) => {
                                ipv6.insert((ip, prefix).into());
                            }
                        }
                    }
                    builder.ipv4(ipv4);
                    builder.ipv6(ipv6);
                    builder.build().unwrap()
                });
                let to_netns = PathBuf::from(to_clone.netns.as_path());
                let to_nic = in_netns(to_netns.as_path(), move || async move {
                    let Ok((connection, handle, _)) = rtnetlink::new_connection() else {
                        panic!("failed to create connection");
                    };
                    tokio::spawn(connection);
                    let link = handle
                        .link()
                        .get()
                        .match_name(to_clone.name.to_string())
                        .execute()
                        .try_next()
                        .await
                        .unwrap()
                        .unwrap();
                    let mut builder = NicBuilder::default();
                    builder
                        .index(link.header.index)
                        .netns(to_clone.netns)
                        .name(to_clone.name.clone())
                        .mtu(to_clone.mtu);
                    for attr in &link.attributes {
                        match attr {
                            LinkAttribute::Address(addr) => {
                                builder.mac(SourceMac::try_from(addr).unwrap());
                            }
                            _ => continue,
                        }
                    }
                    for (ip, prefix) in to_clone.ipv4.iter() {
                        handle
                            .address()
                            .add(link.header.index, (*ip).into(), *prefix)
                            .execute()
                            .await
                            .unwrap();
                    }
                    for (ip, prefix) in to_clone.ipv6.iter() {
                        handle
                            .address()
                            .add(link.header.index, (*ip).into(), *prefix)
                            .execute()
                            .await
                            .unwrap();
                    }
                    let mut ipv4 = BTreeSet::new();
                    let mut ipv6 = BTreeSet::new();
                    for (addr, prefix) in get_addresses_for_interface(handle, to_clone.name).await {
                        match addr {
                            IpAddr::V4(ip) => {
                                ipv4.insert((ip, prefix).into());
                            }
                            IpAddr::V6(ip) => {
                                ipv6.insert((ip, prefix).into());
                            }
                        }
                    }
                    builder.ipv4(ipv4);
                    builder.ipv6(ipv6);
                    builder.build().unwrap()
                });
                let from_nic = Arc::new(from_nic);
                let to_nic = Arc::new(to_nic);
                let from_nic_weak = Arc::downgrade(&from_nic);
                let to_nic_weak = Arc::downgrade(&to_nic);
                Ok((
                    NicConnection {
                        from: from_nic,
                        to: to_nic_weak,
                    },
                    NicConnection {
                        from: to_nic,
                        to: from_nic_weak,
                    },
                ))
            }
            _ => panic!("missing from or to in NicConnectionBuilder"),
        }
    }
}

#[derive(Debug, Builder)]
#[builder(private)]
struct Nic {
    #[builder(setter(into))]
    index: InterfaceIndex,
    #[builder(setter(into))]
    netns: PathBuf,
    name: InterfaceName,
    mtu: u16,
    mac: SourceMac,
    #[builder(setter(into))]
    #[builder(default)]
    ipv4: BTreeSet<IpAssignment<Ipv4Addr>>,
    #[builder(setter(into))]
    #[builder(default)]
    ipv6: BTreeSet<IpAssignment<Ipv6Addr>>,
}

pub struct EthernetConnection {
    from: Arc<Nic>,
    to: Weak<Nic>,
}

impl NicConnectionSpec {
    // fn connect(spec: NicConnectionSpec) -> (Nic, Nic) {
    //     let netns_path = netns.as_ref();
    //     let this_netns = std::fs::File::open(netns_path).unwrap();
    //     let peer_netns_file = std::fs::File::open(peer_netns.as_ref()).unwrap();
    //     let message = LinkMessageBuilder::<LinkVeth>::new_with_info_kind(InfoKind::Veth)
    //         .name(spec.name.to_string())
    //         .mtu(spec.mtu as u32)
    //         .setns_by_fd(this_netns.as_raw_fd())
    //         .set_info_data(InfoData::Veth(InfoVeth::Peer(
    //             LinkMessageBuilder::<LinkVeth>::new_with_info_kind(InfoKind::Veth)
    //                 .name(peer.name.to_string())
    //                 .mtu(peer.mtu as u32)
    //                 .setns_by_fd(peer_netns_file.as_raw_fd())
    //                 .build(),
    //         )))
    //         .build();
    //     let netns_clone = PathBuf::from(netns.as_ref());
    //     let peer_netns_clone = PathBuf::from(peer_netns.as_ref());
    //     let near = in_netns(
    //         PathBuf::from(netns_clone.as_path()).as_path(),
    //         || async move {
    //             let Ok((connection, handle, _)) = rtnetlink::new_connection() else {
    //                 panic!("failed to create connection");
    //             };
    //             tokio::spawn(connection);
    //             handle.link().add(message).execute().await.unwrap();
    //             let req = handle.link().get().match_name(spec.name.to_string());
    //             let mut resp = req.execute();
    //             let resp = resp.try_next().await.unwrap().unwrap();
    //             handle
    //                 .link()
    //                 .set(LinkUnspec::new_with_index(resp.header.index).up().build())
    //                 .execute()
    //                 .await
    //                 .unwrap();
    //             let path_buf = PathBuf::from(netns_clone.as_path());
    //             let mut nic_builder = VEndBuilder::default();
    //             nic_builder
    //                 .name(spec.name)
    //                 .index(resp.header.index.into())
    //                 .netns(path_buf);
    //             for attr in &resp.attributes {
    //                 match attr {
    //                     LinkAttribute::Address(mac) => {
    //                         nic_builder.mac(SourceMac::try_from(mac).unwrap());
    //                     }
    //                     LinkAttribute::Mtu(mtu) => {
    //                         #[allow(clippy::cast_possible_truncation)] // not an issue with veth
    //                         nic_builder.mtu(*mtu as u16);
    //                     }
    //                     _ => continue,
    //                 }
    //             }
    //             let mut ipv4_assignments = BTreeSet::new();
    //             for (ip, prefix) in &spec.ipv4 {
    //                 let mut assignment = IpAddressAssignmentSpecBuilder::default();
    //                 let assignment = assignment.ip(*ip).prefix(*prefix).build().unwrap();
    //                 let assignment = IpAddressAssignment::new(
    //                     assignment,
    //                     nic_builder.index.unwrap(),
    //                     netns_clone.as_path(),
    //                 );
    //                 ipv4_assignments.insert(assignment);
    //             }
    //             let mut ipv6_assignments = BTreeSet::new();
    //             for (ip, prefix) in &spec.ipv6 {
    //                 let mut assignment = IpAddressAssignmentSpecBuilder::default();
    //                 let assignment = assignment.ip(*ip).prefix(*prefix).build().unwrap();
    //                 let assignment = IpAddressAssignment::new(
    //                     assignment,
    //                     nic_builder.index.unwrap(),
    //                     netns_clone.as_path(),
    //                 );
    //                 ipv6_assignments.insert(assignment);
    //             }
    //             let mut resp = handle
    //                 .address()
    //                 .get()
    //                 .set_link_index_filter(resp.header.index)
    //                 .execute();
    //             let Ok(Some(resp)) = resp.try_next().await else {
    //                 if spec.ipv6.is_empty() && spec.ipv4.is_empty() {
    //                     return Arc::new(nic_builder.build().unwrap());
    //                 }
    //                 panic!("wrong");
    //             };
    //             for attr in resp.attributes {
    //                 match attr {
    //                     AddressAttribute::Address(addr) | AddressAttribute::Local(addr) => {
    //                         match addr {
    //                             IpAddr::V4(ip) => {
    //                                 ipv4_assignments.insert(IpAddressAssignment {
    //                                     ip,
    //                                     prefix: resp.header.prefix_len,
    //                                 });
    //                             }
    //                             IpAddr::V6(ip) => {
    //                                 ipv6_assignments.insert(IpAddressAssignment {
    //                                     ip,
    //                                     prefix: resp.header.prefix_len,
    //                                 });
    //                             }
    //                         }
    //                     }
    //                     _ => continue,
    //                 }
    //             }
    //             Arc::new(
    //                 nic_builder
    //                     .ipv4(ipv4_assignments)
    //                     .ipv6(ipv6_assignments)
    //                     .build()
    //                     .unwrap(),
    //             )
    //         },
    //     );
    //     let far = in_netns(peer_netns_clone.clone().as_ref(), || async move {
    //         let Ok((connection, handle, _)) = rtnetlink::new_connection() else {
    //             panic!("failed to create connection");
    //         };
    //         tokio::spawn(connection);
    //         let req = handle.link().get().match_name(peer.name.to_string());
    //         let mut resp = req.execute();
    //         let resp = resp.try_next().await.unwrap().unwrap();
    //         handle
    //             .link()
    //             .set(LinkUnspec::new_with_index(resp.header.index).up().build())
    //             .execute()
    //             .await
    //             .unwrap();
    //         let path_buf = PathBuf::from(peer_netns_clone.as_path());
    //         let mut vend_builder = VEndBuilder::default();
    //         vend_builder
    //             .name(peer.name)
    //             .index(resp.header.index.into())
    //             .netns(path_buf);
    //         for attr in &resp.attributes {
    //             match attr {
    //                 LinkAttribute::Address(mac) => {
    //                     vend_builder.mac(SourceMac::try_from(mac).unwrap());
    //                 }
    //                 LinkAttribute::Mtu(mtu) => {
    //                     #[allow(clippy::cast_possible_truncation)] // not an issue with veth
    //                     vend_builder.mtu(*mtu as u16);
    //                 }
    //                 _ => continue,
    //             }
    //         }
    //         let mut ipv4_assignments = BTreeSet::new();
    //         for (ip, prefix) in peer.ipv4 {
    //             let mut assignment = IpAddressAssignmentSpecBuilder::default();
    //             let assignment = assignment.ip(ip).prefix(prefix).build().unwrap();
    //             let assignment = IpAddressAssignment::new(
    //                 assignment,
    //                 vend_builder.index.unwrap(),
    //                 peer_netns_clone.as_path(),
    //             );
    //             ipv4_assignments.insert(assignment);
    //         }
    //         let mut ipv6_assignments = BTreeSet::new();
    //         for (ip, prefix) in peer.ipv6 {
    //             let mut assignment = IpAddressAssignmentSpecBuilder::default();
    //             let assignment = assignment.ip(ip).prefix(prefix).build().unwrap();
    //             let assignment = IpAddressAssignment::new(
    //                 assignment,
    //                 vend_builder.index.unwrap(),
    //                 peer_netns_clone.as_path(),
    //             );
    //             ipv6_assignments.insert(assignment);
    //         }
    //         Arc::new(
    //             vend_builder
    //                 .ipv4(ipv4_assignments)
    //                 .ipv6(ipv6_assignments)
    //                 .build()
    //                 .unwrap(),
    //         )
    //     });
    //     let weak_near = Arc::downgrade(&near);
    //     let weak_far = Arc::downgrade(&far);
    //     let near = Nic {
    //         vend: near,
    //         peer: weak_far,
    //     };
    //     let far = Nic {
    //         vend: far,
    //         peer: weak_near,
    //     };
    //     (near, far)
    // }
}

#[cfg(test)]
mod tests {
    use super::*;
    use caps::Capability;
    use test_utils::fixin::wrap;
    use test_utils::with_caps;

    #[test]
    fn builder_test() {
        NicSpecBuilder::default()
            .name("x".try_into().unwrap())
            .mtu(9000)
            .ipv4([
                (Ipv4Addr::new(192, 168, 1, 1), 24),
                (Ipv4Addr::new(192, 168, 2, 1), 24),
                (Ipv4Addr::new(192, 168, 3, 1), 24),
            ])
            .ipv6([
                (Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 1, 0, 1), 96),
                (Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 2, 0, 1), 96),
                (Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 3, 0, 1), 96),
            ])
            .build()
            .unwrap();
    }

    #[test]
    fn builder_test2() {
        let from = NicSpecBuilder::default()
            .name("biscuit".try_into().unwrap())
            .mtu(9000)
            .ipv4([(Ipv4Addr::new(192, 168, 1, 1), 24)])
            .build()
            .unwrap();
        let to = NicSpecBuilder::default()
            .name("potato".try_into().unwrap())
            .mtu(9000)
            .ipv4([(Ipv4Addr::new(192, 168, 1, 2), 24)])
            .build()
            .unwrap();
        NicConnectionBuilder::new().from(from).to(to);
    }

    #[test]
    #[wrap(with_caps([Capability::CAP_SYS_ADMIN, Capability::CAP_NET_ADMIN]))]
    fn test2() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_io()
            .enable_time()
            .build()
            .unwrap();
        runtime.block_on(async move {
            rtnetlink::NetworkNamespace::add("potato".to_string())
                .await
                .unwrap();
            rtnetlink::NetworkNamespace::add("biscuit".to_string())
                .await
                .unwrap();
            let mut potato_netns_path = PathBuf::new();
            potato_netns_path.push("/run/netns/potato");
            let mut biscuit_netns_path = PathBuf::new();
            biscuit_netns_path.push("/run/netns/biscuit");
            let x1 = NicSpecBuilder::default()
                .name("x1".try_into().unwrap())
                .mtu(9000)
                .ipv4([(Ipv4Addr::new(192, 168, 1, 1), 24)])
                .ipv6([(Ipv6Addr::new(0xdead, 0xbeef, 0, 0, 0, 0, 0, 1), 96)])
                .netns(potato_netns_path)
                .build()
                .unwrap();
            let y1 = NicSpecBuilder::default()
                .name("y1".try_into().unwrap())
                .mtu(9000)
                .ipv4([(Ipv4Addr::new(192, 168, 1, 2), 24)])
                .ipv6([(Ipv6Addr::new(0xdead, 0xbeef, 0, 0, 0, 0, 0, 2), 96)])
                .netns(biscuit_netns_path)
                .build()
                .unwrap();
            let mut nic_builder = NicConnectionBuilder::new();
            nic_builder.from(x1).to(y1);
            nic_builder.build().unwrap();
        })
    }
}
