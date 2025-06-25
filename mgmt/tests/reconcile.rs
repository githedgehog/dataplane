// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use dataplane_mgmt as mgmt;
use std::collections::HashSet;

use caps::Capability;
use fixin::wrap;
use futures::TryStreamExt;
use interface_manager::Manager;
use interface_manager::interface::fdb::{FdbAction, FdbEntryBuilder, MultiIndexFdbMap};
use interface_manager::interface::{
    BridgePropertiesSpec, InterfaceAssociationSpec, InterfacePropertiesSpec, InterfaceSpecBuilder,
    MultiIndexBridgePropertiesSpecMap, MultiIndexInterfaceAssociationSpecMap,
    MultiIndexInterfaceSpecMap, MultiIndexPciNetdevPropertiesSpecMap,
    MultiIndexVrfPropertiesSpecMap, MultiIndexVtepPropertiesSpecMap, PciNetdevPropertiesSpec,
    VrfPropertiesSpec, VtepPropertiesSpec,
};
use interface_manager::tc::action::gact::{GenericAction, GenericActionSpec};
use interface_manager::tc::action::mirred::{Mirred, MirredSpec};
use interface_manager::tc::action::tunnel_key::{
    TunnelChecksum, TunnelKey, TunnelKeyDetails, TunnelKeySetBuilder, TunnelKeySpecBuilder,
};
use interface_manager::tc::action::{
    Action, ActionDetailsSpec, ActionIndex, ActionKind, ActionSpec,
};
use interface_manager::tc::block::BlockIndex;
use interface_manager::tc::filter::{Filter, FilterIndex, FilterSpecBuilder};
use interface_manager::tc::qdisc::{Qdisc, QdiscProperties, QdiscSpec};
use mgmt::vpc_manager::{RequiredInformationBase, RequiredInformationBaseBuilder, VpcManager};
use net::eth::ethtype::EthType;
use net::eth::mac::Mac;
use net::interface::{AdminState, InterfaceIndex, InterfaceProperties};
use net::ipv4::UnicastIpv4Addr;
use net::pci::PciEbdf;
use net::vxlan::{Vni, Vxlan};
use rekon::{Create, Remove};
use rekon::{Observe, Reconcile};
use rtnetlink::packet_route::neighbour::{NeighbourAddress, NeighbourAttribute, NeighbourFlags};
use rtnetlink::packet_route::tc::TcFilterFlowerOption::{
    Actions, EncKeyId, EncKeyIpv4Dst, EncKeyUdpDstPort, Flags,
};
use rtnetlink::packet_route::tc::{
    TcAction, TcActionAttribute, TcActionGeneric, TcActionGenericOption, TcActionMirrorOption,
    TcActionOption, TcActionTunnelKeyOption, TcActionType, TcFilterFlowerOption,
    TcFlowerOptionFlags, TcMirror, TcMirrorActionType, TcTunnelKey,
};
use rtnetlink::sys::AsyncSocket;
use std::net::Ipv4Addr;
use std::num::NonZero;
use std::sync::Arc;
use std::time::Duration;
use test_utils::with_caps;
use tracing::{debug, error, info, trace};
use tracing_test::traced_test;

#[test]
#[wrap(with_caps([Capability::CAP_NET_ADMIN]))]
#[traced_test]
fn reconcile_fuzz() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .unwrap();

    let handle = runtime.block_on(async {
        let Ok((connection, handle, _)) = rtnetlink::new_connection() else {
            panic!("failed to create connection");
        };
        tokio::spawn(connection);
        std::sync::Mutex::new(Arc::new(handle))
    });
    bolero::check!()
        .with_type()
        .with_test_time(Duration::from_secs(2))
        .for_each(|rib: &RequiredInformationBase| {
            runtime.block_on(async {
                let handle = match handle.lock() {
                    Ok(guard) => (*guard).clone(),
                    Err(poison) => {
                        panic!("mutex poisoned: {poison}");
                    }
                };
                let mut rib = rib.clone();
                let manager = VpcManager::<RequiredInformationBase>::new(handle);
                let mut required_passes = 0;
                while !manager
                    .reconcile(&mut rib, &manager.observe().await.unwrap())
                    .await
                {
                    required_passes += 1;
                    if required_passes >= 30 {
                        panic!("took more than 30 passes to reconcile")
                    }
                }
                assert!(
                    manager
                        .reconcile(&mut rib, &manager.observe().await.unwrap())
                        .await
                )
            });
        });
}

#[allow(clippy::too_many_lines)] // this is an integration test and is expected to be long
#[tokio::test]
#[wrap(with_caps([Capability::CAP_NET_ADMIN]))]
#[traced_test]
async fn reconcile_demo() {
    let mut required_interface_map = MultiIndexInterfaceSpecMap::default();
    let interfaces = [
        InterfaceSpecBuilder::default()
            .name("vrf1".try_into().unwrap())
            .admin_state(AdminState::Up)
            .properties(InterfacePropertiesSpec::Vrf(VrfPropertiesSpec {
                route_table_id: 1.try_into().unwrap(),
            }))
            .build()
            .unwrap(),
        InterfaceSpecBuilder::default()
            .name("vrf2".try_into().unwrap())
            .admin_state(AdminState::Up)
            .properties(InterfacePropertiesSpec::Vrf(VrfPropertiesSpec {
                route_table_id: 2.try_into().unwrap(),
            }))
            .build()
            .unwrap(),
        InterfaceSpecBuilder::default()
            .name("vtep1".try_into().unwrap())
            .admin_state(AdminState::Up)
            .properties(InterfacePropertiesSpec::Vtep(VtepPropertiesSpec {
                vni: 1.try_into().unwrap(),
                local: "192.168.5.155"
                    .parse::<Ipv4Addr>()
                    .unwrap()
                    .try_into()
                    .unwrap(),
                ttl: 64,
                port: Vxlan::PORT,
            }))
            .build()
            .unwrap(),
        InterfaceSpecBuilder::default()
            .name("vtep2".try_into().unwrap())
            .admin_state(AdminState::Up)
            .properties(InterfacePropertiesSpec::Vtep(VtepPropertiesSpec {
                vni: 2.try_into().unwrap(),
                local: "192.168.5.155"
                    .parse::<Ipv4Addr>()
                    .unwrap()
                    .try_into()
                    .unwrap(),
                ttl: 64,
                port: Vxlan::PORT,
            }))
            .build()
            .unwrap(),
        InterfaceSpecBuilder::default()
            .name("br1".try_into().unwrap())
            .admin_state(AdminState::Up)
            .properties(InterfacePropertiesSpec::Bridge(BridgePropertiesSpec {
                vlan_protocol: EthType::VLAN,
                vlan_filtering: false,
            }))
            .build()
            .unwrap(),
        InterfaceSpecBuilder::default()
            .name("br2".try_into().unwrap())
            .admin_state(AdminState::Up)
            .properties(InterfacePropertiesSpec::Bridge(BridgePropertiesSpec {
                vlan_protocol: EthType::VLAN,
                vlan_filtering: false,
            }))
            .build()
            .unwrap(),
    ];

    for interface in interfaces {
        required_interface_map.try_insert(interface).unwrap();
    }

    let mut vtep_props = MultiIndexVtepPropertiesSpecMap::default();
    let mut bridge_props = MultiIndexBridgePropertiesSpecMap::default();
    let mut vrf_props = MultiIndexVrfPropertiesSpecMap::default();
    let mut pci_props = MultiIndexPciNetdevPropertiesSpecMap::default();

    for (_, interface) in required_interface_map.iter() {
        match &interface.properties {
            InterfacePropertiesSpec::Vtep(prop) => {
                vtep_props.try_insert(prop.clone()).unwrap();
            }
            InterfacePropertiesSpec::Bridge(prop) => {
                bridge_props.try_insert(prop.clone()).unwrap();
            }
            InterfacePropertiesSpec::Vrf(prop) => {
                vrf_props.try_insert(prop.clone()).unwrap();
            }
            InterfacePropertiesSpec::Pci(prop) => {
                pci_props.try_insert(prop.clone()).unwrap();
            }
        }
    }

    let mut associations = MultiIndexInterfaceAssociationSpecMap::default();
    associations
        .try_insert(InterfaceAssociationSpec {
            name: "vtep1".to_string().try_into().unwrap(),
            controller_name: Some("br1".to_string().try_into().unwrap()),
        })
        .unwrap();
    associations
        .try_insert(InterfaceAssociationSpec {
            name: "vtep2".to_string().try_into().unwrap(),
            controller_name: Some("br2".to_string().try_into().unwrap()),
        })
        .unwrap();
    associations
        .try_insert(InterfaceAssociationSpec {
            name: "br1".to_string().try_into().unwrap(),
            controller_name: Some("vrf1".to_string().try_into().unwrap()),
        })
        .unwrap();
    associations
        .try_insert(InterfaceAssociationSpec {
            name: "br2".to_string().try_into().unwrap(),
            controller_name: Some("vrf2".to_string().try_into().unwrap()),
        })
        .unwrap();

    let mut required = RequiredInformationBaseBuilder::default()
        .interfaces(required_interface_map)
        .vteps(vtep_props)
        .vrfs(vrf_props)
        .pci_netdevs(pci_props)
        .associations(associations)
        .build()
        .unwrap();

    let Ok((mut connection, handle, _recv)) = rtnetlink::new_connection() else {
        panic!("failed to create connection");
    };
    connection
        .socket_mut()
        .socket_mut()
        .set_rx_buf_sz(812_992)
        .unwrap();
    tokio::spawn(connection);

    let inject_new_requirements = move |req: &mut RequiredInformationBase| {
        let interfaces = [
            InterfaceSpecBuilder::default()
                .name("vtep3".try_into().unwrap())
                .admin_state(AdminState::Up)
                .controller(None)
                .properties(InterfacePropertiesSpec::Vtep(VtepPropertiesSpec {
                    vni: 3.try_into().unwrap(),
                    local: "192.168.5.155"
                        .parse::<Ipv4Addr>()
                        .unwrap()
                        .try_into()
                        .unwrap(),
                    ttl: 64,
                    port: Vxlan::PORT,
                }))
                .build()
                .unwrap(),
            InterfaceSpecBuilder::default()
                .name("br3".try_into().unwrap())
                .admin_state(AdminState::Up)
                .controller(None)
                .properties(InterfacePropertiesSpec::Bridge(BridgePropertiesSpec {
                    vlan_protocol: EthType::VLAN,
                    vlan_filtering: false,
                }))
                .build()
                .unwrap(),
            InterfaceSpecBuilder::default()
                .name("vrf3".try_into().unwrap())
                .admin_state(AdminState::Up)
                .controller(None)
                .properties(InterfacePropertiesSpec::Vrf(VrfPropertiesSpec {
                    route_table_id: 3.try_into().unwrap(),
                }))
                .build()
                .unwrap(),
        ];
        for interface in interfaces {
            match &interface.properties {
                InterfacePropertiesSpec::Bridge(_) => {}
                InterfacePropertiesSpec::Vtep(props) => {
                    req.vteps.try_insert(props.clone()).unwrap();
                }
                InterfacePropertiesSpec::Vrf(props) => {
                    req.vrfs.try_insert(props.clone()).unwrap();
                }
                InterfacePropertiesSpec::Pci(props) => {
                    req.pci_netdevs.try_insert(props.clone()).unwrap();
                }
            }
            req.interfaces.try_insert(interface).unwrap();
        }
        req.associations
            .try_insert(InterfaceAssociationSpec {
                name: "br3".to_string().try_into().unwrap(),
                controller_name: Some("vrf3".to_string().try_into().unwrap()),
            })
            .unwrap();
        req.associations
            .try_insert(InterfaceAssociationSpec {
                name: "vtep3".to_string().try_into().unwrap(),
                controller_name: Some("br3".to_string().try_into().unwrap()),
            })
            .unwrap();
    };

    let remove_some_requirement = move |req: &mut RequiredInformationBase| {
        req.interfaces
            .remove_by_name(&"br1".to_string().try_into().unwrap())
            .unwrap();
        req.interfaces
            .remove_by_name(&"vrf1".to_string().try_into().unwrap())
            .unwrap();
        req.interfaces
            .remove_by_name(&"vtep1".to_string().try_into().unwrap())
            .unwrap();
        req.associations
            .remove_by_name(&"br1".to_string().try_into().unwrap())
            .unwrap();
        req.associations
            .remove_by_name(&"vtep1".to_string().try_into().unwrap())
            .unwrap();
    };

    let vpcs = VpcManager::<RequiredInformationBase>::new(Arc::new(handle));

    for _ in 0..10 {
        let observed = vpcs.observe().await.unwrap();
        vpcs.reconcile(&mut required, &observed).await;
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    info!("injecting new requirements");
    inject_new_requirements(&mut required);
    for _ in 0..20 {
        let observed = vpcs.observe().await.unwrap();
        vpcs.reconcile(&mut required, &observed).await;
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    info!("removing some requirements");
    remove_some_requirement(&mut required);
    for _ in 0..20 {
        let observed = vpcs.observe().await.unwrap();
        vpcs.reconcile(&mut required, &observed).await;
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[allow(clippy::too_many_lines)] // this is an integration test and is expected to be long
#[tokio::test]
#[wrap(with_caps([Capability::CAP_NET_ADMIN]))]
// #[wrap(run_in_netns("biscuit"))]
#[traced_test]
async fn tc_actions_demo() {
    let (mut connection, handle, _recv) = rtnetlink::new_connection().unwrap();
    connection
        .socket_mut()
        .socket_mut()
        .set_rx_buf_sz(812_992)
        .unwrap();
    tokio::spawn(connection);
    let handle = Arc::new(handle);

    let manager = Manager::<Action>::new(handle.clone());
    let x = ActionSpec {
        details: ActionDetailsSpec::TunnelKey({
            let mut tunnel_key = TunnelKeySpecBuilder::default();
            let mut encap = TunnelKeySetBuilder::default();
            encap
                .dst(UnicastIpv4Addr::new(Ipv4Addr::new(192, 168, 1, 1)).unwrap())
                .src(UnicastIpv4Addr::new(Ipv4Addr::new(192, 168, 1, 2)).unwrap())
                .id(Vni::try_from(11).unwrap());
            let encap = encap.build().unwrap();
            tunnel_key
                .index(ActionIndex::try_new(17).unwrap())
                .details(TunnelKeyDetails::Set(encap));
            tunnel_key.build().unwrap()
        }),
    };
    manager.create(&x).await.unwrap();
    let y = ActionSpec {
        details: ActionDetailsSpec::TunnelKey({
            let mut tunnel_key = TunnelKeySpecBuilder::default();
            tunnel_key
                .index(ActionIndex::try_new(18).unwrap())
                .details(TunnelKeyDetails::Unset);
            tunnel_key.build().unwrap()
        }),
    };
    manager.create(&y).await.unwrap();
    let manager2 = Manager::<TunnelKey>::new(handle.clone());
    manager2.observe().await;
}

#[allow(clippy::too_many_lines)] // this is an integration test and is expected to be long
#[tokio::test]
#[wrap(with_caps([Capability::CAP_NET_ADMIN]))]
// #[wrap(run_in_netns("biscuit"))]
#[traced_test]
async fn tc_actions_demo2() {
    let (mut connection, handle, _recv) = rtnetlink::new_connection().unwrap();
    connection
        .socket_mut()
        .socket_mut()
        .set_rx_buf_sz(812_992)
        .unwrap();
    tokio::spawn(connection);
    let handle = Arc::new(handle);

    handle
        .traffic_filter(228)
        .replace()
        .ingress()
        .priority(19010)
        .protocol(0x0003u16.to_be())
        .flower(&[
            // Flags(TcFlowerOptionFlags::SkipSw),
            EncKeyId(2),
            EncKeyIpv4Dst(Ipv4Addr::new(172, 18, 10, 1)),
            EncKeyUdpDstPort(4789),
            Actions(vec![
                {
                    let mut unset = TcAction::default();
                    unset.tab = 1;
                    unset
                        .attributes
                        .push(TcActionAttribute::Kind("tunnel_key".into()));
                    unset.attributes.push(TcActionAttribute::Options(vec![
                        TcActionOption::TunnelKey(TcActionTunnelKeyOption::Parms(TcTunnelKey {
                            t_action: 2, // tunnel key unset
                            ..Default::default()
                        })),
                    ]));
                    unset
                },
                {
                    let mut mirror = TcAction::default();
                    mirror.tab = 2;
                    mirror
                        .attributes
                        .push(TcActionAttribute::Kind("gact".into()));
                    mirror.attributes.push(TcActionAttribute::Options(vec![
                        TcActionOption::Generic(TcActionGenericOption::Parms({
                            let mut params = TcActionGeneric::default();
                            params.action = TcActionType::Trap;
                            params.refcnt = 1;
                            params
                        })),
                    ]));
                    mirror
                },
                // {
                //     let mut mirror = TcAction::default();
                //     mirror.tab = 2;
                //     mirror
                //         .attributes
                //         .push(TcActionAttribute::Kind("mirred".into()));
                //     mirror.attributes.push(TcActionAttribute::Options(vec![
                //         TcActionOption::Mirror(TcActionMirrorOption::Parms({
                //             let mut params = TcMirror::default();
                //             params.generic.index = 0;
                //             params.eaction = TcMirrorActionType::EgressRedir;
                //             params.ifindex = 107;
                //             params.generic.action = TcActionType::Stolen;
                //             params
                //         })),
                //     ]));
                //     mirror
                // },
            ]),
        ])
        .unwrap()
        .execute()
        .await
        .unwrap();
}

#[allow(clippy::too_many_lines)] // this is an integration test and is expected to be long
#[tokio::test]
#[wrap(with_caps([Capability::CAP_NET_ADMIN]))]
// #[wrap(run_in_netns("biscuit"))]
#[traced_test]
async fn tc_actions_demo3() {
    let (mut connection, handle, _recv) = rtnetlink::new_connection().unwrap();
    connection
        .socket_mut()
        .socket_mut()
        .set_rx_buf_sz(812_992)
        .unwrap();
    tokio::spawn(connection);
    let handle = Arc::new(handle);

    handle
        .traffic_filter(58)
        .replace()
        .ingress()
        .priority(9989)
        .protocol(0x0003u16.to_be())
        .flower(&[
            EncKeyId(2),
            EncKeyIpv4Dst(Ipv4Addr::new(172, 18, 10, 1)),
            EncKeyUdpDstPort(4789),
            Actions(vec![
                {
                    let mut unset = TcAction::default();
                    unset.tab = 1;
                    unset.attributes.push(TcActionAttribute::Index(56));
                    unset
                        .attributes
                        .push(TcActionAttribute::Kind("tunnel_key".into()));
                    unset.attributes.push(TcActionAttribute::Options(vec![
                        TcActionOption::TunnelKey(TcActionTunnelKeyOption::Parms(TcTunnelKey {
                            t_action: 2, // tunnel key unset
                            generic: {
                                let mut generic = TcActionGeneric::default();
                                generic.index = 558;
                                generic
                            },
                        })),
                    ]));
                    unset
                },
                {
                    let mut mirror = TcAction::default();
                    mirror.tab = 2;
                    mirror
                        .attributes
                        .push(TcActionAttribute::Kind("mirred".into()));
                    mirror.attributes.push(TcActionAttribute::Options(vec![
                        TcActionOption::Mirror(TcActionMirrorOption::Parms({
                            let mut params = TcMirror::default();
                            params.generic.index = 6;
                            params.eaction = TcMirrorActionType::EgressRedir;
                            params.ifindex = 107;
                            params.generic.action = TcActionType::Stolen;
                            params
                        })),
                    ]));
                    mirror
                },
            ]),
        ])
        .unwrap()
        .execute()
        .await
        .unwrap();
}

#[allow(clippy::too_many_lines)] // this is an integration test and is expected to be long
#[tokio::test]
#[wrap(with_caps([Capability::CAP_NET_ADMIN]))]
// #[wrap(run_in_netns("biscuit"))]
#[traced_test]
async fn assign_qdisc() {
    let (mut connection, handle, _recv) = rtnetlink::new_connection().unwrap();
    connection
        .socket_mut()
        .socket_mut()
        .set_rx_buf_sz(812_992)
        .unwrap();
    tokio::spawn(connection);
    let handle = Arc::new(handle);

    let manager = Manager::<Qdisc>::new(handle.clone());

    let mut clsact = QdiscSpec::new(
        InterfaceIndex::try_new(217).unwrap(),
        QdiscProperties::ClsAct,
    );
    clsact
        .ingress_block(BlockIndex::try_from(19).unwrap())
        .egress_block(BlockIndex::try_from(20).unwrap());

    manager.create(&clsact).await.unwrap();
}

#[allow(clippy::too_many_lines)] // this is an integration test and is expected to be long
#[tokio::test]
#[wrap(with_caps([Capability::CAP_NET_ADMIN]))]
// #[wrap(run_in_netns("biscuit"))]
#[traced_test]
async fn get_qdisc() {
    let (mut connection, handle, _recv) = rtnetlink::new_connection().unwrap();
    connection
        .socket_mut()
        .socket_mut()
        .set_rx_buf_sz(812_992)
        .unwrap();
    tokio::spawn(connection);
    let handle = Arc::new(handle);

    let manager = Manager::<Qdisc>::new(handle.clone());

    let qdiscs = manager.observe().await;

    for qdisc in qdiscs {
        println!("{:#?}", qdisc);
    }
}

#[allow(clippy::too_many_lines)] // this is an integration test and is expected to be long
#[tokio::test]
#[wrap(with_caps([Capability::CAP_NET_ADMIN]))]
// #[wrap(run_in_netns("biscuit"))]
#[traced_test]
async fn del_qdiscs() {
    let (mut connection, handle, _recv) = rtnetlink::new_connection().unwrap();
    connection
        .socket_mut()
        .socket_mut()
        .set_rx_buf_sz(812_992)
        .unwrap();
    tokio::spawn(connection);
    let handle = Arc::new(handle);

    let manager = Manager::<Qdisc>::new(handle.clone());

    let qdiscs = manager.observe().await;

    for qdisc in qdiscs {
        println!("{:#?}", qdisc);
        manager.remove(&qdisc).await.unwrap();
    }
    println!("removed");
    let qdiscs = manager.observe().await;
    for qdisc in qdiscs {
        println!("error: {:#?}", qdisc);
    }
}

#[allow(clippy::too_many_lines)] // this is an integration test and is expected to be long
#[tokio::test]
#[wrap(with_caps([Capability::CAP_NET_ADMIN]))]
// #[wrap(run_in_netns("biscuit"))]
#[traced_test]
async fn reconcile_qdiscs() {
    let (mut connection, handle, _recv) = rtnetlink::new_connection().unwrap();
    connection
        .socket_mut()
        .socket_mut()
        .set_rx_buf_sz(812_992)
        .unwrap();
    tokio::spawn(connection);
    let handle = Arc::new(handle);

    let manager = Manager::<Qdisc>::new(handle.clone());

    let spec = QdiscSpec {
        interface_index: InterfaceIndex::try_new(228).unwrap(),
        properties: QdiscProperties::ClsAct,
        egress_block: Some(BlockIndex::new(NonZero::new(100).unwrap())),
        ingress_block: Some(BlockIndex::new(NonZero::new(199).unwrap())),
    };
    let qdiscs = manager.observe().await;

    manager
        .reconcile(spec.clone(), qdiscs.first())
        .await
        .unwrap();
}

#[allow(clippy::too_many_lines)] // this is an integration test and is expected to be long
#[tokio::test]
#[wrap(with_caps([Capability::CAP_NET_ADMIN]))]
// #[wrap(run_in_netns("biscuit"))]
#[traced_test]
async fn tc_actions_demo5() {
    let (mut connection, handle, _recv) = rtnetlink::new_connection().unwrap();
    connection
        .socket_mut()
        .socket_mut()
        .set_rx_buf_sz(812_992)
        .unwrap();
    tokio::spawn(connection);
    let handle = Arc::new(handle);

    let manager = Manager::<Qdisc>::new(handle.clone());

    let mut clsact = QdiscSpec::new(
        InterfaceIndex::try_new(228).unwrap(),
        QdiscProperties::ClsAct,
    );
    clsact
        .ingress_block(BlockIndex::new(99.try_into().unwrap()))
        .egress_block(BlockIndex::new(100.try_into().unwrap()));

    manager.create(&clsact).await.unwrap();

    handle
        .traffic_filter(0)
        .replace()
        .ingress()
        .priority(9989)
        .protocol(0x0003u16.to_be())
        .block(99)
        .flower(&[
            EncKeyId(2),
            EncKeyIpv4Dst(Ipv4Addr::new(172, 18, 10, 1)),
            EncKeyUdpDstPort(4789),
            Actions(vec![
                {
                    let mut unset = TcAction::default();
                    unset.tab = 1;
                    unset.attributes.push(TcActionAttribute::Index(56));
                    unset
                        .attributes
                        .push(TcActionAttribute::Kind("tunnel_key".into()));
                    unset.attributes.push(TcActionAttribute::Options(vec![
                        TcActionOption::TunnelKey(TcActionTunnelKeyOption::Parms(TcTunnelKey {
                            t_action: 2, // tunnel key unset
                            generic: {
                                let mut generic = TcActionGeneric::default();
                                generic.index = 558;
                                generic
                            },
                        })),
                    ]));
                    unset
                },
                {
                    let mut mirror = TcAction::default();
                    mirror.tab = 3;
                    mirror
                        .attributes
                        .push(TcActionAttribute::Kind("mirred".into()));
                    mirror.attributes.push(TcActionAttribute::Options(vec![
                        TcActionOption::Mirror(TcActionMirrorOption::Parms({
                            let mut params = TcMirror::default();
                            params.generic.index = 6;
                            params.eaction = TcMirrorActionType::EgressRedir;
                            params.ifindex = 107;
                            params.generic.action = TcActionType::Stolen;
                            params
                        })),
                    ]));
                    mirror
                },
            ]),
        ])
        .unwrap()
        .execute()
        .await
        .unwrap();
}

#[allow(clippy::too_many_lines)] // this is an integration test and is expected to be long
#[tokio::test]
#[wrap(with_caps([Capability::CAP_NET_ADMIN]))]
#[traced_test]
async fn tc_actions_demo6() {
    let (mut connection, handle, _recv) = rtnetlink::new_connection().unwrap();
    connection
        .socket_mut()
        .socket_mut()
        .set_rx_buf_sz(812_992)
        .unwrap();
    tokio::spawn(connection);
    let mut req = handle.neighbours().get().fdb().flags(NeighbourFlags::Own);
    req.message_mut()
        .attributes
        .push(NeighbourAttribute::IfIndex(58));
    req.message_mut()
        .attributes
        .push(NeighbourAttribute::Controller(118));
    req.message_mut().header.ifindex = 58;
    let mut resp = req.execute();
    let mut count = 0;
    while let Ok(Some(x)) = resp.try_next().await {
        println!("{x:#?}");
        count += 1;
    }
    println!("count = {count}");
}

#[allow(clippy::too_many_lines)] // this is an integration test and is expected to be long
#[tokio::test]
#[wrap(with_caps([Capability::CAP_NET_ADMIN]))]
#[traced_test]
async fn tc_actions_demo8() {
    let (mut connection, handle, _recv) = rtnetlink::new_connection().unwrap();
    connection
        .socket_mut()
        .socket_mut()
        .set_rx_buf_sz(812_992)
        .unwrap();
    tokio::spawn(connection);
    let mut req = handle
        .neighbours()
        .get()
        .fdb()
        .flags(NeighbourFlags::Own | NeighbourFlags::ExtLearned);
    req.message_mut().header.ifindex = 58;
    req.message_mut()
        .attributes
        .push(NeighbourAttribute::IfIndex(58));
    // TODO: 12 bytes left over in kernel log???
    req.message_mut()
        .attributes
        .push(NeighbourAttribute::Controller(118));
    let mut fdb = MultiIndexFdbMap::with_capacity(100);
    let mut resp = req.execute();
    let mut count = 0;
    let mut evpn_fdb_count = 0;
    let mut normal_fdb_count = 0;
    let mut evpn_actions = HashSet::with_capacity(100);
    while let Ok(Some(entry)) = resp.try_next().await {
        let mut builder = FdbEntryBuilder::new();
        match InterfaceIndex::try_from(entry.header.ifindex) {
            Ok(idx) => {
                builder.dev(idx);
            }
            Err(err) => {
                error!("invalid ifindex {err}");
                continue;
            }
        }
        for attr in &entry.attributes {
            match attr {
                NeighbourAttribute::Destination(NeighbourAddress::Other(addr)) => {
                    if addr.len() != 4 {
                        continue;
                    }
                    let mut a: [u8; 4] = [0; 4];
                    a.copy_from_slice(addr);
                    let ip = match UnicastIpv4Addr::new(Ipv4Addr::from(a)) {
                        Ok(ip) => ip,
                        Err(ip) => {
                            debug!("unsupported multicast ip addr {ip} in fdb");
                            continue;
                        }
                    };
                    builder.dst(ip);
                }
                NeighbourAttribute::LinkLocalAddress(addr) => {
                    if addr.len() != 6 {
                        debug!("non ethernet address in fdb? {addr:?}");
                        continue;
                    }
                    let mut mac = [0u8; 6];
                    mac.copy_from_slice(addr);
                    builder.mac(Mac(mac));
                }
                NeighbourAttribute::SourceVni(vni) => {
                    let Ok(vni) = Vni::new_checked(*vni) else {
                        debug!("invalid vni in fdb {vni}");
                        continue;
                    };
                    builder.vni(vni);
                }
                _ => {}
            }
        }
        count += 1;
        match builder.build() {
            Ok(entry) => {
                match entry.action() {
                    FdbAction::Dev(_) => {
                        normal_fdb_count += 1;
                    }
                    FdbAction::Encap(route) => {
                        evpn_fdb_count += 1;
                        evpn_actions.insert(route.clone());
                    }
                };
                match fdb.try_insert(entry) {
                    Ok(_) => {}
                    Err(err) => {
                        trace!("failed to insert fdb entry: {err:#?}: {err:#?}");
                    }
                };
            }
            Err(err) => {
                trace!("failed to build fdb entry: {err:#?}");
            }
        }
    }
    println!("count = {count}");
    println!("normal = {normal_fdb_count}");
    println!("evpn = {evpn_fdb_count}");
    let entries: Vec<_> = fdb.iter_by_mac().cloned().collect();
    println!("fdb = {entries:#?}");
    println!("evpn_actions = {evpn_actions:#?}");
}

#[allow(clippy::too_many_lines)] // this is an integration test and is expected to be long
#[tokio::test]
#[wrap(with_caps([Capability::CAP_NET_ADMIN]))]
#[traced_test]
async fn list_links() {
    let (mut connection, handle, _recv) = rtnetlink::new_connection().unwrap();
    connection
        .socket_mut()
        .socket_mut()
        .set_rx_buf_sz(812_992)
        .unwrap();
    tokio::spawn(connection);
    let mut resp = handle.link().get().execute();
    while let Ok(Some(x)) = resp.try_next().await {
        println!("{:#?}", x);
    }
}

#[allow(clippy::too_many_lines)] // this is an integration test and is expected to be long
#[tokio::test]
#[wrap(with_caps([Capability::CAP_NET_ADMIN]))]
// #[wrap(run_in_netns("biscuit"))]
#[traced_test]
async fn gact_demo() {
    let (mut connection, handle, _recv) = rtnetlink::new_connection().unwrap();
    connection
        .socket_mut()
        .socket_mut()
        .set_rx_buf_sz(812_992)
        .unwrap();
    tokio::spawn(connection);
    let handle = Arc::new(handle);

    handle
        .traffic_filter(107)
        .replace()
        .ingress()
        .priority(9019)
        .protocol(0x0003u16.to_be())
        .flower(&[
            Flags(TcFlowerOptionFlags::SkipSw),
            EncKeyId(2),
            EncKeyIpv4Dst(Ipv4Addr::new(172, 18, 10, 1)),
            EncKeyUdpDstPort(4789),
            Actions(vec![{
                let mut mirror = TcAction::default();
                mirror.tab = 1;
                mirror
                    .attributes
                    .push(TcActionAttribute::Kind("gact".into()));
                mirror
                    .attributes
                    .push(TcActionAttribute::Options(vec![TcActionOption::Generic(
                        TcActionGenericOption::Parms({
                            let mut params = TcActionGeneric::default();
                            params.action = TcActionType::Trap;
                            params
                        }),
                    )]));
                mirror
            }]),
        ])
        .unwrap()
        .execute()
        .await
        .unwrap();
}

#[allow(clippy::too_many_lines)] // this is an integration test and is expected to be long
#[tokio::test]
#[wrap(with_caps([Capability::CAP_NET_ADMIN]))]
// #[wrap(run_in_netns("biscuit"))]
#[traced_test]
async fn add_chain() {
    let (mut connection, handle, _recv) = rtnetlink::new_connection().unwrap();
    connection
        .socket_mut()
        .socket_mut()
        .set_rx_buf_sz(812_992)
        .unwrap();
    tokio::spawn(connection);
    let handle = Arc::new(handle);
    handle
        .traffic_chain(228)
        .add()
        .chain(11)
        .execute()
        .await
        .unwrap();
}

#[allow(clippy::too_many_lines)] // this is an integration test and is expected to be long
#[tokio::test]
#[wrap(with_caps([Capability::CAP_NET_ADMIN]))]
// #[wrap(run_in_netns("biscuit"))]
#[traced_test]
async fn add_chain_template() {
    let (mut connection, handle, _recv) = rtnetlink::new_connection().unwrap();
    connection
        .socket_mut()
        .socket_mut()
        .set_rx_buf_sz(812_992)
        .unwrap();
    tokio::spawn(connection);
    let handle = Arc::new(handle);
    handle
        .traffic_chain(228)
        .add()
        .chain(12)
        .flower(&[
            EncKeyId(2),
            EncKeyIpv4Dst(Ipv4Addr::new(172, 18, 10, 1)),
            EncKeyUdpDstPort(4789),
            Actions(vec![
                {
                    let mut unset = TcAction::default();
                    unset.tab = 1;
                    unset.attributes.push(TcActionAttribute::Index(56));
                    unset
                        .attributes
                        .push(TcActionAttribute::Kind("tunnel_key".into()));
                    unset.attributes.push(TcActionAttribute::Options(vec![
                        TcActionOption::TunnelKey(TcActionTunnelKeyOption::Parms(TcTunnelKey {
                            t_action: 2, // tunnel key unset
                            generic: {
                                let mut generic = TcActionGeneric::default();
                                generic.index = 558;
                                generic
                            },
                        })),
                    ]));
                    unset
                },
                {
                    let mut mirror = TcAction::default();
                    mirror.tab = 2;
                    mirror
                        .attributes
                        .push(TcActionAttribute::Kind("mirred".into()));
                    mirror.attributes.push(TcActionAttribute::Options(vec![
                        TcActionOption::Mirror(TcActionMirrorOption::Parms({
                            let mut params = TcMirror::default();
                            params.generic.index = 6;
                            params.eaction = TcMirrorActionType::EgressRedir;
                            params.ifindex = 107;
                            params.generic.action = TcActionType::Stolen;
                            params
                        })),
                    ]));
                    mirror
                },
            ]),
        ])
        .unwrap()
        .execute()
        .await
        .unwrap();
}

#[allow(clippy::too_many_lines)] // this is an integration test and is expected to be long
#[tokio::test]
#[wrap(with_caps([Capability::CAP_NET_ADMIN]))]
// #[wrap(run_in_netns("biscuit"))]
#[traced_test]
async fn add_chain_template_to_block() {
    let (mut connection, handle, _recv) = rtnetlink::new_connection().unwrap();
    connection
        .socket_mut()
        .socket_mut()
        .set_rx_buf_sz(812_992)
        .unwrap();
    tokio::spawn(connection);
    let handle = Arc::new(handle);
    handle
        .traffic_chain(0)
        .add()
        .block(10)
        .chain(0)
        // .flower(&[
        //     EncKeyId(2),
        //     EncKeyIpv4Dst(Ipv4Addr::new(172, 18, 10, 1)),
        //     EncKeyUdpDstPort(4789),
        // Actions(vec![
        //     {
        //         let mut unset = TcAction::default();
        //         unset.tab = 1;
        //         unset.attributes.push(TcActionAttribute::Index(56));
        //         unset
        //             .attributes
        //             .push(TcActionAttribute::Kind("tunnel_key".into()));
        //         unset.attributes.push(TcActionAttribute::Options(vec![
        //             TcActionOption::TunnelKey(TcActionTunnelKeyOption::Parms(TcTunnelKey {
        //                 t_action: 2, // tunnel key unset
        //                 generic: {
        //                     let mut generic = TcActionGeneric::default();
        //                     generic.index = 558;
        //                     generic
        //                 },
        //             })),
        //         ]));
        //         unset
        //     },
        //     {
        //         let mut mirror = TcAction::default();
        //         mirror.tab = 2;
        //         mirror
        //             .attributes
        //             .push(TcActionAttribute::Kind("mirred".into()));
        //         mirror.attributes.push(TcActionAttribute::Options(vec![
        //             TcActionOption::Mirror(TcActionMirrorOption::Parms({
        //                 let mut params = TcMirror::default();
        //                 params.generic.index = 6;
        //                 params.eaction = TcMirrorActionType::EgressRedir;
        //                 params.ifindex = 107;
        //                 params.generic.action = TcActionType::Stolen;
        //                 params
        //             })),
        //         ]));
        //         mirror
        //     },
        // ]),
        // ])
        // .unwrap()
        .execute()
        .await
        .unwrap();
}

#[allow(clippy::too_many_lines)] // this is an integration test and is expected to be long
#[tokio::test]
#[wrap(with_caps([Capability::CAP_NET_ADMIN]))]
// #[wrap(run_in_netns("biscuit"))]
#[traced_test]
async fn add_filter_to_block() {
    let (mut connection, handle, _recv) = rtnetlink::new_connection().unwrap();
    connection
        .socket_mut()
        .socket_mut()
        .set_rx_buf_sz(812_992)
        .unwrap();
    tokio::spawn(connection);
    let handle = Arc::new(handle);
    let chain = 10;
    let block = 10;
    let _ = handle
        .traffic_chain(0)
        .del()
        .block(block)
        .chain(chain)
        .execute()
        .await;
    handle
        .traffic_chain(0)
        .add()
        .block(block)
        .chain(chain)
        .flower(&[
            EncKeyId(0),
            EncKeyIpv4Dst(Ipv4Addr::new(0, 0, 0, 0)),
            EncKeyUdpDstPort(0),
        ])
        .unwrap()
        .execute()
        .await
        .unwrap();
    handle
        .traffic_filter(0)
        .add()
        .ingress()
        .protocol(0x0003u16.to_be())
        .block(block)
        .chain(chain)
        .flower(&[
            EncKeyId(9),
            EncKeyIpv4Dst(Ipv4Addr::new(192, 168, 5, 155)),
            EncKeyUdpDstPort(4789),
            Actions(vec![
                {
                    let mut unset = TcAction::default();
                    unset.tab = 1;
                    unset.attributes.push(TcActionAttribute::Index(56));
                    unset
                        .attributes
                        .push(TcActionAttribute::Kind("tunnel_key".into()));
                    unset.attributes.push(TcActionAttribute::Options(vec![
                        TcActionOption::TunnelKey(TcActionTunnelKeyOption::Parms(TcTunnelKey {
                            t_action: 2, // tunnel key unset
                            generic: {
                                let mut generic = TcActionGeneric::default();
                                generic.index = 559;
                                generic
                            },
                        })),
                    ]));
                    unset
                },
                {
                    let mut mirror = TcAction::default();
                    mirror.tab = 2;
                    mirror
                        .attributes
                        .push(TcActionAttribute::Kind("mirred".into()));
                    mirror.attributes.push(TcActionAttribute::Options(vec![
                        TcActionOption::Mirror(TcActionMirrorOption::Parms({
                            let mut params = TcMirror::default();
                            params.generic.index = 6;
                            params.eaction = TcMirrorActionType::EgressRedir;
                            params.ifindex = 217;
                            params.generic.action = TcActionType::Stolen;
                            params
                        })),
                    ]));
                    mirror
                },
            ]),
        ])
        .unwrap()
        .execute()
        .await
        .unwrap();
}

#[allow(clippy::too_many_lines)] // this is an integration test and is expected to be long
#[tokio::test]
#[wrap(with_caps([Capability::CAP_NET_ADMIN]))]
// #[wrap(run_in_netns("biscuit"))]
#[traced_test]
async fn remove_chain() {
    let (mut connection, handle, _recv) = rtnetlink::new_connection().unwrap();
    connection
        .socket_mut()
        .socket_mut()
        .set_rx_buf_sz(812_992)
        .unwrap();
    tokio::spawn(connection);
    let handle = Arc::new(handle);
    let block = 10;
    let chain = 10;
    handle
        .traffic_chain(0)
        .del()
        .block(block)
        .chain(chain)
        .execute()
        .await
        .unwrap();
}

#[allow(clippy::too_many_lines)] // this is an integration test and is expected to be long
#[tokio::test]
// #[wrap(with_caps([Capability::CAP_NET_ADMIN]))]
// #[wrap(run_in_netns("biscuit"))]
#[traced_test]
async fn observe() {
    let (mut connection, handle, _recv) = rtnetlink::new_connection().unwrap();
    connection
        .socket_mut()
        .socket_mut()
        .set_rx_buf_sz(812_992)
        .unwrap();
    tokio::spawn(connection);
    let handle = Arc::new(handle);

    let manager = VpcManager::<RequiredInformationBase>::new(handle);
    let x = manager.observe().await.unwrap();
    x.interfaces
        .iter()
        .filter(|(_, x)| matches!(x.properties, InterfaceProperties::Pci(_)))
        .for_each(|(idx, x)| {
            println!("{idx}: {x:#?}");
        });
}

#[allow(clippy::too_many_lines)] // this is an integration test and is expected to be long
#[tokio::test]
// #[wrap(with_caps([Capability::CAP_NET_ADMIN]))]
// #[wrap(run_in_netns("biscuit"))]
#[traced_test]
async fn observe_tunnel_key_actions() {
    let (mut connection, handle, _recv) = rtnetlink::new_connection().unwrap();
    connection
        .socket_mut()
        .socket_mut()
        .set_rx_buf_sz(812_992)
        .unwrap();
    tokio::spawn(connection);
    let handle = Arc::new(handle);

    let manager = Manager::<TunnelKey>::new(handle);
    let x = manager.observe().await;
    println!("{x:#?}");
}

#[allow(clippy::too_many_lines)] // this is an integration test and is expected to be long
#[tokio::test]
#[wrap(with_caps([Capability::CAP_NET_ADMIN]))]
// #[wrap(run_in_netns("biscuit"))]
#[traced_test]
async fn create_filter() {
    let (mut connection, handle, _recv) = rtnetlink::new_connection().unwrap();
    connection
        .socket_mut()
        .socket_mut()
        .set_rx_buf_sz(812_992)
        .unwrap();
    tokio::spawn(connection);
    let handle = Arc::new(handle);
    let manager = Manager::<Filter>::new(handle.clone());
    let block: BlockIndex = 3.try_into().unwrap();
    let chain = 3;
    let priority = 18;
    let filter_handle: FilterIndex = 0x229.try_into().unwrap();
    let mut spec = FilterSpecBuilder::default();
    let mut spec = spec
        .handle(filter_handle)
        .block(block)
        .chain(chain)
        .priority(priority)
        .handle(filter_handle)
        .actions(vec![
            ActionSpec {
                details: ActionDetailsSpec::TunnelKey({
                    let mut tunnel_key = TunnelKeySpecBuilder::default();
                    tunnel_key.index(882.try_into().unwrap());
                    tunnel_key.details({
                        TunnelKeyDetails::Set(
                            TunnelKeySetBuilder::default()
                                .dst(UnicastIpv4Addr::new(Ipv4Addr::new(192, 168, 5, 1)).unwrap())
                                .src(UnicastIpv4Addr::new(Ipv4Addr::new(192, 168, 5, 155)).unwrap())
                                .id(Vni::new_checked(1234).unwrap())
                                .checksum(TunnelChecksum::Compute)
                                .dst_port(Vxlan::PORT)
                                .ttl(64)
                                .tos(3)
                                .build()
                                .unwrap(),
                        )
                    });
                    tunnel_key.build().unwrap()
                }),
            },
            ActionSpec {
                details: ActionDetailsSpec::Redirect(MirredSpec {
                    index: 192.try_into().unwrap(),
                    to: 285.try_into().unwrap(),
                }),
            },
        ])
        .criteria(vec![
            TcFilterFlowerOption::EthType(0x0800),
            EncKeyId(728),
            EncKeyIpv4Dst(Ipv4Addr::new(172, 18, 10, 1)),
            EncKeyUdpDstPort(4789),
        ])
        .build()
        .unwrap();

    let actions_manager = Manager::<Action>::new(handle.clone());
    for action in &spec.actions {
        match actions_manager.create(action).await {
            Ok(()) => {}
            Err(err) => {
                eprintln!("{err:#?}");
            }
        }
    }

    let actions: Vec<Vec<TcActionAttribute>> = spec
        .actions
        .iter()
        .map(|x| {
            let mut attrs = vec![];
            match x.details {
                ActionDetailsSpec::Redirect(act) => {
                    attrs.push(TcActionAttribute::Kind(Mirred::KIND.to_string()));
                    attrs.push(TcActionAttribute::Options(vec![TcActionOption::Mirror(
                        TcActionMirrorOption::Parms({
                            let mut mirror = TcMirror::default();
                            mirror.generic.index = act.index.into();
                            mirror.eaction = TcMirrorActionType::EgressRedir;
                            mirror.ifindex = act.to.to_u32();
                            mirror.generic.action = TcActionType::Stolen;
                            mirror
                        }),
                    )]));
                }
                ActionDetailsSpec::Generic(_) => {
                    todo!();
                }
                ActionDetailsSpec::TunnelKey(act) => {
                    attrs.push(TcActionAttribute::Kind(TunnelKey::KIND.to_string()));
                    match act.details {
                        TunnelKeyDetails::Set(_) => {
                            attrs.push(TcActionAttribute::Options({
                                vec![TcActionOption::TunnelKey(TcActionTunnelKeyOption::Parms(
                                    TcTunnelKey {
                                        generic: {
                                            let mut generic = TcActionGeneric::default();
                                            generic.index = act.index.into();
                                            generic
                                        },
                                        t_action: 1, // 1 is for encap
                                    },
                                ))]
                            }));
                        }
                        TunnelKeyDetails::Unset => {
                            attrs.push(TcActionAttribute::Options({
                                vec![TcActionOption::TunnelKey(TcActionTunnelKeyOption::Parms(
                                    TcTunnelKey {
                                        generic: {
                                            let mut generic = TcActionGeneric::default();
                                            generic.index = act.index.into();
                                            generic
                                        },
                                        t_action: 2, // 2 is for decap
                                    },
                                ))]
                            }))
                        }
                    }
                }
            };
            attrs
        })
        .collect();

    let actions: Vec<_> = actions
        .into_iter()
        .enumerate()
        .map(|(idx, attrs)| {
            let mut action = TcAction::default();
            if idx >= u16::MAX as usize {
                panic!("nonsensical number of actions (u16::MAX is the upper limit)");
            }
            #[allow(clippy::cast_possible_truncation)]
            {
                action.tab = (idx + 1) as u16;
            }
            action.attributes = attrs;
            action
        })
        .collect();
    spec.criteria.push(Actions(actions));

    manager.create(&spec).await.unwrap();
}

#[allow(clippy::too_many_lines)] // this is an integration test and is expected to be long
#[tokio::test]
#[wrap(with_caps([Capability::CAP_NET_ADMIN]))]
// #[wrap(run_in_netns("biscuit"))]
#[traced_test]
async fn its_a_trap() {
    let (mut connection, handle, _recv) = rtnetlink::new_connection().unwrap();
    connection
        .socket_mut()
        .socket_mut()
        .set_rx_buf_sz(812_992)
        .unwrap();
    tokio::spawn(connection);
    let handle = Arc::new(handle);
    let manager = Manager::<Filter>::new(handle.clone());
    let block: BlockIndex = 3.try_into().unwrap();
    let chain = 3;
    let priority = 39;
    let filter_handle: FilterIndex = 0x4.try_into().unwrap();
    let mut spec = FilterSpecBuilder::default();
    let mut spec = spec
        .handle(filter_handle)
        .block(block)
        .chain(chain)
        .priority(priority)
        .handle(filter_handle)
        .criteria(vec![TcFilterFlowerOption::EthType(0x0806)])
        .actions(vec![ActionSpec {
            details: ActionDetailsSpec::Generic(GenericActionSpec {
                index: 779.try_into().unwrap(),
                action_type: TcActionType::Trap,
            }),
        }])
        .build()
        .unwrap();

    let actions_manager = Manager::<Action>::new(handle.clone());
    for action in &spec.actions {
        match actions_manager.create(action).await {
            Ok(()) => {}
            Err(err) => {
                eprintln!("{err:#?}");
            }
        }
    }
    let actions = spec
        .actions
        .iter()
        .enumerate()
        .map(|(idx, action)| {
            if idx >= u16::MAX as usize {
                panic!("absurd number of actions (u16::MAX is the upper limit)");
            }
            let mut action = TcAction::from(action);
            #[allow(clippy::cast_possible_truncation)] // checked safe
            {
                action.tab = (idx + 1) as u16;
            }
            action
        })
        .collect();

    spec.criteria.push(Actions(actions));

    manager.create(&spec).await.unwrap();
}

#[allow(clippy::too_many_lines)] // this is an integration test and is expected to be long
#[tokio::test]
#[wrap(with_caps([Capability::CAP_NET_ADMIN]))]
// #[wrap(run_in_netns("biscuit"))]
#[traced_test]
async fn observe_gact() {
    let (mut connection, handle, _recv) = rtnetlink::new_connection().unwrap();
    connection
        .socket_mut()
        .socket_mut()
        .set_rx_buf_sz(812_992)
        .unwrap();
    tokio::spawn(connection);
    let handle = Arc::new(handle);

    let manager = Manager::<GenericAction>::new(handle);
    let x = manager.observe().await;
    println!("{x:#?}");
}

#[allow(clippy::too_many_lines)] // this is an integration test and is expected to be long
#[tokio::test]
#[wrap(with_caps([Capability::CAP_NET_ADMIN]))]
// #[wrap(run_in_netns("biscuit"))]
#[traced_test]
async fn observe_mirred() {
    let (mut connection, handle, _recv) = rtnetlink::new_connection().unwrap();
    connection
        .socket_mut()
        .socket_mut()
        .set_rx_buf_sz(812_992)
        .unwrap();
    tokio::spawn(connection);
    let handle = Arc::new(handle);

    let manager = Manager::<Mirred>::new(handle);
    let x = manager.observe().await;
    println!("{x:#?}");
}

#[allow(clippy::too_many_lines)] // this is an integration test and is expected to be long
#[tokio::test]
#[wrap(with_caps([Capability::CAP_NET_ADMIN]))]
// #[wrap(run_in_netns("biscuit"))]
#[traced_test]
async fn observe_interfaces() {
    let (mut connection, handle, _recv) = rtnetlink::new_connection().unwrap();
    connection
        .socket_mut()
        .socket_mut()
        .set_rx_buf_sz(812_992)
        .unwrap();
    tokio::spawn(connection);
    let handle = Arc::new(handle);

    let manager = VpcManager::<RequiredInformationBase>::new(handle);
    let x = manager.observe().await;
    println!("{x:#?}");
}
