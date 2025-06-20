// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use dataplane_mgmt as mgmt;

use caps::Capability;
use fixin::wrap;
use futures::TryStreamExt;
use interface_manager::Manager;
use interface_manager::interface::tc::action::Action;
use interface_manager::interface::tc::qdisc::{BlockIndex, ClsAct, EgressBlock, IngressBlock};
use interface_manager::interface::{
    BridgePropertiesSpec, InterfaceAssociationSpec, InterfacePropertiesSpec, InterfaceSpecBuilder,
    MultiIndexBridgePropertiesSpecMap, MultiIndexInterfaceAssociationSpecMap,
    MultiIndexInterfaceSpecMap, MultiIndexVrfPropertiesSpecMap, MultiIndexVtepPropertiesSpecMap,
    VrfPropertiesSpec, VtepPropertiesSpec,
};
use mgmt::vpc_manager::{RequiredInformationBase, RequiredInformationBaseBuilder, VpcManager};
use net::eth::ethtype::EthType;
use net::interface::{AdminState, InterfaceIndex};
use net::vxlan::Vxlan;
use rekon::Create;
use rekon::{Observe, Reconcile};
use rtnetlink::packet_route::tc::TcFilterFlowerOption::{
    Actions, EncKeyId, EncKeyIpv4Dst, EncKeyUdpDstPort,
};
use rtnetlink::packet_route::tc::{
    TcAction, TcActionAttribute, TcActionGeneric, TcActionMirrorOption, TcActionOption,
    TcActionTunnelKeyOption, TcActionType, TcMirror, TcMirrorActionType, TcTunnelKey,
};
use rtnetlink::sys::AsyncSocket;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;
use test_utils::with_caps;
use tracing::info;
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
    let Ok((mut connection, handle, _recv)) = rtnetlink::new_connection() else {
        panic!("failed to create connection");
    };
    connection
        .socket_mut()
        .socket_mut()
        .set_rx_buf_sz(812_992)
        .unwrap();
    tokio::spawn(connection);
    let handle = Arc::new(handle);

    let manager = Manager::<Action>::new(handle.clone());
    manager.create(()).await;

    let tunnel_key_params = TcTunnelKey {
        t_action: 1, // tunnel key set
        ..Default::default()
    };
    let mut tunnel_key_set = TcAction::default();
    tunnel_key_set.tab = 1;
    tunnel_key_set.attributes = vec![
        TcActionAttribute::Kind("tunnel_key".into()),
        TcActionAttribute::Options(vec![
            TcActionOption::TunnelKey(TcActionTunnelKeyOption::EncDstPort(4789)),
            TcActionOption::TunnelKey(TcActionTunnelKeyOption::NoCsum(true)),
            TcActionOption::TunnelKey(TcActionTunnelKeyOption::EncTtl(64)),
            TcActionOption::TunnelKey(TcActionTunnelKeyOption::EncIpv4Dst(Ipv4Addr::new(
                169, 254, 32, 55,
            ))),
            TcActionOption::TunnelKey(TcActionTunnelKeyOption::EncKeyId(2)),
            TcActionOption::TunnelKey(TcActionTunnelKeyOption::EncIpv4Src(Ipv4Addr::new(
                172, 18, 10, 1,
            ))),
            TcActionOption::TunnelKey(TcActionTunnelKeyOption::Parms(tunnel_key_params)),
        ]),
    ];
    let mirror = {
        let mut mirror = TcAction::default();
        mirror.tab = 2;
        mirror
            .attributes
            .push(TcActionAttribute::Kind("mirred".into()));
        mirror
            .attributes
            .push(TcActionAttribute::Options(vec![TcActionOption::Mirror(
                TcActionMirrorOption::Parms({
                    let mut params = TcMirror::default();
                    params.generic.index = 5;
                    params.eaction = TcMirrorActionType::EgressRedir;
                    params.ifindex = 117;
                    params.generic.action = TcActionType::Stolen;
                    params
                }),
            )]));
        mirror
    };
    // handle
    //     .traffic_filter(107)
    //     .replace()
    //     .index(107)
    //     .ingress()
    //     .priority(9005)
    //     .protocol(0x0003u16.to_be())
    //     .flower(&[
    //         EthDst([0, 1, 2, 3, 4, 5]),
    //         Actions(vec![tunnel_key_set, mirror]),
    //     ])
    //     .unwrap()
    //     .execute()
    //     .await
    //     .unwrap();
    let mut resp = handle.traffic_action().get().kind("tunnel_key").execute();
    // while let Ok(Some(x)) = resp.try_next().await {
    //     println!("{:#?}", x);
    // }
    let mut resp = handle.traffic_filter(96).get().ingress().execute();
    while let Ok(Some(x)) = resp.try_next().await {
        println!("{:#?}", x);
    }
}

#[allow(clippy::too_many_lines)] // this is an integration test and is expected to be long
#[tokio::test]
#[wrap(with_caps([Capability::CAP_NET_ADMIN]))]
// #[wrap(run_in_netns("biscuit"))]
#[traced_test]
async fn tc_actions_demo2() {
    let Ok((mut connection, handle, _recv)) = rtnetlink::new_connection() else {
        panic!("failed to create connection");
    };
    connection
        .socket_mut()
        .socket_mut()
        .set_rx_buf_sz(812_992)
        .unwrap();
    tokio::spawn(connection);
    let handle = Arc::new(handle);

    handle
        .traffic_filter(117)
        .replace()
        .ingress()
        .priority(9009)
        .protocol(0x0003u16.to_be())
        .flower(&[
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
                        .push(TcActionAttribute::Kind("mirred".into()));
                    mirror.attributes.push(TcActionAttribute::Options(vec![
                        TcActionOption::Mirror(TcActionMirrorOption::Parms({
                            let mut params = TcMirror::default();
                            params.generic.index = 0;
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
async fn tc_actions_demo3() {
    let Ok((mut connection, handle, _recv)) = rtnetlink::new_connection() else {
        panic!("failed to create connection");
    };
    connection
        .socket_mut()
        .socket_mut()
        .set_rx_buf_sz(812_992)
        .unwrap();
    tokio::spawn(connection);
    let handle = Arc::new(handle);

    handle
        .traffic_filter(117)
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
async fn tc_actions_demo4() {
    let Ok((mut connection, handle, _recv)) = rtnetlink::new_connection() else {
        panic!("failed to create connection");
    };
    connection
        .socket_mut()
        .socket_mut()
        .set_rx_buf_sz(812_992)
        .unwrap();
    tokio::spawn(connection);
    let handle = Arc::new(handle);

    let manager = Manager::<ClsAct>::new(handle.clone());

    let mut clsact = ClsAct::new(InterfaceIndex::new(107));
    clsact
        .ingress_block(IngressBlock::new(BlockIndex::new(19)))
        .egress_block(EgressBlock::new(BlockIndex::new(20)));

    manager.create(&clsact).await.unwrap();
}

#[allow(clippy::too_many_lines)] // this is an integration test and is expected to be long
#[tokio::test]
#[wrap(with_caps([Capability::CAP_NET_ADMIN]))]
// #[wrap(run_in_netns("biscuit"))]
#[traced_test]
async fn tc_actions_demo5() {
    let Ok((mut connection, handle, _recv)) = rtnetlink::new_connection() else {
        panic!("failed to create connection");
    };
    connection
        .socket_mut()
        .socket_mut()
        .set_rx_buf_sz(812_992)
        .unwrap();
    tokio::spawn(connection);
    let handle = Arc::new(handle);

    let manager = Manager::<ClsAct>::new(handle.clone());

    let mut clsact = ClsAct::new(InterfaceIndex::new(117));
    clsact
        .ingress_block(IngressBlock::new(BlockIndex::new(99)))
        .egress_block(EgressBlock::new(BlockIndex::new(100)));

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
    let Ok((mut connection, handle, _recv)) = rtnetlink::new_connection() else {
        panic!("failed to create connection");
    };
    connection
        .socket_mut()
        .socket_mut()
        .set_rx_buf_sz(812_992)
        .unwrap();
    tokio::spawn(connection);
    let mut resp = handle.neighbours().get().fdb().execute();
    while let Ok(Some(x)) = resp.try_next().await {
        println!("{x:#?}");
    }
}
