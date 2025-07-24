// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use dataplane_mgmt as mgmt;

use caps::Capability;
use fixin::wrap;
use interface_manager::interface::{
    BridgePropertiesSpec, InterfaceAssociationSpec, InterfacePropertiesSpec, InterfaceSpecBuilder,
    MultiIndexBridgePropertiesSpecMap, MultiIndexInterfaceAssociationSpecMap,
    MultiIndexInterfaceSpecMap, MultiIndexPciNetdevPropertiesSpecMap,
    MultiIndexVrfPropertiesSpecMap, MultiIndexVtepPropertiesSpecMap, VrfPropertiesSpec,
    VtepPropertiesSpec,
};
use mgmt::vpc_manager::{RequiredInformationBase, RequiredInformationBaseBuilder, VpcManager};
use net::eth::ethtype::EthType;
use net::interface::AdminState;
use net::vxlan::Vxlan;
use rekon::{Observe, Reconcile};
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
            InterfacePropertiesSpec::Dummy => {}
            InterfacePropertiesSpec::Tap => {}
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
                InterfacePropertiesSpec::Bridge(_)
                | InterfacePropertiesSpec::Dummy
                | InterfacePropertiesSpec::Pci(_)
                | InterfacePropertiesSpec::Tap => {}
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
