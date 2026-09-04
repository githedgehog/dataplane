// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use dataplane_mgmt as mgmt;

use caps::Capability;
use concurrency::sync::Arc;
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
use net::interface::{AdminState, InterfaceName, InterfaceProperties};
use net::vxlan::Vxlan;
use nix::sched::CloneFlags;
use rekon::{Observe, Reconcile};
use rtnetlink::packet_route::link::{InfoData, InfoVxlan};
use rtnetlink::sys::AsyncSocket;
use rtnetlink::{LinkBridge, LinkVxlan};
use std::future::Future;
use std::net::Ipv4Addr;
use std::time::Duration;
use test_utils::with_caps;
use tracing::info;

#[n_vm::test]
#[wrap(with_caps([Capability::CAP_NET_ADMIN]))]
fn reconcile_fuzz() {
    #[n_vm::config]
    const _: _ = n_vm::VmConfigBuilder::default()
        .corpus(n_vm::CorpusPolicy::Fuzz)
        .build();

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
        // Bolero's `for_each` uses `catch_unwind` internally, which
        // requires the captured state to be `RefUnwindSafe`. The
        // parking_lot Mutex behind `concurrency::sync::Mutex` is not,
        // because its inner `UnsafeCell` lacks the explicit
        // `RefUnwindSafe` impl that `std::sync::Mutex` provides.
        // Reach into std here on purpose.
        #[allow(clippy::disallowed_types)]
        std::sync::Mutex::new(Arc::new(handle)) // nosemgrep: rust-no-direct-std-sync-import
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

/// Run `exec` in a network namespace of this test's own.
///
/// Reconciliation destroys interfaces which are absent from the plan, so a test which creates
/// devices named after somebody else's software has no business doing so in a namespace shared
/// with a real deployment of that software.
fn in_private_netns<Exec, Fut, Out>(exec: Exec) -> Out
where
    Exec: (FnOnce() -> Fut) + Send + 'static,
    Fut: Future<Output = Out>,
    Out: Send + 'static,
{
    std::thread::Builder::new()
        .name("private-netns".to_string())
        .spawn(move || {
            nix::sched::unshare(CloneFlags::CLONE_NEWNET).unwrap_or_else(|err| {
                panic!("failed to create a private network namespace: {err}")
            });
            tokio::runtime::Builder::new_current_thread()
                .enable_io()
                .enable_time()
                .build()
                .unwrap_or_else(|err| panic!("failed to build tokio runtime: {err}"))
                .block_on(exec())
        })
        .unwrap_or_else(|err| panic!("failed to spawn netns thread: {err}"))
        .join()
        .unwrap_or_else(|err| std::panic::resume_unwind(err))
}

/// The network devices created by a CNI must survive reconciliation.
///
/// Flannel's vxlan backend creates a vxlan device (`flannel.1`) and a bridge (`cni0`).  Both parse
/// as perfectly ordinary interfaces of kinds we manage, so nothing but the naming scheme
/// distinguishes them from interfaces of ours which have dropped out of the plan.  Removing them
/// severs pod networking on the node.
///
/// The flannel VTEP here deliberately shares a VNI with a VPC of ours (flannel defaults to vni 1)
/// while terminating on flannel's own UDP port.  That is legal in the kernel, and the reconciler
/// must not confuse the two.
#[n_vm::test]
#[wrap(with_caps([Capability::CAP_NET_ADMIN, Capability::CAP_SYS_ADMIN]))]
fn foreign_cni_devices_are_not_removed() {
    const FLANNEL_VTEP: &str = "flannel.1";
    const FLANNEL_BRIDGE: &str = "cni0";
    const FLANNEL_VNI: u32 = 1;
    const FLANNEL_PORT: u16 = 8472;
    /// An interface of ours, left over from a plan which no longer mentions it.
    const STALE: &str = "vpc9-vtp";

    in_private_netns(|| async {
        let Ok((connection, handle, _)) = rtnetlink::new_connection() else {
            panic!("failed to create connection");
        };
        tokio::spawn(connection);
        let handle = Arc::new(handle);

        handle
            .link()
            .add(
                LinkVxlan::new(FLANNEL_VTEP, FLANNEL_VNI)
                    .set_info_data(InfoData::Vxlan(vec![
                        InfoVxlan::Id(FLANNEL_VNI),
                        InfoVxlan::Port(FLANNEL_PORT),
                        InfoVxlan::Local(Ipv4Addr::new(10, 42, 0, 0)),
                        InfoVxlan::Ttl(0),
                    ]))
                    .build(),
            )
            .execute()
            .await
            .unwrap();
        handle
            .link()
            .add(LinkBridge::new(FLANNEL_BRIDGE).build())
            .execute()
            .await
            .unwrap();
        handle
            .link()
            .add(
                LinkVxlan::new(STALE, 9)
                    .set_info_data(InfoData::Vxlan(vec![
                        InfoVxlan::Id(9),
                        InfoVxlan::Port(Vxlan::PORT.as_u16()),
                        InfoVxlan::Local(Ipv4Addr::new(192, 168, 5, 155)),
                        InfoVxlan::Ttl(64),
                    ]))
                    .build(),
            )
            .execute()
            .await
            .unwrap();

        let mut interfaces = MultiIndexInterfaceSpecMap::default();
        let mut vteps = MultiIndexVtepPropertiesSpecMap::default();
        let mut vrfs = MultiIndexVrfPropertiesSpecMap::default();
        let mut associations = MultiIndexInterfaceAssociationSpecMap::default();

        let vtep_props = VtepPropertiesSpec {
            // the same vni flannel is using, on our own port
            vni: FLANNEL_VNI.try_into().unwrap(),
            local: "192.168.5.155"
                .parse::<Ipv4Addr>()
                .unwrap()
                .try_into()
                .unwrap(),
            ttl: 64,
            port: Vxlan::PORT,
        };
        let vrf_props = VrfPropertiesSpec {
            route_table_id: 1.try_into().unwrap(),
        };
        vteps.try_insert(vtep_props.clone()).unwrap();
        vrfs.try_insert(vrf_props.clone()).unwrap();
        for interface in [
            InterfaceSpecBuilder::default()
                .name("vpc1-vrf".try_into().unwrap())
                .admin_state(AdminState::Up)
                .properties(InterfacePropertiesSpec::Vrf(vrf_props))
                .build()
                .unwrap(),
            InterfaceSpecBuilder::default()
                .name("vpc1-bri".try_into().unwrap())
                .admin_state(AdminState::Up)
                .properties(InterfacePropertiesSpec::Bridge(BridgePropertiesSpec {
                    vlan_protocol: EthType::VLAN,
                    vlan_filtering: false,
                }))
                .build()
                .unwrap(),
            InterfaceSpecBuilder::default()
                .name("vpc1-vtp".try_into().unwrap())
                .admin_state(AdminState::Up)
                .properties(InterfacePropertiesSpec::Vtep(vtep_props))
                .build()
                .unwrap(),
        ] {
            interfaces.try_insert(interface).unwrap();
        }
        for (name, controller) in [("vpc1-bri", "vpc1-vrf"), ("vpc1-vtp", "vpc1-bri")] {
            associations
                .try_insert(InterfaceAssociationSpec {
                    name: name.try_into().unwrap(),
                    controller_name: Some(controller.try_into().unwrap()),
                })
                .unwrap();
        }

        let mut required = RequiredInformationBaseBuilder::default()
            .interfaces(interfaces)
            .vteps(vteps)
            .vrfs(vrfs)
            .associations(associations)
            .build()
            .unwrap();

        let vpcs = VpcManager::<RequiredInformationBase>::new(handle);
        let mut passes = 0;
        while !vpcs
            .reconcile(&mut required, &vpcs.observe().await.unwrap())
            .await
        {
            passes += 1;
            assert!(passes < 30, "reconciliation did not converge");
        }

        let observed = vpcs.observe().await.unwrap();
        let get = |name: &str| {
            observed
                .interfaces
                .get_by_name(&InterfaceName::try_from(name).unwrap())
        };

        let flannel_vtep = get(FLANNEL_VTEP)
            .unwrap_or_else(|| panic!("{FLANNEL_VTEP} was removed by the reconciler"));
        assert!(
            matches!(flannel_vtep.properties, InterfaceProperties::Vtep(_)),
            "{FLANNEL_VTEP} was replaced by something else: {flannel_vtep:?}"
        );
        let flannel_bridge = get(FLANNEL_BRIDGE)
            .unwrap_or_else(|| panic!("{FLANNEL_BRIDGE} was removed by the reconciler"));
        assert!(
            matches!(flannel_bridge.properties, InterfaceProperties::Bridge(_)),
            "{FLANNEL_BRIDGE} was replaced by something else: {flannel_bridge:?}"
        );

        // ... but an interface of ours which the plan no longer mentions is still collected
        assert!(
            get(STALE).is_none(),
            "{STALE} is ours and is absent from the plan, so it should have been removed"
        );

        for ours in ["vpc1-vrf", "vpc1-bri", "vpc1-vtp"] {
            assert!(get(ours).is_some(), "{ours} was never created");
        }
    });
}

#[allow(clippy::too_many_lines)] // this is an integration test and is expected to be long
#[n_vm::test]
#[wrap(with_caps([Capability::CAP_NET_ADMIN]))]
async fn reconcile_demo() {
    let mut required_interface_map = MultiIndexInterfaceSpecMap::default();
    let interfaces = [
        InterfaceSpecBuilder::default()
            .name("vpc1-vrf".try_into().unwrap())
            .admin_state(AdminState::Up)
            .properties(InterfacePropertiesSpec::Vrf(VrfPropertiesSpec {
                route_table_id: 1.try_into().unwrap(),
            }))
            .build()
            .unwrap(),
        InterfaceSpecBuilder::default()
            .name("vpc2-vrf".try_into().unwrap())
            .admin_state(AdminState::Up)
            .properties(InterfacePropertiesSpec::Vrf(VrfPropertiesSpec {
                route_table_id: 2.try_into().unwrap(),
            }))
            .build()
            .unwrap(),
        InterfaceSpecBuilder::default()
            .name("vpc1-vtp".try_into().unwrap())
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
            .name("vpc2-vtp".try_into().unwrap())
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
            .name("vpc1-bri".try_into().unwrap())
            .admin_state(AdminState::Up)
            .properties(InterfacePropertiesSpec::Bridge(BridgePropertiesSpec {
                vlan_protocol: EthType::VLAN,
                vlan_filtering: false,
            }))
            .build()
            .unwrap(),
        InterfaceSpecBuilder::default()
            .name("vpc2-bri".try_into().unwrap())
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
            InterfacePropertiesSpec::Tap => {}
        }
    }

    let mut associations = MultiIndexInterfaceAssociationSpecMap::default();
    associations
        .try_insert(InterfaceAssociationSpec {
            name: "vpc1-vtp".to_string().try_into().unwrap(),
            controller_name: Some("vpc1-bri".to_string().try_into().unwrap()),
        })
        .unwrap();
    associations
        .try_insert(InterfaceAssociationSpec {
            name: "vpc2-vtp".to_string().try_into().unwrap(),
            controller_name: Some("vpc2-bri".to_string().try_into().unwrap()),
        })
        .unwrap();
    associations
        .try_insert(InterfaceAssociationSpec {
            name: "vpc1-bri".to_string().try_into().unwrap(),
            controller_name: Some("vpc1-vrf".to_string().try_into().unwrap()),
        })
        .unwrap();
    associations
        .try_insert(InterfaceAssociationSpec {
            name: "vpc2-bri".to_string().try_into().unwrap(),
            controller_name: Some("vpc2-vrf".to_string().try_into().unwrap()),
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
                .name("vpc3-vtp".try_into().unwrap())
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
                .name("vpc3-bri".try_into().unwrap())
                .admin_state(AdminState::Up)
                .controller(None)
                .properties(InterfacePropertiesSpec::Bridge(BridgePropertiesSpec {
                    vlan_protocol: EthType::VLAN,
                    vlan_filtering: false,
                }))
                .build()
                .unwrap(),
            InterfaceSpecBuilder::default()
                .name("vpc3-vrf".try_into().unwrap())
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
                name: "vpc3-bri".to_string().try_into().unwrap(),
                controller_name: Some("vpc3-vrf".to_string().try_into().unwrap()),
            })
            .unwrap();
        req.associations
            .try_insert(InterfaceAssociationSpec {
                name: "vpc3-vtp".to_string().try_into().unwrap(),
                controller_name: Some("vpc3-bri".to_string().try_into().unwrap()),
            })
            .unwrap();
    };

    let remove_some_requirement = move |req: &mut RequiredInformationBase| {
        req.interfaces
            .remove_by_name(&"vpc1-bri".to_string().try_into().unwrap())
            .unwrap();
        req.interfaces
            .remove_by_name(&"vpc1-vrf".to_string().try_into().unwrap())
            .unwrap();
        req.interfaces
            .remove_by_name(&"vpc1-vtp".to_string().try_into().unwrap())
            .unwrap();
        req.associations
            .remove_by_name(&"vpc1-bri".to_string().try_into().unwrap())
            .unwrap();
        req.associations
            .remove_by_name(&"vpc1-vtp".to_string().try_into().unwrap())
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
