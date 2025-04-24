// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use caps::{CapSet, Capability};
use dataplane_vpc_manager::{RequiredInformationBase, RequiredInformationBaseBuilder, VpcManager};
use fixin::wrap;
use interface_manager::interface::{
    BridgePropertiesSpec, InterfaceAssociationSpec, InterfacePropertiesSpec, InterfaceSpecBuilder,
    MultiIndexBridgePropertiesSpecMap, MultiIndexInterfaceAssociationSpecMap,
    MultiIndexInterfaceSpecMap, MultiIndexVrfPropertiesSpecMap, MultiIndexVtepPropertiesSpecMap,
    VrfPropertiesSpec, VtepPropertiesSpec,
};
use interface_manager::netns::swap_thread_to_netns;
use net::eth::ethtype::EthType;
use net::interface::AdminState;
use rekon::{Observe, Reconcile};
use rtnetlink::NetworkNamespace;
use rtnetlink::sys::AsyncSocket;
use std::net::Ipv4Addr;
use std::panic::{RefUnwindSafe, UnwindSafe, catch_unwind};
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info};
use tracing_test::traced_test;

/// Fixture which runs the test in a network namespace of the given name.
fn run_in_netns<F: UnwindSafe + Send + FnOnce() -> T, T>(
    netns_name: impl AsRef<str>,
) -> impl FnOnce(F) -> T
where
    T: Send,
{
    move |f: F| {
        let netns_path = format!("/run/netns/{netns_name}", netns_name = netns_name.as_ref());
        std::thread::scope(|scope| {
            std::thread::Builder::new()
                .name(netns_name.as_ref().to_string())
                .spawn_scoped(scope, || {
                    with_caps([Capability::CAP_SYS_ADMIN])(|| unsafe {
                        swap_thread_to_netns(&netns_path)
                    })
                    .unwrap_or_else(|e| panic!("{e}"));
                    catch_unwind(f).unwrap()
                })
                .unwrap()
                .join()
                .unwrap()
        })
    }
}

/// Fixture which creates and cleans up a network namespace with the given name.
fn with_scoped_netns<F: 'static + Send + RefUnwindSafe + UnwindSafe + Send + FnOnce() -> T, T>(
    netns_name: impl 'static + Send + UnwindSafe + RefUnwindSafe + AsRef<str>,
) -> impl FnOnce(F) -> T
where
    T: Send,
{
    move |f: F| {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .unwrap();
        with_caps([Capability::CAP_SYS_ADMIN])(|| {
            runtime.block_on(async {
                let netns_name_copy = netns_name.as_ref().to_string();
                let Ok((connection, _, _)) = rtnetlink::new_connection() else {
                    panic!("failed to create connection");
                };
                tokio::spawn(connection);
                match NetworkNamespace::add(netns_name_copy).await {
                    Ok(()) => {}
                    Err(err) => {
                        let netns_name = netns_name.as_ref();
                        panic!("failed to create network namespace {netns_name}: {err}");
                    }
                }
            });
        });
        let ret = catch_unwind(f);
        with_caps([Capability::CAP_SYS_ADMIN])(|| {
            runtime.block_on(async {
                match NetworkNamespace::del(netns_name.as_ref().to_string()).await {
                    Ok(()) => {}
                    Err(err) => {
                        let netns_name = netns_name.as_ref();
                        panic!("failed to remove network namespace {netns_name}: {err}");
                    }
                }
            });
        });
        ret.unwrap()
    }
}

/// Fixture which creates and runs a test in the network namespace of the given name.
fn in_scoped_netns<F: 'static + Send + RefUnwindSafe + UnwindSafe + Send + FnOnce() -> T, T>(
    netns_name: impl 'static + Sync + UnwindSafe + RefUnwindSafe + AsRef<str>,
) -> impl FnOnce(F) -> T
where
    T: Send + UnwindSafe + RefUnwindSafe,
{
    let netns_name_copy = netns_name.as_ref().to_string();
    |f: F| with_scoped_netns(netns_name_copy.clone())(|| run_in_netns(netns_name_copy)(f))
}

/// Fixture which runs the supplied function with _additional_ granted capabilities.
fn with_caps<F: UnwindSafe + FnOnce() -> T, T>(
    caps: impl IntoIterator<Item = Capability>,
) -> impl FnOnce(F) -> T {
    move |f: F| {
        let current_caps = match caps::read(None, CapSet::Effective) {
            Ok(current_caps) => current_caps,
            Err(err) => {
                error!("caps error: {}", err);
                panic!("caps error: {err}");
            }
        };
        let needed_caps: Vec<_> = caps
            .into_iter()
            .filter(|cap| !current_caps.contains(cap))
            .collect();
        for cap in &needed_caps {
            caps::raise(None, CapSet::Effective, *cap)
                .unwrap_or_else(|err| panic!("unable to raise capability to {cap}: {err}"));
        }
        let ret = catch_unwind(f);
        for cap in &needed_caps {
            caps::drop(None, CapSet::Effective, *cap)
                .unwrap_or_else(|err| panic!("unable to drop capability to {cap}: {err}"));
        }
        ret.unwrap()
    }
}

#[test]
#[wrap(with_caps([Capability::CAP_NET_ADMIN]))]
#[wrap(in_scoped_netns("reconcile_fuzz"))]
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
#[wrap(in_scoped_netns("reconcile_demo"))]
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
