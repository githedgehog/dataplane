// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use dataplane_mgmt as mgmt;
use std::ffi::{CStr, CString};

use caps::Capability;
use fixin::wrap;
use interface_manager::interface::{
    BridgePropertiesSpec, InterfaceAssociationSpec, InterfacePropertiesSpec, InterfaceSpecBuilder,
    MultiIndexBridgePropertiesSpecMap, MultiIndexInterfaceAssociationSpecMap,
    MultiIndexInterfaceSpecMap, MultiIndexPciNetdevPropertiesSpecMap,
    MultiIndexVrfPropertiesSpecMap, MultiIndexVtepPropertiesSpecMap, PciNetdevPropertiesSpec,
    VrfPropertiesSpec, VtepPropertiesSpec,
};
use mgmt::vpc_manager::{RequiredInformationBase, RequiredInformationBaseBuilder, VpcManager};
use net::buffer::{PacketBuffer, PacketBufferMut, TestBuffer};
use net::eth::ethtype::EthType;
use net::headers::TryHeaders;
use net::interface::switch::SwitchId;
use net::interface::{AdminState, InterfaceName, Mtu};
use net::packet::Packet;
use net::pci::PciEbdf;
use net::vxlan::Vxlan;
use rekon::{Observe, Reconcile};
use rtnetlink::sys::AsyncSocket;
use std::net::Ipv4Addr;
use std::num::NonZero;
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::time::Duration;
use test_utils::with_caps;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
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
            .name("enp1s0f1np1".try_into().unwrap())
            .admin_state(AdminState::Up)
            .properties(InterfacePropertiesSpec::Pci(PciNetdevPropertiesSpec {
                // switch_id: Some(SwitchId::new("ac88b20003ebc008").unwrap()),
                // port_name: Some("p1".to_string()),
                // parent_dev: Some(PciEbdf::try_new("0000:01:00.1".to_string()).unwrap()),
                switch_id: None,
                port_name: None,
                parent_dev: None,
            }))
            .mtu(Some(Mtu::try_from(9000).unwrap()))
            .build()
            .unwrap(),
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

#[repr(transparent)]
#[derive(Debug)]
pub struct TapDevice {
    file: tokio::fs::File,
}

impl TapDevice {
    #[cold]
    #[tracing::instrument(level = "info")]
    pub async fn new(name: &InterfaceName) -> Result<Self, std::io::Error> {
        mod helper {
            nix::ioctl_write_ptr_bad!(
                /** Create a tap device */
                make_tap_device,
                libc::TUNSETIFF,
                libc::ifreq
            );
            nix::ioctl_write_ptr_bad!(
                /** Keep the tap device after the program ends */
                persist_tap_device,
                libc::TUNSETPERSIST,
                libc::ifreq
            );
        }
        debug!("opening /dev/net/tun");
        let tap_file = tokio::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open("/dev/net/tun")
            .await?;
        let mut ifreq = libc::ifreq {
            ifr_name: [0; libc::IF_NAMESIZE],
            ifr_ifru: libc::__c_anonymous_ifr_ifru {
                ifru_ifindex: libc::IFF_TAP | libc::IFF_NO_PI,
            },
        };
        for (i, byte) in name.as_ref().as_bytes().iter().enumerate() {
            ifreq.ifr_name[i] = *byte as libc::c_char
        }
        debug!("attempting to create tap device: {name}");
        let ret = unsafe { helper::make_tap_device(tap_file.as_raw_fd(), &ifreq)? };
        if ret < 0 {
            let err = std::io::Error::last_os_error();
            error!("failed to create tap device {name}: {err}");
            return Err(err);
        }
        info!("created tap device: {name}");
        debug!("attempting to persist tap device: {name}");
        unsafe { helper::persist_tap_device(tap_file.as_raw_fd(), &ifreq)? };
        if ret < 0 {
            let err = std::io::Error::last_os_error();
            error!("failed to persist tap device {name}: {err}");
            return Err(err);
        }
        info!("persisted tap device: {name}");
        Ok(Self { file: tap_file })
    }

    #[tracing::instrument(level = "trace")]
    pub async fn read<Buf: PacketBufferMut>(
        &mut self,
        buf: &mut Buf,
    ) -> Result<NonZero<u16>, tokio::io::Error> {
        let bytes_read = self.file.read(buf.as_mut()).await?;
        let bytes_read = match u16::try_from(bytes_read) {
            Ok(bytes_read) => bytes_read,
            Err(err) => {
                error!("nonsense packet length received: {err}");
                return Err(tokio::io::Error::other(err));
            }
        };
        let bytes_read = match NonZero::new(bytes_read) {
            Some(bytes_read) => bytes_read,
            None => {
                return Err(tokio::io::Error::new(
                    tokio::io::ErrorKind::UnexpectedEof,
                    "unexpected EOF on tap device",
                ));
            }
        };
        let orig_len = match u16::try_from(buf.as_ref().len()) {
            Ok(orig_len) => orig_len,
            Err(err) => {
                error!("nonsense sized buffer: {}", buf.as_ref().len());
                return Err(tokio::io::Error::other(err));
            }
        };
        debug_assert!(orig_len >= bytes_read.get());
        buf.trim_from_end(orig_len - bytes_read.get())
            .expect("failed to trim buffer: illegal memory manipulation");
        Ok(bytes_read)
    }

    #[tracing::instrument(level = "trace")]
    pub async fn write<Buf: PacketBuffer>(&mut self, buf: Buf) -> Result<(), tokio::io::Error> {
        self.file.write_all(buf.as_ref()).await
    }
}

#[tokio::test(flavor = "current_thread")]
#[traced_test]
#[wrap(with_caps([Capability::CAP_NET_ADMIN]))]
async fn tap_test_tokio2() -> Result<(), tokio::io::Error> {
    let mut tap_device = TapDevice::new(&InterfaceName::try_from("some_tap1").unwrap())
        .await
        .unwrap();
    // TODO: assert that the MTU is less than or equal to 16348
    let buf = [0u8; 16384];
    let mut test_buffer = TestBuffer::from_raw_data(&buf);
    let bytes_read = tap_device.read(&mut test_buffer).await?;
    assert_eq!(bytes_read.get() as usize, test_buffer.as_ref().len());
    let packet = Packet::new(test_buffer).unwrap();
    trace!("got packet: {:#?}", packet.headers());
    assert_eq!(packet.total_len(), bytes_read.get());
    let test_buffer = packet.serialize().unwrap();
    tap_device.write(test_buffer).await
}

#[tokio::test(flavor = "current_thread")]
#[traced_test]
#[wrap(with_caps([Capability::CAP_NET_ADMIN]))]
async fn tap_test_tokio() {
    let mut tap_device = TapDevice::new(&InterfaceName::try_from("some_tap0").unwrap())
        .await
        .unwrap();

    // TODO: assert that the MTU is less than or equal to 16348
    let buf = [0u8; 16384];
    loop {
        let mut test_buffer = TestBuffer::from_raw_data(&buf);
        match tap_device.file.read(test_buffer.as_mut()).await {
            Ok(_) => {
                let packet = Packet::new(test_buffer).unwrap();
                debug!("got packet: {:#?}", packet.headers());
                let test_buffer = packet.serialize().unwrap();
                tap_device
                    .file
                    .write_all(test_buffer.as_ref())
                    .await
                    .unwrap();
            }
            Err(err) => {
                error!("failed to read from tap: {err}");
            }
        }
    }
}
