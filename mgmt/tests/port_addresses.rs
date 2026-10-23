// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! The vpc manager putting configured port addresses on the ports' taps, against a real kernel.
//!
//! Kept apart from `reconcile.rs`, which needs the `bolero` feature, so that it runs in every
//! test build.

use dataplane_mgmt as mgmt;

use caps::Capability;
use concurrency::sync::Arc;
use config::internal::interfaces::interface::{IfEthConfig, InterfaceConfig, InterfaceType};
use config::internal::routing::vrf::VrfConfig;
use config::{DeviceConfig, InternalConfig};
use fixin::wrap;
use futures::TryStreamExt;
use interface_manager::interface::TapDevice;
use mgmt::vpc_manager::{RequiredInformationBase, VpcManager};
use net::interface::InterfaceName;
use nix::sched::CloneFlags;
use rtnetlink::packet_route::address::AddressAttribute;
use std::collections::BTreeSet;
use std::future::Future;
use std::net::IpAddr;
use test_utils::with_caps;

/// Run `exec` in a network namespace of this test's own, so that the tap it creates and the
/// addresses it adds touch nothing real.
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

/// The addresses on the interface with this index, as `address/prefix length`.
async fn addresses_on(handle: &rtnetlink::Handle, index: u32) -> BTreeSet<(IpAddr, u8)> {
    handle
        .address()
        .get()
        .set_link_index_filter(index)
        .execute()
        .map_ok(|message| {
            let prefix_len = message.header.prefix_len;
            message
                .attributes
                .into_iter()
                .find_map(|attribute| match attribute {
                    AddressAttribute::Local(ip) => Some(ip),
                    AddressAttribute::Address(ip @ IpAddr::V6(_)) => Some(ip),
                    _ => None,
                })
                .map(|ip| (ip, prefix_len))
        })
        .try_filter_map(|address| async move { Ok(address) })
        .try_collect()
        .await
        .unwrap()
}

async fn index_of(handle: &rtnetlink::Handle, name: &str) -> u32 {
    handle
        .link()
        .get()
        .match_name(name.to_string())
        .execute()
        .try_next()
        .await
        .unwrap()
        .unwrap_or_else(|| panic!("{name} does not exist"))
        .header
        .index
}

/// A port's configured addresses end up on its tap, whatever zebra has or has not done.
///
/// Zebra can be left unable to address a tap for good (see `port_addresses.rs` in the vpc
/// manager), so the dataplane puts the addresses on itself. This checks the parts of that which
/// the kernel alone can show:
///
/// - every configured address of an ethernet port lands on the interface of that name, IPv4 and
///   IPv6, with and without a broadcast address;
/// - an address zebra already installed is left in place and does not stop the rest;
/// - applying the same configuration again changes nothing and fails nothing;
/// - a port with no interface is passed over, and a loopback's addresses are not touched.
#[n_vm::test]
#[wrap(with_caps([Capability::CAP_NET_ADMIN, Capability::CAP_SYS_ADMIN]))]
fn configured_port_addresses_are_put_on_the_ports_taps() {
    const PORT: &str = "port1";

    in_private_netns(|| async {
        let Ok((connection, handle, _)) = rtnetlink::new_connection() else {
            panic!("failed to create connection");
        };
        tokio::spawn(connection);
        let handle = Arc::new(handle);

        // Held for the duration, as the control-plane bridge would hold it.
        let tap = TapDevice::open(&InterfaceName::try_from(PORT).unwrap()).unwrap();
        let index = index_of(&handle, PORT).await;
        let lo = index_of(&handle, "lo").await;

        let wanted: BTreeSet<(IpAddr, u8)> = [
            (IpAddr::from([192, 0, 2, 0]), 31),
            (IpAddr::from([198, 51, 100, 1]), 24),
            ("2001:db8::1".parse().unwrap(), 64),
        ]
        .into_iter()
        .collect();
        let mut port = InterfaceConfig::new(
            PORT,
            InterfaceType::Ethernet(IfEthConfig { mac: None }),
            false,
        );
        for (ip, prefix_len) in &wanted {
            port = port.add_address(*ip, *prefix_len);
        }
        let absent = InterfaceConfig::new(
            "absent0",
            InterfaceType::Ethernet(IfEthConfig { mac: None }),
            false,
        )
        .add_address(IpAddr::from([203, 0, 113, 0]), 31);
        let loopback = InterfaceConfig::new("lo", InterfaceType::Loopback, false)
            .add_address(IpAddr::from([10, 255, 0, 1]), 32);
        let mut default_vrf = VrfConfig::new("default", None, true);
        default_vrf.add_interface_config(port);
        default_vrf.add_interface_config(absent);
        default_vrf.add_interface_config(loopback);
        let mut internal = InternalConfig::new("gw", DeviceConfig::new());
        internal.add_vrf_config(default_vrf).unwrap();

        assert!(
            addresses_on(&handle, index).await.is_disjoint(&wanted),
            "{PORT} starts with addresses this test expects the manager to add"
        );

        // As if zebra had installed one before the dataplane got to it.
        handle
            .address()
            .add(index, IpAddr::from([198, 51, 100, 1]), 24)
            .execute()
            .await
            .unwrap();

        let vpcs = VpcManager::<RequiredInformationBase>::new(handle.clone());
        vpcs.put_port_addresses(&internal).await;
        assert_eq!(
            addresses_on(&handle, index).await,
            wanted,
            "{PORT} should hold exactly its configured addresses"
        );

        vpcs.put_port_addresses(&internal).await;
        assert_eq!(
            addresses_on(&handle, index).await,
            wanted,
            "applying the same configuration again should change nothing"
        );

        assert!(
            !addresses_on(&handle, lo)
                .await
                .contains(&(IpAddr::from([10, 255, 0, 1]), 32)),
            "the loopback is not a port; its addresses are zebra's alone to install"
        );

        drop(tap);
    });
}
