// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! The configured addresses of the gateway's ports, put on the interfaces which stand for them.
//!
//! # Why the dataplane does this, and not only zebra
//!
//! Each port's addresses are in the FRR configuration the dataplane renders, so zebra puts them on
//! the port's tap. But zebra hands every IPv4 address install to the dataplane's FRR plugin
//! before the kernel sees it. The plugin holds the install until the dataplane answers it, and while
//! no dataplane is listening, it keeps the install queued against the tap that existed when zebra
//! queued it.
//!
//! When FRR runs in a pod of its own, zebra outlives the dataplane. A dataplane which exits just
//! after creating its taps leaves installs queued for them. The next dataplane creates taps with
//! the same names but new indices, and zebra skips them because their addresses are still queued.
//! The queued installs then fail against indices which are gone, and zebra ignores the failure.
//! The taps never get their addresses for the rest of zebra's life, BGP over those ports never
//! comes up, and configuring the address again in FRR changes nothing.
//!
//! An address the kernel reports, however it got there, replaces zebra's stuck record of it. So the
//! dataplane puts the configured addresses on the taps itself, each time it applies a
//! configuration. Zebra's own install, when it comes, finds the address already there.
//!
//! # What this does not do
//!
//! It only adds. An address which leaves the configuration is removed by zebra, as before, when
//! FRR applies the new configuration.

use super::VpcManager;
use config::InternalConfig;
use config::internal::interfaces::interface::{InterfaceAddress, InterfaceType};
use futures::TryStreamExt;
use rtnetlink::packet_route::address::AddressAttribute;
use std::collections::BTreeSet;
use std::net::IpAddr;
use tracing::{debug, error, info, warn};

impl<R> VpcManager<R> {
    /// Put every configured address of each of the gateway's ports on the interface of the same
    /// name, if it is not there already.
    ///
    /// Failures are logged, not returned: zebra installs the same addresses, so one this misses
    /// may still arrive, and a configuration should not be refused over it.
    pub async fn put_port_addresses(&self, internal: &InternalConfig) {
        let Some(default_vrf) = internal.vrfs.default_vrf_config() else {
            return;
        };
        for port in default_vrf
            .interfaces
            .values()
            .filter(|iface| matches!(iface.iftype, InterfaceType::Ethernet(_)))
            .filter(|iface| !iface.addresses.is_empty())
        {
            self.put_addresses(&port.name, &port.addresses).await;
        }
    }

    async fn put_addresses(&self, name: &str, wanted: &BTreeSet<InterfaceAddress>) {
        let index = match self
            .handle
            .link()
            .get()
            .match_name(name.to_string())
            .execute()
            .try_next()
            .await
        {
            Ok(Some(link)) => link.header.index,
            Ok(None) => {
                warn!("port {name} has configured addresses but no interface to put them on");
                return;
            }
            Err(e) => {
                error!("could not look up port {name} to put its addresses on it: {e}");
                return;
            }
        };

        let present = match self.addresses_of(index).await {
            Ok(present) => present,
            Err(e) => {
                error!("could not list the addresses of port {name}: {e}");
                return;
            }
        };

        for address in wanted.iter().filter(|a| !present.contains(*a)) {
            let InterfaceAddress {
                address: ip,
                mask_len,
            } = address;
            match self
                .handle
                .address()
                .add(index, *ip, *mask_len)
                .execute()
                .await
            {
                Ok(()) => info!("put address {ip}/{mask_len} on port {name}"),
                // Zebra got there between the listing and now.
                Err(rtnetlink::Error::NetlinkError(e))
                    if e.to_io().kind() == std::io::ErrorKind::AlreadyExists =>
                {
                    debug!("port {name} already has address {ip}/{mask_len}");
                }
                Err(e) => error!(
                    "could not put address {ip}/{mask_len} on port {name}: {e}. Unless zebra \
                     installs it, nothing routes over this port."
                ),
            }
        }
    }

    async fn addresses_of(
        &self,
        index: u32,
    ) -> Result<BTreeSet<InterfaceAddress>, rtnetlink::Error> {
        self.handle
            .address()
            .get()
            .set_link_index_filter(index)
            .execute()
            .try_filter_map(|message| async move {
                let mask_len = message.header.prefix_len;
                Ok(message
                    .attributes
                    .into_iter()
                    .find_map(|attribute| match attribute {
                        // IFA_LOCAL is the interface's own address; for IPv6, which has none,
                        // IFA_ADDRESS is.
                        AddressAttribute::Local(ip) => Some(InterfaceAddress::new(ip, mask_len)),
                        AddressAttribute::Address(ip @ IpAddr::V6(_)) => {
                            Some(InterfaceAddress::new(ip, mask_len))
                        }
                        _ => None,
                    }))
            })
            .try_collect()
            .await
    }
}
