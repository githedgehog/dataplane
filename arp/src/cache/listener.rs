// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! ARP/ND cache kernel listener. The kernel listener opens a netlink socket to the kernel,
//! subscribes for neighbor changes and updates the neighbor cache. It is the only writer
//! to the cache.

use crate::cache::cacherw::NeighCacheWriter;
use crate::cache::{NeighEntry, NeighState};

use futures::{StreamExt, TryStreamExt};
use net::eth::mac::DestinationMac;
use net::eth::mac::Mac;
use net::interface::InterfaceIndex;

use rtnetlink::packet_core::{NetlinkMessage, NetlinkPayload};
use rtnetlink::packet_route::neighbour::{
    NeighbourAddress, NeighbourAttribute, NeighbourFlags, NeighbourMessage, NeighbourState,
};
use rtnetlink::packet_route::{AddressFamily, RouteNetlinkMessage};
use rtnetlink::proto::Connection;
use rtnetlink::sys::{SocketAddr, TokioSocket};
use rtnetlink::{MulticastGroup, new_connection, new_multicast_connection_with_socket};

use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::Notify;

use futures::channel::mpsc::UnboundedReceiver;

#[allow(unused)]
use tracing::{debug, error, info};

fn get_ip_address(attributes: &[NeighbourAttribute]) -> Option<IpAddr> {
    if let Some(destination) = attributes
        .iter()
        .find(|a| matches!(*a, NeighbourAttribute::Destination(_)))
    {
        return match destination {
            NeighbourAttribute::Destination(NeighbourAddress::Inet(a)) => Some(IpAddr::V4(*a)),
            NeighbourAttribute::Destination(NeighbourAddress::Inet6(a)) => Some(IpAddr::V6(*a)),
            _ => None,
        };
    }
    None
}
fn get_mac(attributes: &[NeighbourAttribute]) -> Option<DestinationMac> {
    let addr_vec = attributes
        .iter()
        .find(|a| matches!(*a, NeighbourAttribute::LinkLocalAddress(_)))
        .map(|x| match x {
            NeighbourAttribute::LinkLocalAddress(mac) => mac.clone(),
            _ => unreachable!(),
        })?;

    let mac_array: Result<[u8; 6], _> = addr_vec.try_into();
    match mac_array {
        Ok(mac) => DestinationMac::new(Mac::from(mac)).ok(),
        Err(_) => None,
    }
}

// Convert the state of a neighbor from rtnetlink
impl TryFrom<NeighbourState> for NeighState {
    type Error = String; // FIXME
    fn try_from(state: NeighbourState) -> Result<Self, Self::Error> {
        match state {
            NeighbourState::None => Ok(NeighState::Unset),
            NeighbourState::Incomplete => Ok(NeighState::Incomplete),
            NeighbourState::Reachable => Ok(NeighState::Reachable),
            NeighbourState::Stale => Ok(NeighState::Stale),
            NeighbourState::Delay => Ok(NeighState::Delay),
            NeighbourState::Probe => Ok(NeighState::Probe),
            NeighbourState::Failed => Ok(NeighState::Failed),
            NeighbourState::Noarp => Ok(NeighState::Noarp),
            NeighbourState::Permanent => Ok(NeighState::Permanent),
            state => Err(format!("Unknown neighbor state {state}")),
        }
    }
}

// Build a [`NeighEntry`] from a netlink neighbor message.
// Mac is optional, as it may not be known.
impl TryFrom<&NeighbourMessage> for NeighEntry {
    type Error = String; // FIXME
    fn try_from(neigh: &NeighbourMessage) -> Result<Self, Self::Error> {
        let ifindex = InterfaceIndex::try_from(neigh.header.ifindex).map_err(|e| e.to_string())?; // FIXME
        let address = get_ip_address(&neigh.attributes).ok_or("No ip available".to_string())?;
        let state = NeighState::try_from(neigh.header.state)?;
        let mac = get_mac(&neigh.attributes);
        Ok(Self {
            address,
            ifindex,
            mac,
            state,
        })
    }
}

/// Check if `AddressFamily` is for IPv4 (ARP) or IPv6 (ND)
fn is_ip_family(family: AddressFamily) -> bool {
    matches!(family, AddressFamily::Inet | AddressFamily::Inet6)
}

/// We want the cache to mirror the kernel's arp/nd cache. However, we don't want/need
/// some of the entries in the kernel. This method filters out:
///   - families other than IPv4/IPv6 (e.g. bridge FDB entries)
///   - neigh entries installed by a control plane (e.g. EVPN rmacs of remote VTEPs that FRR installs over the VRF bridges).
///   - entries for multicast addresses (mac is derived from the address).
fn is_arp_nd_neighbor(neigh: &NeighbourMessage) -> bool {
    is_ip_family(neigh.header.family)
        && !neigh.header.flags.contains(NeighbourFlags::ExtLearned)
        && get_ip_address(&neigh.attributes).is_none_or(|address| !address.is_multicast())
}

/// The [`NeighListener`] is the component that listens to netlink neighbor changes and
/// updates the cache, mirroring the kernel neighbors: entries tell the state of the resolution
/// and whether they are usable. The cache will be visible by the pipeline NFs (e.g. egress) and
/// also the ARP/ND resolver which manages packets awaiting resolution:
///    - Every time the listener adds or updates an entry in the cache, it notifies over `cache_notify`,
///      to let the single waiter (the ARP/ND resolver task) know that the cache was modified.
///      The notifications over `cache_notify` won't be missed.
pub(crate) struct NeighListener {
    connection: Option<Connection<RouteNetlinkMessage, TokioSocket>>,
    receiver: UnboundedReceiver<(NetlinkMessage<RouteNetlinkMessage>, SocketAddr)>,
    cachew: NeighCacheWriter,
    cache_notify: Arc<Notify>,
}
impl NeighListener {
    /// Create a new [`NeighListener`]
    pub fn new(cachew: NeighCacheWriter, cache_notify: Arc<Notify>) -> std::io::Result<Self> {
        let (connection, _handle, receiver) =
            new_multicast_connection_with_socket::<TokioSocket>(&[MulticastGroup::Neigh])?;
        Ok(Self {
            connection: Some(connection),
            receiver,
            cachew,
            cache_notify,
        })
    }

    /// Learn the neighbors that the kernel already has and update the cache.
    /// This must be called before [`NeighListener::start`] since otherwise attempting to resolve
    /// IPs could destroy permanent ARP entries. This method uses its own netlink connection for simplicity.
    ///
    /// # Errors
    ///
    /// Fails if the netlink connection cannot be created, or if the dump fails.
    pub async fn sync(&mut self) -> Result<usize, String> {
        let (connection, handle, _) = new_connection().map_err(|e| e.to_string())?;
        tokio::spawn(connection);

        // pull all neighbors
        let mut neighbors = handle.neighbours().get().execute();
        let mut entries = vec![];
        while let Some(neigh) = neighbors.try_next().await.map_err(|e| e.to_string())? {
            if !is_arp_nd_neighbor(&neigh) {
                continue;
            }
            match NeighEntry::try_from(&neigh) {
                Ok(entry) => entries.push(entry),
                Err(e) => debug!("Ignoring neighbor: {e}"),
            }
        }
        let num_entries = entries.len();
        self.cachew.add_entries(entries);
        Ok(num_entries)
    }

    /// Start the [`NeighListener`]: it listens to the changes of the neighbors. It only ends if
    /// its netlink connection ends.
    pub async fn start(mut self) {
        if let Some(connection) = self.connection.take() {
            tokio::select! {
                () = connection => error!("Netlink neighbor connection terminated!"),
                () = self.listen() => {}
            }
        }
    }

    async fn listen(&mut self) {
        debug!("Netlink neighbor listener started...");
        while let Some((message, _)) = self.receiver.next().await {
            match &message.payload {
                NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewNeighbour(neigh)) => {
                    if !is_arp_nd_neighbor(neigh) {
                        continue;
                    }
                    match NeighEntry::try_from(neigh) {
                        Ok(entry) => {
                            // publish entry and notify
                            self.cachew.add_entry(entry);
                            self.cache_notify.notify_one();
                        }
                        Err(e) => debug!("Ignoring neighbor: {e}"),
                    }
                }
                NetlinkPayload::InnerMessage(RouteNetlinkMessage::DelNeighbour(neigh)) => {
                    if !is_ip_family(neigh.header.family) {
                        continue;
                    }
                    let Ok(ifindex) = InterfaceIndex::try_from(neigh.header.ifindex) else {
                        continue;
                    };
                    let Some(address) = get_ip_address(&neigh.attributes) else {
                        continue;
                    };
                    self.cachew.del_entry(address, ifindex);
                }
                NetlinkPayload::Error(e) => error!("Netlink error: {:?}", e),
                _ => {} // ignore
            }
        }
    }
}
