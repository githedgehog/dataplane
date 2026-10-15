// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Netlink routines for ARP/ND

use rtnetlink::packet_route::neighbour::{NeighbourFlags, NeighbourState};
use rtnetlink::packet_route::route::RouteType;

use std::net::IpAddr;

#[allow(unused)]
use tracing::{debug, error, info};

/// Have the kernel resolve `target`. With `NTF_USE`, the kernel only acts as if it had traffic
/// for the target: it creates an (incomplete) entry if there is none, and sends requests if the
/// entry is not reachable. The state requested is ignored. The request does not exclude existing
/// entries (it replaces), so that it can be used to confirm them.
///
/// N.B. `NTF_USE` makes a permanent (static) entry dynamic: the kernel then resolves it as any
/// other, and fails it if nobody answers. So permanent entries should not be probed.
async fn do_probe(
    handle: &rtnetlink::Handle,
    ifindex: u32,
    target: IpAddr,
) -> Result<(), rtnetlink::Error> {
    debug!("Probing for for {target}, ifindex {ifindex}");
    handle
        .neighbours()
        .add(ifindex, target)
        .state(NeighbourState::Incomplete)
        .kind(RouteType::Broadcast)
        .flags(NeighbourFlags::Use)
        .replace()
        .execute()
        .await
}

/// Have the kernel resolve `target`. If the kernel has no entry for it, or a failed one, it
/// starts resolving it: the entry becomes incomplete and requests are broadcast. If the kernel
/// is already resolving it (incomplete entry), the kernel keeps on doing so. See [`do_probe`].
pub async fn arp_nd_probe(
    handle: &rtnetlink::Handle,
    ifindex: u32,
    target: IpAddr,
) -> Result<(), String> {
    do_probe(handle, ifindex, target)
        .await
        .map_err(|e| format!("E: {e}"))
}

/// Have the kernel confirm its entry for `target`, which keeps its MAC meanwhile. For a stale
/// entry, the kernel sends unicast probes to that MAC after a delay: the entry becomes reachable
/// if the neighbor answers, or failed otherwise.
pub async fn arp_nd_confirm(
    handle: &rtnetlink::Handle,
    ifindex: u32,
    target: IpAddr,
) -> Result<(), String> {
    do_probe(handle, ifindex, target)
        .await
        .map_err(|e| format!("E: {e}"))
}

#[cfg(test)]
pub(crate) mod test_netlink_utils {
    use super::arp_nd_probe;
    use crate::cache::{NeighCacheWriter, NeighListener, NeighState};

    use futures::TryStreamExt;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::Notify;

    use caps::Capability;
    use fixin::wrap;
    use interface_manager::interface::TapDevice;
    use net::eth::mac::{DestinationMac, Mac};
    use net::interface::{InterfaceIndex, InterfaceName};
    use nix::net::if_::if_nametoindex;
    use test_utils::with_caps;

    use rtnetlink::packet_route::AddressFamily;
    use rtnetlink::packet_route::neighbour::{
        NeighbourAddress, NeighbourAttribute, NeighbourState,
    };
    use rtnetlink::packet_route::route::RouteType;
    use rtnetlink::{LinkUnspec, new_connection};

    use std::net::IpAddr;
    use std::str::FromStr;
    #[allow(unused)]
    use tracing::{debug, info};
    use tracing_test::traced_test;

    // Util: Create a tap `name` and bring it up. The tap is only used as a kernel interface
    // over which ARP/ND can be done (it is not read or written).
    #[allow(unused)]
    pub(crate) async fn create_tap(name: &str) -> (InterfaceName, InterfaceIndex) {
        let name = InterfaceName::try_from(name).unwrap();
        TapDevice::open(&name).await.expect("Failed to create tap");
        let ifindex = if_nametoindex(name.as_ref()).expect("Failed to get tap ifindex");

        // FIXME: the TapDevice in main is broken: nobody holds the fd open, so it gets no carrier.
        // Temporary fixing this via sysctl
        for sysctl in [
            format!("/proc/sys/net/ipv4/conf/{name}/arp_evict_nocarrier"),
            format!("/proc/sys/net/ipv6/conf/{name}/ndisc_evict_nocarrier"),
        ] {
            std::fs::write(&sysctl, "0").unwrap_or_else(|e| panic!("Failed to set {sysctl}: {e}"));
        }
        bring_up(ifindex).await;

        // Bring loopback up too, which gives the host an IPv4 address (127.0.0.1). Otherwise,
        // the kernel has no local routing table and deems every IPv4 destination broadcast:
        // its neighbors are then NOARP, and ARP requests are never sent.
        bring_up(if_nametoindex("lo").expect("Failed to get loopback ifindex")).await;

        (name, InterfaceIndex::try_new(ifindex).unwrap())
    }

    // Util: Bring a kernel interface up (e.g. a tap)
    async fn bring_up(ifindex: u32) {
        let (connection, handle, _) = rtnetlink::new_connection().unwrap();
        tokio::spawn(connection);
        handle
            .link()
            .set(LinkUnspec::new_with_index(ifindex).up().build())
            .execute()
            .await
            .expect("Failed to bring up interface");
        info!("Interface with ifindex {ifindex} should now be up");
    }

    // Util: Set the kernel neighbor entry for `target` in some `state`, with or without a mac
    #[allow(unused)]
    pub(crate) async fn set_neigh(
        ifindex: u32,
        target: IpAddr,
        mac: Option<Mac>,
        state: NeighbourState,
    ) -> Result<(), rtnetlink::Error> {
        let (connection, handle, _) = rtnetlink::new_connection().unwrap();
        tokio::spawn(connection);

        debug!("Setting entry {target} -- {mac:?}, ifindex {ifindex} in state {state}");
        let request = handle
            .neighbours()
            .add(ifindex, target)
            .state(state)
            .kind(RouteType::Broadcast);
        let request = match mac {
            Some(mac) => request.link_layer_address(mac.as_ref()),
            None => request,
        };
        request.replace().execute().await
    }

    // Util: Get the state of the kernel neighbor entry for `target`, if there is one
    #[allow(unused)]
    pub(crate) async fn get_neigh_state(ifindex: u32, target: IpAddr) -> Option<NeighbourState> {
        let (connection, handle, _) = rtnetlink::new_connection().unwrap();
        tokio::spawn(connection);

        let (family, address) = match target {
            IpAddr::V4(a) => (AddressFamily::Inet, NeighbourAddress::Inet(a)),
            IpAddr::V6(a) => (AddressFamily::Inet6, NeighbourAddress::Inet6(a)),
        };
        let mut neighbors = handle
            .neighbours()
            .get()
            .set_address_family(family)
            .execute();
        while let Some(neigh) = neighbors.try_next().await.unwrap() {
            let destination = NeighbourAttribute::Destination(address.clone());
            if neigh.header.ifindex == ifindex && neigh.attributes.contains(&destination) {
                return Some(neigh.header.state);
            }
        }
        None
    }

    // Util: Wait until `condition` holds, for at most `timeout`. Returns whether it holds.
    #[allow(unused)]
    pub(crate) async fn wait_until(
        timeout: Duration,
        mut condition: impl AsyncFnMut() -> bool,
    ) -> bool {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if condition().await {
                return true;
            }
            if tokio::time::Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    #[n_vm::test]
    #[wrap(with_caps([Capability::CAP_NET_ADMIN]))]
    #[cfg_attr(not(emulated), traced_test)]
    async fn test_neigh_netlink_probing() {
        let (_, ifindex) = create_tap("tap0").await;
        let ifindex = ifindex.to_u32();

        let (connection, handle, _) = new_connection().unwrap();
        tokio::spawn(connection);

        // ARP
        let target = IpAddr::from_str("10.0.0.7").unwrap();
        arp_nd_probe(&handle, ifindex, target).await.unwrap();

        // ND
        let target = IpAddr::from_str("fe80::aaaa:bbbb:cccc:0001").unwrap();
        arp_nd_probe(&handle, ifindex, target).await.unwrap();
    }

    /// Test that the listener learns the neighbors added to the kernel: it adds them to the
    /// cache and reports the additions.
    #[n_vm::test]
    #[wrap(with_caps([Capability::CAP_NET_ADMIN]))]
    #[cfg_attr(not(emulated), traced_test)]
    async fn test_neigh_netlink_listener() {
        // create a tap and bring it up
        let (_, ifindex) = create_tap("tap0").await;

        // create cache and listener writing to it
        let (cachew, cacher) = NeighCacheWriter::new();
        let report = Arc::new(Notify::new());
        let listener = NeighListener::new(cachew, report.clone()).unwrap();
        let listening = tokio::spawn(listener.start());

        // emulate a neighbor responding to an ARP/NS: the kernel has a reachable entry for it
        let ip = IpAddr::from_str("10.0.0.7").unwrap();
        let mac = Mac([0x02, 0xca, 0xfe, 0xba, 0xbe, 0x07]);
        set_neigh(ifindex.to_u32(), ip, Some(mac), NeighbourState::Reachable)
            .await
            .unwrap();

        // check that the listener reports the addition in the cache
        tokio::time::timeout(Duration::from_secs(5), report.notified())
            .await
            .expect("the listener did not report the new neighbor");

        // check that the mac is in the cache, and the name of the interface of the new entry
        assert_eq!(
            cacher.get_mac(ip, ifindex),
            Some(DestinationMac::new(mac).unwrap())
        );
        let ifname = cacher
            .get_entry(ip, ifindex)
            .and_then(|e| e.ifname().cloned());
        assert_eq!(ifname.as_deref(), Some("tap0"));
        let cache = cacher.enter().unwrap();
        println!("{}", *cache);

        listening.abort();
    }

    /// Test that the listener mirrors the state of the kernel neighbors in the cache: a stale
    /// neighbor is usable, and a failed one is not (the kernel provides no mac for it).
    #[n_vm::test]
    #[wrap(with_caps([Capability::CAP_NET_ADMIN]))]
    #[cfg_attr(not(emulated), traced_test)]
    async fn test_neigh_netlink_listener_stale_and_failed() {
        // create a tap and bring it up
        let (_, ifindex) = create_tap("tap0").await;

        // create cache and listener writing to it
        let (cachew, cacher) = NeighCacheWriter::new();
        let listener = NeighListener::new(cachew, Arc::new(Notify::new())).unwrap();
        let listening = tokio::spawn(listener.start());

        let ip = IpAddr::from_str("10.0.0.7").unwrap();
        let mac = Mac([0x02, 0xca, 0xfe, 0xba, 0xbe, 0x07]);
        let state = || cacher.get_entry(ip, ifindex).map(|entry| entry.state());

        // a stale neighbor is in the cache, and usable
        set_neigh(ifindex.to_u32(), ip, Some(mac), NeighbourState::Stale)
            .await
            .unwrap();
        let stale = wait_until(Duration::from_secs(5), async || {
            state() == Some(NeighState::Stale)
        })
        .await;
        assert!(stale, "the stale neighbor is not in the cache");
        assert_eq!(
            cacher.get_mac(ip, ifindex),
            Some(DestinationMac::new(mac).unwrap())
        );

        // a failed neighbor is in the cache, but not usable
        set_neigh(ifindex.to_u32(), ip, None, NeighbourState::Failed)
            .await
            .unwrap();
        let failed = wait_until(Duration::from_secs(5), async || {
            state() == Some(NeighState::Failed)
        })
        .await;
        assert!(failed, "the failed neighbor is not in the cache");
        assert!(cacher.get_mac(ip, ifindex).is_none());

        // the name of the interface is kept across updates
        let ifname = cacher
            .get_entry(ip, ifindex)
            .and_then(|e| e.ifname().cloned());
        assert_eq!(ifname.as_deref(), Some("tap0"));

        listening.abort();
    }

    /// Test that the listener learns the neighbors that the kernel has before it was created
    /// (with their state and mac) when synced, without waiting for any change.
    #[n_vm::test]
    #[wrap(with_caps([Capability::CAP_NET_ADMIN]))]
    #[cfg_attr(not(emulated), traced_test)]
    async fn test_neigh_netlink_listener_sync() {
        // create a tap and bring it up
        let (_, ifindex) = create_tap("tap0").await;

        // the kernel has some neighbors
        let permanent = IpAddr::from_str("10.0.0.7").unwrap();
        let reachable = IpAddr::from_str("10.0.0.8").unwrap();
        let failed = IpAddr::from_str("10.0.0.9").unwrap();
        let mac1 = Mac([0x02, 0xca, 0xfe, 0xba, 0xbe, 0x07]);
        let mac2 = Mac([0x02, 0xca, 0xfe, 0xba, 0xbe, 0x08]);
        let ifindex_u32 = ifindex.to_u32();
        set_neigh(
            ifindex_u32,
            permanent,
            Some(mac1),
            NeighbourState::Permanent,
        )
        .await
        .unwrap();
        set_neigh(
            ifindex_u32,
            reachable,
            Some(mac2),
            NeighbourState::Reachable,
        )
        .await
        .unwrap();
        set_neigh(ifindex_u32, failed, None, NeighbourState::Failed)
            .await
            .unwrap();

        // create cache and listener writing to it, and sync it
        let (cachew, cacher) = NeighCacheWriter::new();
        let mut listener = NeighListener::new(cachew, Arc::new(Notify::new())).unwrap();
        let learnt = listener.sync().await.unwrap();
        assert!(learnt >= 3, "only {learnt} neighbors were learnt");

        // the neighbors are in the cache, with their state and mac
        let entry = |ip| {
            cacher
                .get_entry(ip, ifindex)
                .map(|entry| (entry.state(), entry.mac()))
        };
        let mac = |mac| Some(DestinationMac::new(mac).unwrap());
        assert_eq!(entry(permanent), Some((NeighState::Permanent, mac(mac1))));
        assert_eq!(entry(reachable), Some((NeighState::Reachable, mac(mac2))));
        assert_eq!(entry(failed), Some((NeighState::Failed, None)));
        let ifname = cacher
            .get_entry(permanent, ifindex)
            .and_then(|e| e.ifname().cloned());
        assert_eq!(ifname.as_deref(), Some("tap0"), "learnt entries are named");

        // the listener can then be started
        let listening = tokio::spawn(listener.start());
        listening.abort();
    }
}
