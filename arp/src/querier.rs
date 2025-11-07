// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! ARP/ND querier

use futures::future::join_all;
use futures::io;
use net::interface::InterfaceIndex;
use rtnetlink::Handle;
use std::fmt::Display;
use std::net::IpAddr;

#[allow(unused)]
use tracing::{debug, error, info, warn};

use crate::netlink::{arp_nd_confirm, arp_nd_probe};

/// A target represents an Ipv4 or Ipv6 address to be resolved over an interface
#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
pub(crate) struct Target {
    pub(crate) addr: IpAddr,
    pub(crate) ifindex: InterfaceIndex,
}
impl Target {
    #[must_use]
    pub(crate) fn new(addr: IpAddr, ifindex: InterfaceIndex) -> Self {
        Self { addr, ifindex }
    }
}
impl Display for Target {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ifindex:{} address:{}", self.ifindex, self.addr)
    }
}

/// An [`ArpNdQuerier`] is the entity responsible for issuing ARP requests / Neighbor solicitations
#[derive(Clone)]
pub(crate) struct ArpNdQuerier {
    handle: Handle,
}
impl ArpNdQuerier {
    /// Create an [`ArpNdQuerier`]. This spawns its netlink connection on the current
    /// tokio runtime. The connection ends once the querier (all of its clones) is dropped.
    pub(crate) fn new() -> io::Result<Self> {
        let (connection, handle, _) = rtnetlink::new_connection()?;
        tokio::spawn(connection);
        Ok(Self { handle })
    }
    async fn query(&self, ifindex: InterfaceIndex, target: IpAddr) {
        if let Err(e) = arp_nd_probe(&self.handle, ifindex.to_u32(), target).await {
            error!("Failure querying for {target} over interface {ifindex}: {e}");
        }
    }
    pub(crate) async fn multi_query(&self, targets: impl Iterator<Item = &Target>) {
        let mut vec = vec![];
        for target in targets {
            debug!("Will query for {target}");
            vec.push(self.query(target.ifindex, target.addr));
        }
        join_all(vec).await;
    }
    /// Have the kernel confirm a target it has a (stale) MAC for. See [`arp_nd_confirm`].
    async fn confirm(&self, target: Target) {
        debug!("Will confirm {target}");
        if let Err(e) = arp_nd_confirm(&self.handle, target.ifindex.to_u32(), target.addr).await {
            error!("Failure confirming {target}: {e}");
        }
    }
    /// Have the kernel confirm several targets. See [`ArpNdQuerier::confirm`].
    pub(crate) async fn multi_confirm(&self, targets: impl Iterator<Item = Target>) {
        join_all(targets.map(|target| self.confirm(target))).await;
    }
}

#[cfg(test)]
pub(crate) mod test {
    use crate::netlink::test_netlink_utils::create_tap;
    use crate::querier::{ArpNdQuerier, Target};
    use caps::Capability;
    use fixin::wrap;
    use std::str::FromStr;
    use std::{net::IpAddr, time::Duration};
    use test_utils::with_caps;
    #[allow(unused)]
    use tracing::{debug, info};
    use tracing_test::traced_test;

    #[n_vm::test]
    #[wrap(with_caps([Capability::CAP_NET_ADMIN]))]
    #[cfg_attr(not(emulated), traced_test)]
    async fn test_arp_nd_querier() {
        let (_, ifindex) = create_tap("tap0").await;

        let querier = ArpNdQuerier::new().unwrap();
        let targets: Vec<_> = [
            "10.0.0.2",
            "10.0.0.3",
            "10.0.0.4",
            "10.0.0.5",
            "fe80::aaaa:bbbb:cccc:0001",
            "fe80::aaaa:bbbb:cccc:0002",
        ]
        .iter()
        .map(|a| Target::new(IpAddr::from_str(a).unwrap(), ifindex))
        .collect();

        querier.multi_query(targets.iter()).await;
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}
