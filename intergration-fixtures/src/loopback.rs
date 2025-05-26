// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use derive_builder::Builder;
use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;
use test_utils::in_netns;

#[derive(Debug, Builder, Clone, Default, PartialOrd, PartialEq, Eq, Ord, Hash)]
#[builder(setter(into))]
pub struct LoopbackSpec {
    #[builder(default)]
    ipv4: BTreeSet<(Ipv4Addr, u8)>,
    #[builder(default)]
    ipv6: BTreeSet<(Ipv6Addr, u8)>,
}

impl LoopbackSpecBuilder {
    pub fn add_ipv4(&mut self, ip: Ipv4Addr, prefix: u8) -> &mut Self {
        if prefix > 32 {
            panic!("illegal ipv4 prefix: {prefix}");
        }
        match self.ipv4 {
            None => self.ipv4([(ip, prefix)]),
            Some(ref mut set) => {
                set.insert((ip, prefix));
                self
            }
        }
    }

    pub fn add_ipv6(&mut self, ip: Ipv6Addr, prefix: u8) -> &mut Self {
        if prefix > 128 {
            panic!("illegal ipv6 prefix: {prefix}");
        }
        match self.ipv6 {
            None => self.ipv6([(ip, prefix)]),
            Some(ref mut set) => {
                set.insert((ip, prefix));
                self
            }
        }
    }

    pub fn add_ip(&mut self, ip: IpAddr, prefix: u8) -> &mut Self {
        match ip {
            IpAddr::V4(ip) => self.add_ipv4(ip, prefix),
            IpAddr::V6(ip) => self.add_ipv6(ip, prefix),
        }
    }
}

#[derive(Debug)]
pub struct Loopback {
    spec: LoopbackSpec,
}

impl Loopback {
    pub fn ipv4(&self) -> impl Iterator<Item = &(Ipv4Addr, u8)> {
        self.spec.ipv4.iter()
    }

    pub fn ipv6(&self) -> impl Iterator<Item = &(Ipv6Addr, u8)> {
        self.spec.ipv6.iter()
    }

    pub(crate) fn configure(netns_path: impl AsRef<Path>, spec: LoopbackSpec) -> Loopback {
        let spec = in_netns(netns_path.as_ref(), || async move {
            let Ok((connection, handle, _)) = rtnetlink::new_connection() else {
                panic!("failed to create connection");
            };
            tokio::spawn(connection);
            const LOOPBACK_IFINDEX: u32 = 1;
            for assignment in &spec.ipv4 {
                handle
                    .address()
                    .add(LOOPBACK_IFINDEX, assignment.0.into(), assignment.1)
                    .execute()
                    .await
                    .unwrap();
            }
            for assignment in &spec.ipv6 {
                handle
                    .address()
                    .add(LOOPBACK_IFINDEX, assignment.0.into(), assignment.1)
                    .execute()
                    .await
                    .unwrap();
            }
            spec
        });
        Loopback { spec }
    }
}

#[cfg(test)]
mod tests {
    use crate::loopback::{Loopback, LoopbackSpecBuilder};
    use caps::Capability;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::path::PathBuf;
    use test_utils::fixin::wrap;
    use test_utils::with_caps;

    #[test]
    #[wrap(with_caps([Capability::CAP_SYS_ADMIN, Capability::CAP_NET_ADMIN]))]
    fn can_configure_loopback() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let Ok((connection, handle, _)) = rtnetlink::new_connection() else {
                panic!("failed to create connection");
            };
            let this_netns = PathBuf::from("/proc/self/ns/net");
            tokio::spawn(connection);
            let spec = LoopbackSpecBuilder::default()
                .add_ipv4(Ipv4Addr::new(192, 168, 1, 1), 32)
                .add_ipv6(Ipv6Addr::new(0xdead, 0xbeef, 0, 0, 0, 0, 0, 0), 96)
                .build()
                .unwrap();
            let lo = Loopback::configure(this_netns.as_path(), spec);
            println!("lo: {lo:?}");
        });
    }
}
