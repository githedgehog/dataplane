// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Module to resolve ARP from the /proc. This module only supports ARP (IPv4)

use concurrency::sync::Arc;
use concurrency::sync::atomic::{AtomicBool, Ordering};
use concurrency::thread;
use concurrency::thread::JoinHandle;
use std::net::IpAddr;
use std::time::Duration;

use netdev::Interface;
use netdev::get_interfaces;
use procfs::net::arp;

use super::adjacency::Adjacency;
use super::atablerw::AtableReader;
use crate::atable::atablerw::AtableWriter;
use net::eth::mac::Mac;
use net::interface::{InterfaceIndex, InterfaceIndexError};
use tracing::{debug, error, warn};

/// Util that returns the ifindex of the interface with the given name out of the slice of
/// interfaces provided as argument.
fn get_interface_ifindex(
    interfaces: &[Interface],
    name: &str,
) -> Result<Option<InterfaceIndex>, InterfaceIndexError> {
    interfaces
        .iter()
        .find_map(|interface| {
            if interface.name == name {
                Some(InterfaceIndex::try_new(interface.index))
            } else {
                None
            }
        })
        .transpose()
}

/// An object able to resolve ARP entries and update the adjacency table. The [`AtResolver`]
/// object can be started / stopped and provides read access to an adjacency table via an
/// [`AtableReader`] object.
pub struct AtResolver {
    run: Arc<AtomicBool>,
    handle: Option<JoinHandle<AtableWriter>>,
    atablew: Option<AtableWriter>,
    atabler: AtableReader,
}

impl AtResolver {
    /// Create an ARP table resolver. Returns an [`AtResolver`] object
    /// and an adjacency table reader [`AtableReader`]
    #[must_use]
    pub fn new(run: bool) -> (Self, AtableReader) {
        let (atablew, atabler) = AtableWriter::new();
        let resolver = Self {
            run: Arc::new(AtomicBool::new(run)),
            handle: None,
            atablew: Some(atablew),
            atabler: atabler.clone(),
        };
        (resolver, atabler)
    }

    /// Start the adjacency resolver
    pub fn start(&mut self, poll_period: u64) {
        self.run.store(true, Ordering::Relaxed);
        let Some(mut atablew) = self.atablew.take() else {
            error!("Fatal: can't start resolver; no table accessor");
            return;
        };

        let run = self.run.clone();
        let handle = thread::spawn(move || {
            while run.load(Ordering::Relaxed) {
                AtResolver::refresh_atable_from_proc(&mut atablew);
                thread::sleep(Duration::from_secs(poll_period));
            }
            atablew
        });
        self.handle = Some(handle);
    }

    /// Stop the adjacency resolver
    pub fn stop(&mut self) {
        let handle = self.handle.take();
        if let Some(handle) = handle {
            debug!("Stopping adjacency resolver...");
            self.run.store(false, Ordering::Relaxed);
            if let Ok(w) = handle.join() {
                self.atablew = Some(w);
            }
        }
    }

    /// Get an adjacency table reader from this resolver
    #[must_use]
    pub fn get_reader(&self) -> AtableReader {
        self.atabler.clone()
    }

    /// Loads arp table from /proc and the kernel interfaces and
    /// uses the adjacency table writer to update the adjacency table
    /// associated with the [`AtableWriter`].
    fn refresh_atable_from_proc(atablew: &mut AtableWriter) {
        // load kernel interface information
        let interfaces = get_interfaces();

        // Collect arp entries by loading arp table from /proc and using the
        // interfaces vector just retrieved to resolve interface name to ifindex.
        // Todo: interface name resolution could alternatively be done with ifname_to_index
        // using the libc wrappers.
        if let Ok(arptable) = arp() {
            let adjs = arptable.iter().filter_map(|entry| {
                if let Some(mac) = entry.hw_address {
                    match get_interface_ifindex(&interfaces, &entry.device) {
                        Ok(Some(ifindex)) => {
                            let adj = Adjacency::new(
                                IpAddr::V4(entry.ip_address),
                                ifindex,
                                Mac::from(mac),
                            );
                            Some(adj)
                        }
                        Ok(None) => {
                            warn!("Unable to find Ifindex of {0}", entry.device);
                            None
                        }
                        Err(e) => {
                            error!("error refreshing ARP/ND table: {e}");
                            None
                        }
                    }
                } else {
                    None
                }
            });

            /* clear the table and add the known entries */
            atablew.clear(false);
            adjs.into_iter()
                .map(|adj| atablew.add_adjacency(adj, false))
                .count();
            atablew.publish();
        }
    }
}

/// Properties over the one part of the resolver that does not need `/proc`.
///
/// `refresh_atable_from_proc` reads the kernel's ARP table and its interface list, so it cannot be
/// driven from a test. What can is the step between them: resolving the device name an ARP entry
/// carries to an interface index. Every ARP entry the kernel reports goes through it, and an entry
/// it cannot resolve is dropped -- so getting it wrong loses adjacencies silently.
#[cfg(test)]
mod resolver_properties {
    use super::*;
    use netdev::Interface;

    fn interface(index: u32, name: &str) -> Interface {
        Interface {
            index,
            name: name.to_string(),
            ..Interface::dummy()
        }
    }

    /// A device name resolves to the index of the interface that has it, and to nothing otherwise.
    #[test]
    fn a_device_name_resolves_to_its_own_interface() {
        let interfaces = [interface(2, "eth0"), interface(3, "eth1")];

        for (index, name) in [(2, "eth0"), (3, "eth1")] {
            let found = get_interface_ifindex(&interfaces, name)
                .unwrap_or_else(|e| unreachable!("{e}"))
                .unwrap_or_else(|| panic!("{name} did not resolve"));
            assert_eq!(found.to_u32(), index, "{name} resolved to the wrong index");
        }

        assert_eq!(
            get_interface_ifindex(&interfaces, "eth2").unwrap_or_else(|e| unreachable!("{e}")),
            None,
            "an unknown device must resolve to nothing, not to something else"
        );
        assert_eq!(
            get_interface_ifindex(&[], "eth0").unwrap_or_else(|e| unreachable!("{e}")),
            None,
            "no interfaces, nothing to resolve to"
        );
    }

    /// An interface index of zero is refused rather than turned into an adjacency.
    ///
    /// `InterfaceIndex` is non-zero, and the kernel should never report a zero index -- but the
    /// resolver takes the number from outside, so the distinction between "no such device" and "a
    /// device whose index we cannot represent" has to survive: the first is `Ok(None)` and drops the
    /// entry quietly, the second is an error and says why.
    #[test]
    fn an_interface_index_of_zero_is_an_error_not_a_miss() {
        let interfaces = [interface(0, "eth0")];
        assert!(
            get_interface_ifindex(&interfaces, "eth0").is_err(),
            "index zero must be an error"
        );
        assert_eq!(
            get_interface_ifindex(&interfaces, "eth1").unwrap_or_else(|e| unreachable!("{e}")),
            None,
            "a different name is still just a miss"
        );
    }

    /// The first interface with a name wins, and a later one with the same name does not shadow it.
    #[test]
    fn a_repeated_device_name_resolves_to_the_first() {
        let interfaces = [interface(2, "eth0"), interface(9, "eth0")];
        let found = get_interface_ifindex(&interfaces, "eth0")
            .unwrap_or_else(|e| unreachable!("{e}"))
            .unwrap_or_else(|| unreachable!());
        assert_eq!(found.to_u32(), 2);
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::atable::atablerw::AtableReader;

    /// Prints the adjacency table behind a reader every second, the
    /// indicated number of times
    fn watch_resolver_output(atabler: &AtableReader, times: i32) {
        let mut count = 1;
        while count <= times {
            if let Some(atable) = atabler.enter() {
                println!("{}", *atable);
            }
            thread::sleep(Duration::from_secs(1));
            count += 1;
        }
    }

    #[test]
    #[cfg_attr(
        emulated,
        ignore = "reads /proc/net/arp and queries kernel interfaces, neither available under miri and not reliable under qemu"
    )]
    fn test_adjacency_resolver() {
        let (mut resolver, atabler) = AtResolver::new(true);
        resolver.start(1);
        watch_resolver_output(&atabler, 3);
        resolver.stop();

        println!("Stopped resolver");
        thread::sleep(Duration::from_secs(2));

        resolver.start(1);
        watch_resolver_output(&atabler, 3);
        resolver.stop();
    }
}
