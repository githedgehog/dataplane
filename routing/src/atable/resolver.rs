// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Module to resolve ARP from the /proc. This module only supports ARP (IPv4)

use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::thread::JoinHandle;
use std::time::Duration;

use netdev::Interface;
use netdev::get_interfaces;
use procfs::net::arp;

use crate::atable::atablerw::AtableWriter;
use net::eth::mac::Mac;
use tracing::{debug, error, warn};

use super::adjacency::Adjacency;
use super::atablerw::AtableReader;

/// Util that returns the ifindex of the interface with the given name out of the slice of
/// interfaces provided as argument.
fn get_interface_ifindex(interfaces: &[Interface], name: &str) -> Option<u32> {
    interfaces
        .iter()
        .position(|interface| interface.name == name)
        .map(|pos| interfaces[pos].index)
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
                    if let Some(ifindex) = get_interface_ifindex(&interfaces, &entry.device) {
                        let adj =
                            Adjacency::new(IpAddr::V4(entry.ip_address), ifindex, Mac::from(mac));
                        Some(adj)
                    } else {
                        warn!("Unable to find Ifindex of {0}", entry.device);
                        None
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
                println!("{}", *atable)
            }
            thread::sleep(Duration::from_secs(1));
            count += 1;
        }
    }

    #[test]
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
