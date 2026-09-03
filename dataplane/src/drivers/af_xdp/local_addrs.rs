// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Keeping the XDP program's idea of "our own addresses" current.
//!
//! Redirecting a packet to an `AF_XDP` socket takes it away from the kernel for
//! good, so the XDP program has to know which traffic the host is expecting
//! before it decides. What it needs is the set of addresses the host answers
//! to, and that set is not fixed: the gateway's addresses arrive with its
//! configuration, well after the driver starts, and change with it afterwards.
//!
//! So the set is read from the kernel and handed to the program repeatedly.
//! Polling rather than following netlink is a deliberate trade: the cost is a
//! bounded delay before a new address stops being redirected away from the
//! host, and what it buys is that the program's view is rebuilt from what the
//! kernel actually holds every time, rather than accumulated from a stream of
//! events that a missed message would leave permanently wrong.

use std::net::IpAddr;

use concurrency::sync::Arc;
use concurrency::thread;
#[allow(unused_imports)] // used under loom/shuttle backends
use concurrency::thread::BuilderExt;
use lifecycle::{CancellationToken, Subsystem};
use tracing::{error, info};
use xdp::program::Redirect;

/// How often the host's addresses are read back and handed to the program.
///
/// Also the worst case for how long traffic to a newly configured address goes
/// to the dataplane instead of the host. A session that address is for will
/// retry well past this.
const REFRESH_PERIOD: std::time::Duration = std::time::Duration::from_secs(1);

/// Every address the host answers to, on any interface.
///
/// Not just the interfaces the driver serves: an address on a loopback or a
/// VRF device is the host's too, and a packet carrying it arrives on a real
/// interface all the same.
fn host_addresses() -> Vec<IpAddr> {
    let mut addresses: Vec<IpAddr> = netdev::get_interfaces()
        .iter()
        .flat_map(|interface| {
            interface
                .ipv4
                .iter()
                .map(|net| IpAddr::V4(net.addr()))
                .chain(interface.ipv6.iter().map(|net| IpAddr::V6(net.addr())))
        })
        .collect();
    addresses.sort_unstable();
    addresses.dedup();
    addresses
}

/// Hand the host's addresses to `redirect`, and keep doing so until the
/// subsystem is cancelled.
///
/// The first set is installed before this returns, so that no socket is bound
/// while the program still believes the host has no addresses of its own.
///
/// # Errors
///
/// Returns an error if the first set cannot be installed, or if the thread
/// that keeps them current cannot be spawned. A later refresh that fails is
/// reported and retried.
pub(super) fn track<'scope>(
    scope: &'scope thread::Scope<'scope, '_>,
    subsystem: &Subsystem,
    redirect: &Arc<Redirect>,
) -> Result<(), std::io::Error> {
    let mut installed = host_addresses();
    redirect.set_local_addresses(&installed)?;
    info!(
        "The host answers to {} address(es); traffic to them stays with the kernel",
        installed.len()
    );

    let cancel = subsystem.cancel_token();
    let redirect = redirect.clone();
    let builder = thread::Builder::new().name("af-xdp-local-addrs".to_string());

    builder.spawn_scoped(scope, move || {
        refresh_until_cancelled(&redirect, &mut installed, &cancel);
    })?;

    Ok(())
}

/// Re-read the host's addresses until cancelled, installing them when they
/// have changed.
fn refresh_until_cancelled(
    redirect: &Redirect,
    installed: &mut Vec<IpAddr>,
    cancel: &CancellationToken,
) {
    while !cancel.is_cancelled() {
        thread::sleep(REFRESH_PERIOD);

        let current = host_addresses();
        if current == *installed {
            continue;
        }

        match redirect.set_local_addresses(&current) {
            Ok(()) => {
                info!(
                    "The host answers to {} address(es) now, was {}",
                    current.len(),
                    installed.len()
                );
                *installed = current;
            }
            // Left unchanged so the next pass tries again rather than
            // believing something we failed to install.
            Err(e) => error!("Could not update the host's addresses: {e}"),
        }
    }
}
