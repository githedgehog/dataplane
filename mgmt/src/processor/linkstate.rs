// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Keep the router's view of the kernel's links current.
//!
//! The router used to apply each link event as it came, and drop any event for an interface its
//! configuration did not name yet. An event lost that way was lost for good: the kernel does not
//! repeat itself. That is how a tap given its port's MAC while the first configuration was being
//! built kept its random MAC in the router (githedgehog/fabricator#2268), and events the monitor's
//! subscribers fell behind on were lost the same way.
//!
//! Here a link event is only a cue to look again. Each one leads to a complete observation of the
//! kernel's links, which the router takes in place of the last. The router's view is then as new as
//! the latest observation, and the latest observation is taken after the latest change, however the
//! changes were reported or interleaved with configurations.

use interface_manager::interface::TryFromLinkMessage;
use interface_manager::monitor::{EthEvent, InterfaceMonitor};

use clock::Duration;
use concurrency::sync::Arc;
use futures::TryStreamExt;
use net::interface::Interface;
use routing::{LinkState, LinkStates, RouterCtlSender};
use tokio::sync::broadcast;
use tokio::sync::broadcast::error::{RecvError, TryRecvError};
use tracing::{debug, error, warn};

/// How long to wait before observing again after an observation failed.
const RETRY: Duration = Duration::from_millis(100);

/// Observe all of the kernel's links.
///
/// A link that cannot be modeled (for instance, the loopback) is left out, as the
/// [`VpcManager`](crate::vpc_manager::VpcManager) leaves it out of its own observations. The router
/// keeps the configuration's view of such an interface.
async fn observe(handle: &rtnetlink::Handle) -> Result<LinkStates, rtnetlink::Error> {
    let mut messages = handle.link().get().execute();
    let mut links = vec![];
    while let Some(message) = messages.try_next().await? {
        match Interface::try_from_link_message(&message) {
            Ok(interface) => links.push(LinkState::from(&interface)),
            Err(e) => debug!("Not observing link {}: {e}", message.header.index),
        }
    }
    Ok(links.into_iter().collect())
}

/// Hand the router a fresh observation of the kernel's links whenever they change.
///
/// `changes` must be subscribed to `monitor` before the monitor starts, so that no change can come
/// between the first observation and the watch for the next.
pub(crate) async fn sync_link_state(
    monitor: Arc<InterfaceMonitor>,
    mut changes: broadcast::Receiver<EthEvent>,
    router: RouterCtlSender,
) {
    let (connection, handle, _) = match rtnetlink::new_connection() {
        Ok(connection) => connection,
        Err(e) => {
            error!("Failed to open a netlink connection to observe links: {e}");
            return;
        }
    };
    tokio::spawn(connection);

    // watch first, then look: a change after this point is a cue for another observation
    monitor.wait_ready().await;
    loop {
        match observe(&handle).await {
            Ok(links) => {
                debug!("Observed the state of {} links", links.len());
                if router.send_link_state(links).await.is_err() {
                    warn!("Failed to hand the router the state of the links");
                }
            }
            Err(e) => {
                error!("Failed to observe the kernel's links: {e}. Will try again.");
                tokio::time::sleep(RETRY).await;
                continue;
            }
        }

        // Wait for a change, then consume every other change already queued: the next observation
        // covers them all. Falling behind loses nothing either; it is just another change.
        match changes.recv().await {
            Ok(_) | Err(RecvError::Lagged(_)) => {}
            Err(RecvError::Closed) => {
                warn!(
                    "Interface monitor channel was closed. The router's link state will go stale"
                );
                break;
            }
        }
        while let Ok(_) | Err(TryRecvError::Lagged(_)) = changes.try_recv() {}
    }
}
