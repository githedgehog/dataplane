// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

pub mod bmp_render;
pub mod handler;
pub mod server;

use crate::RouterCtlSender;
pub use server::{BmpServer, BmpServerConfig};

use concurrency::sync::Arc;
use config::internal::status::DataplaneStatus;
use lifecycle::Subsystem;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tracing::{error, info};

use tracectl::trace_target;
trace_target!("bmp", LevelFilter::INFO, &[]);

/// Spawn the BMP server on `handle`, tracked under `mgmt` so it drains
/// with the rest of mgmt's tasks.
#[must_use]
pub fn spawn_bmp_server(
    mgmt: &Subsystem,
    handle: &tokio::runtime::Handle,
    bind: std::net::SocketAddr,
    dp_status: Arc<RwLock<DataplaneStatus>>,
    rtr_ctl: RouterCtlSender,
) -> JoinHandle<()> {
    let cancel = mgmt.cancel_token();
    let fut = async move {
        info!("starting BMP server on {}", bind);
        let cfg = BmpServerConfig {
            bind_addr: bind,
            ..Default::default()
        };
        let srv = BmpServer::new(cfg, handler::StatusHandler::new(dp_status, rtr_ctl));
        tokio::select! {
            () = cancel.cancelled() => {
                info!("BMP server shutdown requested");
            }
            res = srv.run() => {
                if let Err(e) = res {
                    error!("bmp server terminated: {e:#}");
                }
            }
        }
    };
    mgmt.spawn_on(fut, handle)
}
