// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

pub mod bmp_render;
pub mod handler;
pub mod server;

pub use server::{BmpServer, BmpServerConfig};

use concurrency::sync::Arc;
use config::internal::status::DataplaneStatus;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tracing::{error, info};

use tracectl::trace_target;
trace_target!("bmp", LevelFilter::INFO, &[]);

/// Spawn BMP server in background
pub fn spawn_background(
    bind: std::net::SocketAddr,
    dp_status: Arc<RwLock<DataplaneStatus>>,
) -> JoinHandle<()> {
    // The future we want to run
    let fut = async move {
        info!("starting BMP server on {}", bind);
        let cfg = BmpServerConfig {
            bind_addr: bind,
            ..Default::default()
        };
        let srv = BmpServer::new(cfg, handler::StatusHandler::new(dp_status));
        if let Err(e) = srv.run().await {
            error!("bmp server terminated: {e:#}");
        }
    };

    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        handle.spawn(fut)
    } else {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("failed to build Tokio runtime for BMP");
        let rt_static: &'static tokio::runtime::Runtime = Box::leak(Box::new(rt));
        rt_static.spawn(fut)
    }
}
