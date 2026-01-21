// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

pub mod bmp_render;
pub mod handler;
pub mod server;

pub use server::{BmpServer, BmpServerConfig};

use concurrency::sync::{Arc, RwLock};
use config::internal::status::DataplaneStatus;
use netgauze_bmp_pkt::BmpMessage;
use tokio::task::JoinHandle;
use tracing::{debug, error, info};

/// Background BMP server runner that updates shared dataplane status.
pub struct StatusHandler {
    dp_status: Arc<RwLock<DataplaneStatus>>,
}

impl StatusHandler {
    pub fn new(dp_status: Arc<RwLock<DataplaneStatus>>) -> Self {
        Self { dp_status }
    }
}

#[async_trait::async_trait]
impl handler::BmpHandler for StatusHandler {
    async fn on_message(&self, _peer: std::net::SocketAddr, msg: BmpMessage) {
        {
            let mut guard = self
                .dp_status
                .write()
                .expect("dataplane status lock poisoned");
            bmp_render::handle_bmp_message(&mut guard, &msg);
        }
        debug!("BMP: released dataplane status write guard after handling message");
    }
}

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
        let srv = BmpServer::new(cfg, StatusHandler::new(dp_status));
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
