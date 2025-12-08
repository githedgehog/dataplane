// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

pub mod bmp_render;
pub mod handler;
pub mod server;

pub use handler::BmpHandler;
pub use server::{BmpServer, BmpServerConfig};

use concurrency::sync::{Arc, RwLock};
use config::internal::status::DataplaneStatus;
use netgauze_bmp_pkt::BmpMessage;
use tokio::task::JoinHandle;
use tracing::info;

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
        // Your `concurrency::sync::RwLock` returns Result<Guard, PoisonError> like std::
        let mut guard = self
            .dp_status
            .write()
            .expect("dataplane status lock poisoned");
        bmp_render::handle_bmp_message(&mut *guard, &msg);
    }
}

/// Spawn BMP server in background
pub fn spawn_background(
    bind: std::net::SocketAddr,
    dp_status: Arc<RwLock<DataplaneStatus>>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        info!("starting BMP server on {}", bind);
        let cfg = BmpServerConfig {
            bind_addr: bind,
            ..Default::default()
        };
        let srv = BmpServer::new(cfg, StatusHandler::new(dp_status));
        if let Err(e) = srv.run().await {
            tracing::error!("bmp server terminated: {e:#}");
        }
    })
}
