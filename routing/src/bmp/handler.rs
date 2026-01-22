// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use async_trait::async_trait;
use concurrency::sync::Arc;
use config::internal::status::DataplaneStatus;
use netgauze_bmp_pkt::BmpMessage;
use tokio::sync::RwLock;
use tracing::debug;

use crate::bmp::bmp_render;

#[async_trait]
pub trait BmpHandler: Send + Sync + 'static {
    /// Called for every well-formed BMP message.
    async fn on_message(&self, peer: std::net::SocketAddr, msg: BmpMessage);

    /// Called when a connection terminates (EOF / error).
    async fn on_disconnect(&self, _peer: std::net::SocketAddr, _reason: &str) {
        debug!("BMP: connection to {} disconnected", _peer);
    }
}

/// Background BMP handler that updates shared dataplane status.
pub struct StatusHandler {
    dp_status: Arc<RwLock<DataplaneStatus>>,
}

impl StatusHandler {
    #[must_use]
    pub fn new(dp_status: Arc<RwLock<DataplaneStatus>>) -> Self {
        Self { dp_status }
    }
}

#[async_trait]
impl BmpHandler for StatusHandler {
    async fn on_message(&self, _peer: std::net::SocketAddr, msg: BmpMessage) {
        {
            let mut guard = self.dp_status.write().await;
            bmp_render::handle_bmp_message(&mut guard, &msg);
        }
        debug!("BMP: released dataplane status write guard after handling message");
    }
}
