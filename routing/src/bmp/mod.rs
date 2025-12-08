// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![allow(unused)]

pub mod bmp_render;
pub mod handler;
pub mod server;

use std::thread::{self, JoinHandle};

use args::BmpServerParams;
use handler::BmpHandler;
use server::{BmpServer, BmpServerConfig};
use tracing::{debug, error};

use concurrency::syn::{Arc, RwLock};
use config::internal::status::DataplaneStatus;

/// A BMP handler that updates `DataplaneStatus` via `bmp_render::hande_bmp_message`.
struct StatusUpdateHandler {
    dp: Arc<RwLock<DataplaneStatus>>,
}

#[async_trait::async_trait]
impl BmpHandler for StatusUpdateHandler {
    async fn on_message(&self, _peer: std::net::SocketAddr, msg: netgauze_bmp_pkt::BmpMessage) {
        if let Ok(mut guard) = self.dp.try_write() {
            bmp_render::hande_bmp_message(&mut *guard, &msg);
        } else {
            // non-blocking: skip if lock not immediately available
        }
    }

    async fn on_disconnect(&self, _peer: std::net::SocketAddr, _reason: &str) {
        // no-op
    }
}

/// Spawn BMP server in a dedicated thread with its own Tokio runtime.
/// Always uses `StatusUpdateHandler` to update `DataplaneStatus`.
pub fn spawn_background(
    params: &BmpServerParams,
    dp_status: Arc<RwLock<DataplaneStatus>>,
) -> JoinHandle<()> {
    let bind = params.bind;
    let stats_interval_ms = params.stats_interval_ms;

    thread::Builder::new()
        .name("bmp-server".to_string())
        .spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_io()
                .enable_time()
                .build()
                .expect("failed to build BMP tokio runtime");

            rt.block_on(async move {
                let cfg = BmpServerConfig {
                    bind_addr: bind,
                    ..Default::default()
                };

                debug!(
                    "BMP: starting StatusUpdateHandler on {bind}, interval={}ms",
                    stats_interval_ms
                );
                let handler = StatusUpdateHandler { dp: dp_status };
                let srv = BmpServer::new(cfg, handler);
                if let Err(e) = srv.run().await {
                    error!("BMP server exited with error: {e:#}");
                }
            });
        })
        .expect("failed to start bmp-server thread")
}
