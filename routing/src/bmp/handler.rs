// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use async_trait::async_trait;
use netgauze_bmp_pkt::BmpMessage;

#[async_trait]
pub trait BmpHandler: Send + Sync + 'static {
    /// Called for every well-formed BMP message.
    async fn on_message(&self, peer: std::net::SocketAddr, msg: BmpMessage);

    /// Called when a connection terminates (EOF / error).
    async fn on_disconnect(&self, peer: std::net::SocketAddr, reason: &str) {
        let _ = (peer, reason); // no-op
    }
}

pub struct JsonLogHandler;

#[async_trait::async_trait]
impl BmpHandler for JsonLogHandler {
    async fn on_message(&self, peer: std::net::SocketAddr, msg: BmpMessage) {
        // BmpMessage implements serde, so this is safe:
        match serde_json::to_string(&msg) {
            Ok(line) => println!(r#"{{"peer":"{}","bmp":{}}}"#, peer, line),
            Err(e) => eprintln!("serialize error from {}: {e}", peer),
        }
    }
}
