// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use async_trait::async_trait;
use netgauze_bmp_pkt::BmpMessage;

#[async_trait]
pub trait BmpHandler: Send + Sync + 'static {
    /// Called for every well-formed BMP message.
    async fn on_message(&self, peer: std::net::SocketAddr, msg: BmpMessage);

    /// Called when a connection terminates (EOF / error).
    async fn on_disconnect(&self, _peer: std::net::SocketAddr, _reason: &str) {
        // no-op
    }
}
