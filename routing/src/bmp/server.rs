// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Minimal BMP server built on NetGauze 0.8.0
//! - Frames a TCP stream with `BmpCodec`
//! - Yields `netgauze_bmp_pkt::BmpMessage` items
//! - Hands each item to a user-provided `BmpHandler`

use anyhow::{Context, Result};
use concurrency::sync::Arc;
use futures_util::StreamExt;
use netgauze_bmp_pkt::BmpMessage;
use netgauze_bmp_pkt::codec::BmpCodec;
use std::net::SocketAddr;
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinSet;
use tokio_util::codec::FramedRead;

use tracing::debug;
use crate::bmp::handler::BmpHandler;

#[derive(Clone, Debug)]
pub struct BmpServerConfig {
    pub bind_addr: SocketAddr,
    pub tcp_nodelay: bool,
    /// Reserved for future tuning (no stable API to set TCP recv buf on Tokio stream).
    pub tcp_recv_buf: Option<usize>,
    /// Optional cap on simultaneously active peers.
    pub max_conns: Option<usize>,
}

impl Default for BmpServerConfig {
    fn default() -> Self {
        Self {
            bind_addr: "0.0.0.0:5000".parse().unwrap(),
            tcp_nodelay: true,
            tcp_recv_buf: Some(1 << 20),
            max_conns: None,
        }
    }
}

pub struct BmpServer<H: BmpHandler> {
    cfg: BmpServerConfig,
    handler: Arc<H>,
}

impl<H: BmpHandler> BmpServer<H> {
    pub fn new(cfg: BmpServerConfig, handler: H) -> Self {
        Self {
            cfg,
            handler: Arc::new(handler),
        }
    }

    pub async fn run(self) -> Result<()> {
        let listener = TcpListener::bind(self.cfg.bind_addr)
            .await
            .with_context(|| format!("bind {}", self.cfg.bind_addr))?;
        tracing::info!("BMP server listening on {}", self.cfg.bind_addr);

        let mut tasks: JoinSet<Result<()>> = JoinSet::new();
        let mut active: usize = 0;

        loop {
            let (sock, peer) = listener.accept().await?;
            if let Some(cap) = self.cfg.max_conns {
                if active >= cap {
                    tracing::warn!("rejecting {} (max_conns reached)", peer);
                    continue;
                }
            }

            active = active.saturating_add(1);
            let cfg = self.cfg.clone();
            let handler = Arc::clone(&self.handler);

            tasks.spawn(async move { handle_peer(sock, peer, cfg, handler).await });

            // Reap finished connections (non-blocking)
            while let Some(joined) = tasks.try_join_next() {
                match joined {
                    Ok(Ok(())) => active = active.saturating_sub(1),
                    Ok(Err(e)) => {
                        active = active.saturating_sub(1);
                        tracing::warn!("bmp task error: {e:#}");
                    }
                    Err(e) => {
                        active = active.saturating_sub(1);
                        tracing::warn!("bmp task join error: {e:#}");
                    }
                }
            }
        }
    }
}

async fn handle_peer<H: BmpHandler>(
    sock: TcpStream,
    peer: SocketAddr,
    cfg: BmpServerConfig,
    handler: Arc<H>,
) -> Result<()> {
    if cfg.tcp_nodelay {
        let _ = sock.set_nodelay(true);
    }
    // Frame the stream as BMP
    let codec = BmpCodec::default();
    let mut reader = FramedRead::new(sock, codec);

    while let Some(frame) = reader.next().await {
        match frame {
            Ok(msg) => {
                debug!("BMP: received message from {}: {:?}", peer, msg);
                // netgauze_bmp_pkt::BmpMessage for both v3 and v4. TODO: smatov: v4 handling
                handler.on_message(peer, msg).await;
            }
            Err(e) => {
                handler
                    .on_disconnect(peer, &format!("decode error: {e:?}"))
                    .await;
                return Ok(());
            }
        }
    }

    handler.on_disconnect(peer, "eof").await;
    Ok(())
}
