// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//!   BMP server built on `NetGauze` 0.8.0
//! - Reads a TCP stream into a `BytesMut`
//! - Decodes BMP frames using `BmpCodec`
//! - On decode error: discards one BMP frame (best-effort resync) and continues
//!   so FRR doesn't see "connection reset by peer".

use anyhow::{Context, Result};
use bytes::{Buf, BytesMut};
use concurrency::sync::Arc;
use netgauze_bmp_pkt::codec::BmpCodec;
use std::net::SocketAddr;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinSet;
use tokio_util::codec::Decoder;
use tracing::{debug, info, warn};

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
    #[must_use]
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
        info!("BMP server listening on {}", self.cfg.bind_addr);

        let mut tasks: JoinSet<Result<()>> = JoinSet::new();
        let mut active: usize = 0;

        loop {
            let (sock, peer) = listener.accept().await?;
            if let Some(cap) = self.cfg.max_conns {
                if active >= cap {
                    warn!("rejecting {} (max_conns reached)", peer);
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
                        warn!("bmp task error: {e:#}");
                    }
                    Err(e) => {
                        active = active.saturating_sub(1);
                        warn!("bmp task join error: {e:#}");
                    }
                }
            }
        }
    }
}

/// BMP common header is:
/// - version: u8
/// - length:  u32 (network endian), total length INCLUDING the common header
const BMP_COMMON_HDR_LEN: usize = 1 + 4;

fn drop_one_bmp_frame_best_effort(buf: &mut BytesMut) {
    if buf.len() < BMP_COMMON_HDR_LEN {
        // Not enough data to know length; drop what we have to avoid infinite loop.
        buf.clear();
        return;
    }

    // buf[0] = version
    let len = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;

    if len < BMP_COMMON_HDR_LEN {
        // Bogus length; drop one byte and try to resync.
        buf.advance(1);
        return;
    }

    if buf.len() >= len {
        // Drop exactly one frame.
        buf.advance(len);
    } else {
        // We don't have full frame yet; keep buffer and wait for more bytes.
        // But to avoid looping forever on the same error without progress, drop 1 byte.
        buf.advance(1);
    }
}

async fn handle_peer<H: BmpHandler>(
    mut sock: TcpStream,
    peer: SocketAddr,
    cfg: BmpServerConfig,
    handler: Arc<H>,
) -> Result<()> {
    if cfg.tcp_nodelay {
        if let Err(e) = sock.set_nodelay(true) {
            warn!("BMP: could not set TCP_NODELAY for {}: {}", peer, e);
        }
    }

    // Buffer for stream and codec for BMP framing/parsing
    let mut buf = BytesMut::with_capacity(cfg.tcp_recv_buf.unwrap_or(1 << 20));
    let mut codec = BmpCodec::default();

    loop {
        // Read more bytes from TCP
        let n = sock
            .read_buf(&mut buf)
            .await
            .with_context(|| format!("read from {peer}"))?;

        if n == 0 {
            handler.on_disconnect(peer, "eof").await;
            return Ok(());
        }

        // Drain as many BMP messages as possible from current buffer
        loop {
            match codec.decode(&mut buf) {
                Ok(Some(msg)) => {
                    debug!("BMP: received message from {}: {:?}", peer, msg);
                    handler.on_message(peer, msg).await;
                }
                Ok(None) => {
                    // Need more bytes
                    break;
                }
                Err(e) => {
                    // IMPORTANT: do not drop the TCP connection.
                    // Log + best-effort resync by discarding a frame.
                    debug!(
                        "BMP decode error from {}: {:?} (dropping one BMP frame and continuing)",
                        peer, e
                    );
                    drop_one_bmp_frame_best_effort(&mut buf);
                    // continue loop and try decoding again
                }
            }
        }
    }
}
