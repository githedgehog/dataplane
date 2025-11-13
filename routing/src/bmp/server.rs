// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use anyhow::{Context, Result};
use bytes::BytesMut;
use netgauze_bmp_pkt::codec::BmpCodec;
use netgauze_bmp_pkt::BmpMessage;
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinSet;
use tokio_util::codec::FramedRead;

use crate::bmp::handler::BmpHandler;

#[derive(Clone, Debug)]
pub struct BmpServerConfig {
    pub bind_addr: std::net::SocketAddr,
    pub tcp_nodelay: bool,
    pub tcp_recv_buf: Option<usize>,
    pub max_conns: Option<usize>,
}

impl Default for BmpServerConfig {
    fn default() -> Self {
        Self {
            bind_addr: "0.0.0.0:5000".parse().unwrap(),
            tcp_nodelay: true,
            tcp_recv_buf: Some(1 << 20), // 1 MiB
            max_conns: None,
        }
    }
}

pub struct BmpServer<H: BmpHandler> {
    cfg: BmpServerConfig,
    handler: H,
}

impl<H: BmpHandler> BmpServer<H> {
    pub fn new(cfg: BmpServerConfig, handler: H) -> Self {
        Self { cfg, handler }
    }

    pub async fn run(self) -> Result<()> {
        let listener = TcpListener::bind(self.cfg.bind_addr)
            .await
            .with_context(|| format!("bind {}", self.cfg.bind_addr))?;
        tracing::info!("BMP server listening on {}", self.cfg.bind_addr);

        let mut tasks = JoinSet::new();
        let mut active = 0usize;

        loop {
            let (sock, peer) = listener.accept().await?;
            if let Some(cap) = self.cfg.max_conns {
                if active >= cap {
                    tracing::warn!("rejecting {} (max_conns reached)", peer);
                    continue;
                }
            }
            active += 1;
            let cfg = self.cfg.clone();
            let handler = &self.handler;
            let handler = handler; // capture by move below
            tasks.spawn(handle_peer(sock, peer, cfg, handler));
            // Periodically reap finished tasks
            while let Some(ready) = tasks.try_join_next()? {
                ready?;
                active = active.saturating_sub(1);
            }
        }
    }
}

async fn handle_peer<H: BmpHandler>(
    mut sock: TcpStream,
    peer: std::net::SocketAddr,
    cfg: BmpServerConfig,
    handler: &H,
) -> Result<()> {
    if cfg.tcp_nodelay {
        let _ = sock.set_nodelay(true);
    }
    if let Some(sz) = cfg.tcp_recv_buf {
        let _ = sock.set_recv_buffer_size(sz);
    }

    // Framed BMP stream using NetGauze’s codec
    let codec = BmpCodec::default();
    let reader = FramedRead::new(sock, codec);

    tokio::pin!(reader);

    // Use a scratch buffer for zero-copy clones if needed
    let mut _scratch = BytesMut::new();

    use futures_util::StreamExt;
    let mut reader = reader;
    while let Some(frame) = reader.next().await {
        match frame {
            Ok(BmpMessage::V3(msg)) => {
                handler.on_message(peer, BmpMessage::V3(msg)).await;
            }
            Ok(BmpMessage::V4(msg)) => {
                handler.on_message(peer, BmpMessage::V4(msg)).await;
            }
            Err(e) => {
                handler.on_disconnect(peer, &format!("decode error: {e}")).await;
                return Ok(());
            }
        }
    }
    handler.on_disconnect(peer, "eof").await;
    Ok(())
}
