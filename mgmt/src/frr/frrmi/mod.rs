// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

// FRRMI: FRR management interface

#![cfg(unix)]
use bytes::Buf;
use bytes::BytesMut;

use tokio::io::{AsyncWriteExt, ErrorKind};
use tokio::net::UnixStream;
use tokio::time::{Duration, timeout};

use std::io::Cursor;
use std::path::Path;
use std::str;
use std::str::from_utf8;
use thiserror::Error;
#[allow(unused)]
use tracing::{debug, error, info, warn};

use crate::frr::renderer::builder::ConfigBuilder;
use crate::models::external::gwconfig::GenId;

#[derive(Error, Debug)]
pub enum FrrErr {
    #[error("Failed to connect FrrMi: {0}")]
    ConnectFailed(&'static str),

    #[error("No connection to frr-agent exists")]
    NotConnected,

    #[error("Timeout: did not receive response in time")]
    TimeOut,

    #[error("Peer left")]
    PeerLeft,

    #[error("Receive failure {0}")]
    RxFail(String),

    #[error("Send failure {0}")]
    TxFail(String),

    #[error("Reloading error: {0}")]
    ReloadErr(String),

    #[error("Decoding error")]
    DecodeError(&'static str),
}

/// Connect to the specified remote path and provide a [`UnixStream`] socket.
/// Will fail if connection does not succeed in the indicated timeout specified as a [`Duration`].
pub async fn connect_sock_stream<P: AsRef<Path> + ?Sized + std::fmt::Display>(
    remote: &P,
    tout: Duration,
) -> Result<UnixStream, FrrErr> {
    debug!("Connecting to frr-agent at {}...", remote);
    let sock = timeout(tout, UnixStream::connect(remote))
        .await
        .map_err(|_| FrrErr::TimeOut)?
        .map_err(|_| {
            error!("Failed to connect to {}", remote);
            FrrErr::ConnectFailed("Failed to connect")
        })?;
    debug!("Connected to {}", remote);
    Ok(sock)
}

/// Receive **EXACTLY** len octets of data over the specified [`UnixStream`] socket
async fn do_recv(sock: &mut UnixStream, len: usize) -> Result<Vec<u8>, FrrErr> {
    let mut data = BytesMut::with_capacity(len);
    let mut chunk_buffer = vec![0u8; len];
    while data.len() < len {
        sock.readable()
            .await
            .map_err(|e| FrrErr::RxFail(e.to_string()))?;
        match sock.try_read(&mut chunk_buffer) {
            Ok(0) => return Err(FrrErr::PeerLeft),
            Ok(n) => data.extend_from_slice(&chunk_buffer[..n]),
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                continue;
            }
            Err(e) => return Err(FrrErr::RxFail(e.to_string())),
        };
    }
    Ok(data.into())
}

/// Receive a message made of |length|genid|data. This applies to both requests and responses.
async fn receive_msg(sock: &mut UnixStream) -> Result<(GenId, String), FrrErr> {
    /* data length as 8 octets*/
    let len_buf = do_recv(sock, 8).await?;
    let len_buf: [u8; 8] = len_buf
        .try_into()
        .map_err(|_| FrrErr::DecodeError("Error decoding msg length"))?;
    let msg_len = u64::from_ne_bytes(len_buf) as usize;

    /* genid */
    let genid_buf = do_recv(sock, 8).await?;
    let genid_buf: [u8; 8] = genid_buf
        .try_into()
        .map_err(|_| FrrErr::DecodeError("Error decoding genid"))?;
    let genid = i64::from_ne_bytes(genid_buf) as GenId;

    /* data with length msg_len */
    let buf = do_recv(sock, msg_len).await?;
    let message = from_utf8(&buf).map_err(|_| FrrErr::DecodeError("Error decoding message"))?;
    debug!("Got message with {msg_len} octets for genid {genid}");
    Ok((genid, message.to_string()))
}

/// Receive a (response) message over the [`FrrMi`] with the provided timeout.
/// Fails if no **COMPLETE** message is received in the indicated timeout.
async fn receive_msg_timed(
    sock: &mut UnixStream,
    tout: Duration,
) -> Result<(GenId, String), FrrErr> {
    timeout(tout, receive_msg(sock)).await.map_err(|_| {
        let peer = sock.peer_addr();
        error!("No response from agent at {peer:?} in {tout:?}");
        FrrErr::TimeOut
    })?
}

/// Send a buffer over the provided [`UnixStream`]
async fn send_buf(sock: &mut UnixStream, buf: &[u8]) -> Result<(), FrrErr> {
    let mut cursor = Cursor::new(buf);
    while cursor.has_remaining() {
        sock.write_buf(&mut cursor).await.map_err(|e| {
            error!("Failed to send buffer: {e}");
            FrrErr::TxFail(e.to_string())
        })?;
    }
    Ok(())
}

/// Send a message over the provided [`UnixStream`]. Messages are structured as
///    |length(8)|genid(8)|data(variable)|
/// where the numbers indicate the number of octets.
async fn send_msg(sock: &mut UnixStream, genid: GenId, msg: &[u8]) -> Result<(), FrrErr> {
    /* length of data */
    let length = msg.len() as u64;

    debug!("Sending message. Genid: {genid} size: {length}");

    /* assemble wire message: |length|genid|data| */
    let mut wire_msg = BytesMut::with_capacity(msg.len() + 16);
    wire_msg.extend_from_slice(&length.to_ne_bytes());
    wire_msg.extend_from_slice(&genid.to_ne_bytes());
    wire_msg.extend_from_slice(msg);

    /* send wire message */
    send_buf(sock, &wire_msg).await?;
    debug!("Successfully sent msg. data-len: {length} genid: {genid}");
    Ok(())
}

pub struct FrrMi {
    sock: Option<UnixStream>,
    remote: String,
    timeout: Duration,
}
impl FrrMi {
    const FRRMI_TIMEOUT: u64 = 10;

    /// Create an frrmi to talk to an frr-agent.
    pub async fn new(remote_addr: &str) -> Result<FrrMi, FrrErr> {
        let mut frrmi = Self {
            sock: None,
            remote: remote_addr.to_string(),
            timeout: Duration::from_secs(Self::FRRMI_TIMEOUT),
        };
        let _ = frrmi.connect().await;
        if frrmi.is_connected() {
            let _ = frrmi.probe().await;
            if !frrmi.is_connected() {
                warn!("Frrmi is NOT connected to agent");
            }
        }
        info!(
            "Created frrmi. remote: {} connected: {}",
            &frrmi.remote,
            frrmi.is_connected(),
        );
        Ok(frrmi)
    }
    pub async fn connect(&mut self) -> Result<(), FrrErr> {
        let timeout = Duration::from_secs(Self::FRRMI_TIMEOUT);
        let stream = connect_sock_stream(&self.remote, timeout).await?;
        self.sock = Some(stream);
        Ok(())
    }
    pub fn is_connected(&self) -> bool {
        self.sock.is_some()
    }

    /// Probe the frr-agent with this [`FrrMi`] by sending a keepalive message
    pub async fn probe(&mut self) -> Result<(), FrrErr> {
        if !self.is_connected() {
            debug!("Frrmi is not connected to agent...");
            self.connect().await?;
        }
        debug!("Probing frr-agent...");
        self.send_receive(0, "KEEPALIVE").await
    }

    /// Receive a response
    async fn receive_response(&mut self) -> Result<(), FrrErr> {
        debug!("Awaiting reply from frr-agent at {}...", self.remote);
        if let Some(stream) = &mut self.sock {
            let (genid, response) = receive_msg_timed(stream, self.timeout).await?;
            debug!(
                "Got response from frr-agent at {} for genid {genid}: {response}",
                self.remote
            );
            match response.as_str() {
                "Ok" => Ok(()),
                _ => Err(FrrErr::ReloadErr(response)),
            }
        } else {
            Err(FrrErr::NotConnected)
        }
    }

    /// Send a message over this [`FrrMi`], such as a config or a keepalive and receive the response.
    /// Returns error if message could not be sent, or the response could not
    /// be received, or a response was received but it was not "Ok"
    async fn send_receive(&mut self, genid: GenId, msg: &str) -> Result<(), FrrErr> {
        if !self.is_connected() {
            debug!("Frmmi is not connected to agent...");
            self.connect().await?;
        }

        if let Some(sock) = &mut self.sock {
            /* send the request: if sending fails, we may disconnect */
            #[allow(clippy::collapsible_if)]
            if let Err(e) = send_msg(sock, genid, msg.as_bytes()).await {
                if matches!(e, FrrErr::PeerLeft | FrrErr::RxFail(_) | FrrErr::TxFail(_)) {
                    warn!("Got error: {e}. Disconnecting frrmi...");
                    let _ = sock.shutdown().await;
                    self.sock.take();
                    return Err(e);
                }
            }
            /* we could send the request: receive the response */
            self.receive_response().await
        } else {
            unreachable!()
        }
    }

    /// Apply the config in FRR represented by [`ConfigBuilder`] using this [`FrrMi`]
    pub async fn apply_config(
        &mut self,
        genid: GenId,
        config: &ConfigBuilder,
    ) -> Result<(), FrrErr> {
        info!("Applying FRR config. Genid={genid} agent={}", &self.remote);
        let conf_str = config.to_string();
        if let Err(e) = self.send_receive(genid, &conf_str).await {
            error!("Failed to apply config for gen {genid}: {e}");
            Err(e)
        } else {
            info!("Successfully applied config for gen {genid} in FRR");
            Ok(())
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::frr::renderer::builder::Render;
    use crate::models::external::gwconfig::GwConfig;
    use crate::processor::tests::test::sample_external_config;
    use tokio::fs;
    use tokio::net::UnixListener;
    use tokio::task::JoinHandle;
    use tracing_test::traced_test;

    /// Create a fake frr-agent async task for testing.
    /// The agent can be stopped by calling abort() on the returned handle.
    pub async fn fake_frr_agent(agent_address: &str) -> JoinHandle<()> {
        debug!("Starting fake frr-agent at {agent_address}...");

        /* remove stale entries in FS and create new */
        let _ = std::fs::remove_file(agent_address);
        let bind_path = Path::new(agent_address);
        if let Some(parent_dir) = bind_path.parent() {
            debug!("Creating directory at {parent_dir:?}...");
            fs::create_dir_all(parent_dir).await.unwrap();
        }
        let listener = UnixListener::bind(bind_path).unwrap();

        /* spawn */
        let task = tokio::spawn(async move {
            debug!("frr-agent will accept connections now");
            let (mut sock, peer) = listener.accept().await.unwrap();
            debug!("frr-agent got connection from {peer:?}");
            loop {
                let (genid, request) = receive_msg(&mut sock).await.unwrap();
                debug!("frr-agent got request:\n{request}");
                send_msg(&mut sock, genid, "Ok".to_string().as_bytes())
                    .await
                    .unwrap();
            }
        });
        debug!("Spawned fake frr-agent");
        task
    }

    #[tokio::test(flavor = "multi_thread")]
    #[traced_test]
    async fn test_frrmi() {
        /* build some sample config */
        let external = sample_external_config();
        let mut config = GwConfig::new(external);
        config.validate().expect("Validation should succeed");
        config.build_internal_config().expect("Should succeed");
        let rendered = config.internal.as_ref().unwrap().render(&config);

        /* start faked frr-agent */
        let frr_agent = fake_frr_agent("/tmp/frrmi-test/frr-agent.sock").await;

        /* open frrmi */
        let mut frrmi = FrrMi::new("/tmp/frrmi-test/frr-agent.sock").await.unwrap();

        /* apply config over frrmi */
        if let Err(e) = frrmi.apply_config(config.genid(), &rendered).await {
            error!("Failed to apply config: {e:?}");
        } else {
            info!("Successfully applied config");
        }

        /* stop fake frr-agent */
        frr_agent.abort();
    }
}
