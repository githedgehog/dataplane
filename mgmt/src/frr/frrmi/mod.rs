// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

// FRRMI: FRR management interface

use nix::sys::socket::{setsockopt, sockopt};
use std::str;
use tokio::time::{Duration, timeout};

use crate::frr::renderer::builder::ConfigBuilder;
use crate::models::external::gwconfig::GenId;

use std::fs;
use std::net::Shutdown;
use std::os::fd::BorrowedFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::AsRawFd;
use std::path::Path;
use thiserror::Error;
use tracing::{debug, error, info};

use tokio::net::UnixDatagram;

#[derive(Error, Debug)]
pub enum FrrErr {
    #[error("Failed to open FrrMi: {0}")]
    FailOpen(&'static str),

    #[error("No connection to frr-agent exists")]
    NotConnected,

    #[error("Frr-agent is down or unreachable")]
    FrrAgentDown,

    #[error("Failed to communicate with frr-agent: {0}")]
    FailCommFrrAgent(String),

    #[error("Timeout: did not receive response in time")]
    TimeOut,

    #[error("Reloading error: {0}")]
    ReloadErr(String),
}

pub fn open_unix_sock_async<P: AsRef<Path> + ?Sized + std::fmt::Display>(
    bind_addr: &P,
) -> Result<UnixDatagram, &'static str> {
    debug!("Opening sock at {bind_addr}...");

    /* remove entry from filesystem */
    let _ = std::fs::remove_file(bind_addr);

    /* create intermediate directories */
    let path = Path::new(bind_addr.as_ref());
    if let Some(parent_dir) = path.parent() {
        debug!("Creating directory at {parent_dir:?}...");
        fs::create_dir_all(parent_dir)
            .map_err(|_| "Failed to create path to unix sock local address")?;
    }

    /* create sock */
    let sock = UnixDatagram::bind(bind_addr).map_err(|_| "Failed to bind socket")?;
    let raw_fd = sock.as_raw_fd();
    let send_buf_size = 8 * 1024 * 1024;
    let borrowed_fd = unsafe { BorrowedFd::borrow_raw(raw_fd) };
    setsockopt(&borrowed_fd, sockopt::SndBuf, &send_buf_size)
        .map_err(|_| "Failed to set send buffer size")?;
    let recv_buf_size = 8 * 1024 * 1024;
    setsockopt(&borrowed_fd, sockopt::RcvBuf, &recv_buf_size)
        .map_err(|_| "Failed to set receive buffer size")?;
    let mut perms = fs::metadata(bind_addr)
        .map_err(|_| "Failed to retrieve path metadata")?
        .permissions();
    perms.set_mode(0o777); // fixme: make this more restrictive
    fs::set_permissions(bind_addr, perms).map_err(|_| "Failure setting permissions")?;
    debug!("Created unix sock and bound to {bind_addr}");
    Ok(sock)
}

pub struct FrrMi {
    sock: UnixDatagram,
    local: String,
    remote: String,
    connected: bool,
    up: bool,
    rx_timeout: Duration,
}
impl FrrMi {
    const REPLY_TIMEOUT: u64 = 10;

    /// Create an frrmi to talk to an frr-agent.
    pub async fn new(bind_addr: &str, remote_addr: &str) -> Result<FrrMi, FrrErr> {
        let sock = open_unix_sock_async(bind_addr).map_err(FrrErr::FailOpen)?;
        let mut frrmi = Self {
            sock,
            local: bind_addr.to_string(),
            remote: remote_addr.to_string(),
            connected: false,
            up: false,
            rx_timeout: Duration::from_secs(Self::REPLY_TIMEOUT),
        };
        /* attempt connect to frr-agent. If successful, probe the frr-agent */
        frrmi.connect();
        if frrmi.is_connected() {
            frrmi.probe().await;
        }
        info!(
            "Successfully opened frrmi. Local:{} remote:{} connected:{} up:{}",
            &frrmi.local, &frrmi.remote, frrmi.connected, frrmi.up
        );
        Ok(frrmi)
    }
    /// Close the socket of this frrmi. Currently UNUSED
    pub fn close(&mut self) {
        info!("Shutting down frrmi...");
        let _ = self.sock.shutdown(Shutdown::Both);
    }
    /// Tell if the frrmi is connected to the remote address
    pub fn is_connected(&self) -> bool {
        self.connected
    }

    /// Tell if according to the frrmi, the frr-agent is up or not
    pub fn is_up(&self) -> bool {
        self.up
    }
    /// Connect the frrmi to the configured remote address
    pub fn connect(&mut self) {
        debug!("Connecting frrmi to {}...", &self.remote);
        match self.sock.connect(&self.remote) {
            Ok(_) => {
                debug!("Connected to frr-agent at {}", self.remote);
                self.connected = true;
            }
            Err(e) => {
                error!("Can't connect to frr-agent at {}: {e}", self.remote);
            }
        }
    }
    /// Probe the frr-agent with this [`FrrMi`] by sending a keepalive message
    pub async fn probe(&mut self) {
        if !self.is_connected() {
            self.connect();
        }
        if self.is_connected() {
            debug!("Probing frr-agent...");
            let up = self.send_receive(0, "KEEPALIVE").await.is_ok();
            if up != self.up {
                info!("Frr-agent at {} is up", self.remote);
                self.up = up
            }
        }
    }

    /// Receive a response
    async fn receive_response(&self) -> Result<(), FrrErr> {
        debug!("Awaiting reply from frr-agent at {}...", self.remote);

        /* start a timeout for the reception of the response */
        let mut rx_buff = vec![0u8; 1024];
        let result = match timeout(self.rx_timeout, self.sock.recv(&mut rx_buff)).await {
            Ok(result) => result,
            Err(_) => {
                error!(
                    "Got no response from frr-agent in {:?} seconds",
                    self.rx_timeout
                );
                return Err(FrrErr::TimeOut);
            }
        };

        /* we received response in time. Check it */
        match result {
            Ok(len) => {
                /* decode response as a string */
                if let Ok(response) = String::from_utf8(rx_buff[0..len].to_vec()) {
                    debug!("Frr-agent answered: {response}");
                    match response.as_str() {
                        "Ok" => Ok(()),
                        _ => Err(FrrErr::ReloadErr(response)),
                    }
                } else {
                    Err(FrrErr::ReloadErr("Failed to parse response".to_string()))
                }
            }
            Err(e) => {
                error!("Error receiving over frrmi: {e}");
                Err(FrrErr::FailCommFrrAgent(e.to_string()))
            }
        }
    }

    /// Send a message over this [`FrrMi`], such as a config or a keepalive
    /// and receive the response.
    ///
    /// Returns error if message could not be sent, or the response could not
    /// be received, or a response was received but it was not "Ok"
    async fn send_receive(&self, genid: GenId, msg: &str) -> Result<(), FrrErr> {
        if !self.is_connected() || !self.is_up() {
            /* // FIXME: this requires frrmi to be mutable
                       self.probe();
                       if !self.is_connected() {
                           return Err(FrrErr::NotConnected);
                       }
                       if !self.is_up() {
                           return Err(FrrErr::FrrAgentDown);
                       }
            */
        }

        /* send length of message */
        let length = msg.len() as u64;
        self.sock.send(&length.to_ne_bytes()).await.map_err(|e| {
            error!("Fatal: Failed to send message length: {e}");
            FrrErr::FailCommFrrAgent(e.to_string())
        })?;

        /* send genid (0 in keepalives) */
        self.sock.send(&genid.to_ne_bytes()).await.map_err(|e| {
            error!("Fatal: Failed to send genid: {e}");
            FrrErr::FailCommFrrAgent(e.to_string())
        })?;

        /* send message (e.g. a config or a keepalive) */
        self.sock.send(msg.as_bytes()).await.map_err(|e| {
            error!("Fatal: Failed to send message: {e}");
            FrrErr::FailCommFrrAgent(e.to_string())
        })?;

        /* receive reply from frr-agent and check its contents */
        self.receive_response().await
    }

    /// Apply the config in FRR represented by [`ConfigBuilder`] using this [`FrrMi`]
    pub async fn apply_config(&self, genid: GenId, config: &ConfigBuilder) -> Result<(), FrrErr> {
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
    use tokio::task::JoinHandle;
    use tracing_test::traced_test;

    /// Create a fake frr-agent async task for testing.
    /// The agent can be stopped by calling abort() on the returned handle.
    pub async fn fake_frr_agent(agent_address: &str) -> JoinHandle<()> {
        /* N.B: socknames include name of test to avoid issues with other tests running concurrently */
        let sock = open_unix_sock_async(agent_address).expect("Should succeed");
        tokio::spawn(async move {
            loop {
                let mut rx_buff = vec![0u8; 8192];
                let (_, _) = sock.recv_from(&mut rx_buff).await.unwrap();
                let (_, requestor) = sock.recv_from(&mut rx_buff).await.unwrap();
                sock.send_to(
                    "Ok".to_string().as_bytes(),
                    requestor.as_pathname().unwrap(),
                )
                .await
                .unwrap();
            }
        })
    }

    #[tokio::test]
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
        let frrmi = FrrMi::new(
            "/tmp/frrmi-test/frrmi.sock",
            "/tmp/frrmi-test/frr-agent.sock",
        )
        .await
        .unwrap();

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
