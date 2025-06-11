// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Control-plane interface (CPI)

#![allow(clippy::items_after_statements)]

use crate::atable::atablerw::AtableReader;
use crate::cli::handle_cli_request;
use crate::cpi_process::process_rx_data;
use crate::ctl::handle_ctl_msg;

use crate::ctl::{CpiCtlMsg, RouterCtlSender};
use crate::errors::RouterError;
use crate::fib::fibtable::FibTableWriter;
use crate::interfaces::iftablerw::IfTableWriter;
use crate::routingdb::RoutingDb;

use cli::cliproto::{CliRequest, CliSerialize};
use dplane_rpc::socks::RpcCachedSock;

use mio::unix::SourceFd;
use mio::{Events, Interest, Poll, Token};
use std::fs;
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixDatagram;
use std::thread::{self, JoinHandle};
use std::time::Duration;
use tokio::sync::mpsc::{Receiver, Sender, channel};
use tracing::{debug, error, info};

// capacity of cpi control channel. This should have very little impact on performance.
const CTL_CHANNEL_CAPACITY: usize = 100;

pub struct CpiHandle {
    pub ctl: Sender<CpiCtlMsg>,
    pub handle: Option<JoinHandle<()>>,
}
impl CpiHandle {
    /// Terminate the CPI
    ///
    /// # Errors
    /// Fails if the channel has been dropped or the thread cannot be joined
    pub fn finish(&mut self) -> Result<(), RouterError> {
        debug!("Requesting CPI to stop..");
        self.ctl
            .try_send(CpiCtlMsg::Finish)
            .map_err(|_| RouterError::Internal("Error sending over ctl channel"))?;

        let handle = self.handle.take();
        if let Some(handle) = handle {
            debug!("Waiting for CPI to terminate..");
            handle
                .join()
                .map_err(|_| RouterError::Internal("Error joining thread"))?;
            debug!("CPI ended successfully");
            Ok(())
        } else {
            Err(RouterError::Internal("No handle"))
        }
    }
    #[must_use]
    pub fn get_ctl_tx(&self) -> RouterCtlSender {
        RouterCtlSender::new(self.ctl.clone())
    }
}

pub const DEFAULT_DP_UX_PATH: &str = "/var/run/frr/hh/dataplane.sock";
pub const DEFAULT_DP_UX_PATH_CLI: &str = "/tmp/dataplane_ctl.sock";
pub const DEFAULT_FRR_AGENT_PATH: &str = "/var/run/frr/frr-agent.sock";

pub struct CpiConf {
    pub cpi_sock_path: Option<String>,
    pub cli_sock_path: Option<String>,
}
impl Default for CpiConf {
    fn default() -> Self {
        Self {
            cpi_sock_path: Some(DEFAULT_DP_UX_PATH.to_string()),
            cli_sock_path: Some(DEFAULT_DP_UX_PATH_CLI.to_string()),
        }
    }
}

fn open_unix_sock(path: &String) -> Result<UnixDatagram, RouterError> {
    let _ = std::fs::remove_file(path);
    let sock = UnixDatagram::bind(path).map_err(|_| RouterError::InvalidPath(path.to_owned()))?;
    let mut perms = fs::metadata(path)
        .map_err(|_| RouterError::Internal("Failure retrieving socket metadata"))?
        .permissions();
    perms.set_mode(0o777);
    fs::set_permissions(path, perms).map_err(|_| RouterError::PermError)?;
    sock.set_nonblocking(true)
        .map_err(|_| RouterError::Internal("Failure setting non-blocking socket"))?;
    Ok(sock)
}

pub(crate) const CPSOCK: Token = Token(0);
pub(crate) const CLISOCK: Token = Token(1);

pub(crate) struct Cpi {
    pub(crate) run: bool,
    pub(crate) frozen: bool,
    pub(crate) cp_sock_path: String,
    pub(crate) cli_sock_path: String,
    pub(crate) poller: Poll,
    pub(crate) clisock: UnixDatagram,
    pub(crate) cached_sock: RpcCachedSock,
    pub(crate) ctl_tx: Sender<CpiCtlMsg>,
    pub(crate) ctl_rx: Receiver<CpiCtlMsg>,
}
impl Cpi {
    fn new(conf: &CpiConf) -> Result<Cpi, RouterError> {
        /* path to bind to for routing function */
        let cp_sock_path = conf.cpi_sock_path.as_ref().map_or_else(
            || DEFAULT_DP_UX_PATH.to_owned(),
            std::borrow::ToOwned::to_owned,
        );

        /* path to bind to for cli */
        let cli_sock_path = conf.cli_sock_path.as_ref().map_or_else(
            || DEFAULT_DP_UX_PATH_CLI.to_owned(),
            std::borrow::ToOwned::to_owned,
        );

        /* create unix sock for routing function and bind it */
        let cpsock = open_unix_sock(&cp_sock_path)?;

        /* create unix sock for cli and bind it */
        let clisock = open_unix_sock(&cli_sock_path)?;

        /* internal ctl channel */
        let (ctl_tx, ctl_rx) = channel::<CpiCtlMsg>(CTL_CHANNEL_CAPACITY);

        /* Routing socket */
        let cpsock_fd = cpsock.as_raw_fd();
        let mut ev_cpsock = SourceFd(&cpsock_fd);

        /* Build a cached socket */
        let cached_sock = RpcCachedSock::from_sock(cpsock);

        /* cli socket */
        let clisock_fd = clisock.as_raw_fd();
        let mut ev_clisock = SourceFd(&clisock_fd);

        /* create poller and register cp_sock and cli_sock */
        let poller = Poll::new().map_err(|_| RouterError::Internal("Poll creation failed"))?;
        poller
            .registry()
            .register(&mut ev_cpsock, CPSOCK, Interest::READABLE)
            .map_err(|_| RouterError::Internal("Failed to register CPI sock"))?;
        poller
            .registry()
            .register(&mut ev_clisock, CLISOCK, Interest::READABLE)
            .map_err(|_| RouterError::Internal("Failed to register CLI sock"))?;

        Ok(Cpi {
            run: true,
            frozen: false,
            cp_sock_path,
            cli_sock_path,
            poller,
            clisock,
            cached_sock,
            ctl_tx,
            ctl_rx,
        })
    }
}

#[allow(clippy::missing_errors_doc)]
pub fn start_cpi(
    conf: &CpiConf,
    fibtw: FibTableWriter,
    iftw: IfTableWriter,
    atabler: AtableReader,
) -> Result<CpiHandle, RouterError> {
    let mut cpi = Cpi::new(conf)?;
    let ctl_tx = cpi.ctl_tx.clone();

    /* CPI & CLI loop */
    let cpi_loop = move || {
        info!("CPI Listening at {}.", &cpi.cp_sock_path);
        info!("CLI Listening at {}.", &cpi.cli_sock_path);
        let mut events = Events::with_capacity(64);
        let mut buf = vec![0; 1024];

        /* create routing database: this is fully owned by the CPI */
        let mut db = RoutingDb::new(fibtw, iftw, atabler);

        info!("Entering CPI IO loop....");
        while cpi.run {
            if let Err(e) = cpi.poller.poll(&mut events, Some(Duration::from_secs(1))) {
                error!("Poller error!: {e}");
                continue;
            }

            /* events on unix sockets */
            for event in &events {
                match event.token() {
                    CPSOCK => {
                        while event.is_readable() {
                            if let Ok((len, peer)) = cpi.cached_sock.recv_from(buf.as_mut_slice()) {
                                process_rx_data(&mut cpi.cached_sock, &peer, &buf[..len], &mut db);
                            } else {
                                break;
                            }
                        }
                        if event.is_writable() && !cpi.frozen {
                            cpi.cached_sock.flush_out_fast();
                            if !cpi.cached_sock.interests().is_writable() {
                                if let Err(e) = cpi.poller.registry().reregister(
                                    &mut SourceFd(&cpi.cached_sock.get_raw_fd()),
                                    CPSOCK,
                                    cpi.cached_sock.interests(),
                                ) {
                                    error!("Poller reregister failed for CPI: {e} !!!");
                                }
                            }
                        }
                    }
                    CLISOCK => {
                        while event.is_readable() {
                            if let Ok((len, peer)) = cpi.clisock.recv_from(buf.as_mut_slice()) {
                                if let Ok(request) = CliRequest::deserialize(&buf[0..len]) {
                                    handle_cli_request(&cpi.clisock, &peer, request, &db);
                                }
                            } else {
                                break;
                            }
                        }
                    }
                    _ => {}
                }
            }

            /* handle control-channel messages */
            handle_ctl_msg(&mut cpi, &mut db);
        }
    };
    let handle = thread::Builder::new()
        .name("CPI".to_string())
        .spawn(cpi_loop)
        .map_err(|_| RouterError::Internal("Failure spawning thread"))?;

    Ok(CpiHandle {
        ctl: ctl_tx,
        handle: Some(handle),
    })
}

#[cfg(test)]
mod tests {
    use crate::atable::atablerw::AtableWriter;
    use crate::cpi::{CpiConf, start_cpi};
    use crate::errors::RouterError;
    use crate::fib::fibtable::FibTableWriter;
    use crate::interfaces::iftablerw::IfTableWriter;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_cpi_ctl() {
        let cpi_bind_addr = "/tmp/hh_dataplane.sock".to_string();
        let _ = std::fs::remove_file(&cpi_bind_addr);

        /* Build cpi configuration */
        let conf = CpiConf {
            cpi_sock_path: Some(cpi_bind_addr),
            cli_sock_path: None,
        };

        /* create interface table */
        let (iftw, _iftr) = IfTableWriter::new();

        /* create fib table */
        let (fibtw, _fibtr) = FibTableWriter::new();

        /* create atable */
        let (_atablew, atabler) = AtableWriter::new();

        /* start CPI */
        let mut cpi = start_cpi(&conf, fibtw, iftw, atabler).expect("Should succeed");
        thread::sleep(Duration::from_secs(3));
        assert_eq!(cpi.finish(), Ok(()));
    }
    #[test]
    fn test_cpi_failure_bad_path() {
        /* Build cpi configuration with bad path for unix sock */
        let conf = CpiConf {
            cpi_sock_path: Some("/nonexistent/hh_dataplane.sock".to_string()),
            cli_sock_path: None,
        };

        /* create interface table */
        let (iftw, _iftr) = IfTableWriter::new();

        /* create fib table */
        let (fibtw, _fibtr) = FibTableWriter::new();

        /* create atable */
        let (_atablew, atabler) = AtableWriter::new();

        /* start CPI */
        let cpi = start_cpi(&conf, fibtw, iftw, atabler);
        assert!(cpi.is_err_and(|e| matches!(e, RouterError::InvalidPath(_))));
    }
}
