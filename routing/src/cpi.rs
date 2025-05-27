// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Control-plane interface (CPI)

#![allow(clippy::items_after_statements)]

const DEFAULT_DP_UX_PATH: &str = "/var/run/frr/hh_dataplane.sock";
const DEFAULT_DP_UX_PATH_CLI: &str = "/tmp/dataplane_ctl.sock";

use crate::atable::atablerw::AtableReader;
use crate::cli::handle_cli_request;
use crate::cpi_process::process_rx_data;
use crate::errors::RouterError;
use crate::evpn::Vtep;
use crate::fib::fibtable::FibTableWriter;
use crate::interfaces::iftablerw::IfTableWriter;
use crate::routingdb::RoutingDb;

use cli::cliproto::{CliRequest, CliSerialize};
use dplane_rpc::log::Level;
use dplane_rpc::socks::RpcCachedSock;

use mio::unix::SourceFd;
use mio::{Events, Interest, Poll, Token};
use std::fs;
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixDatagram;
use std::str::FromStr;
use std::thread::{self, JoinHandle};
use std::time::Duration;
use tokio::sync::mpsc::error::TryRecvError;
use tokio::sync::mpsc::{Sender, channel};
use tracing::{debug, error, info, warn};

// A channel sender to the cpi/router
#[allow(unused)]
pub struct RouterCtlSender(tokio::sync::mpsc::Sender<CpiCtlMsg>);

// capacity of cpi control channel. This should have very little impact on performance.
const CTL_CHANNEL_CAPACITY: usize = 100;

#[allow(unused)]
pub enum CpiCtlMsg {
    Finish,
    SetVtep(Vtep),
}

pub struct CpiHandle {
    pub ctl: Sender<CpiCtlMsg>,
    pub handle: Option<JoinHandle<()>>,
}
#[allow(unused)]
impl CpiHandle {
    /// Terminate the CPI
    ///
    /// # Errors
    /// Fails if the channel has been dropped or the thread cannot be joined
    pub fn finish(&mut self) -> Result<(), RouterError> {
        debug!("Requesting CPI to stop..");
        self.ctl
            .try_send(CpiCtlMsg::Finish)
            .map_err(|_| RouterError::CpiFailure)?;

        let handle = self.handle.take();
        if let Some(handle) = handle {
            debug!("Waiting for CPI to terminate..");
            handle.join().map_err(|_| RouterError::CpiFailure)?;
            debug!("CPI ended successfully");
            Ok(())
        } else {
            Err(RouterError::Internal("No handle"))
        }
    }
    pub fn get_ctl_tx(&self) -> RouterCtlSender {
        RouterCtlSender(self.ctl.clone())
    }
}

pub struct CpiConf {
    pub rpc_loglevel: Option<String>,
    pub cpi_sock_path: Option<String>,
    pub cli_sock_path: Option<String>,
}

fn open_unix_sock(path: &String) -> Result<UnixDatagram, RouterError> {
    let _ = std::fs::remove_file(path);
    let sock = UnixDatagram::bind(path).map_err(|_| RouterError::InvalidSockPath)?;
    let mut perms = fs::metadata(path)
        .map_err(|_| RouterError::InvalidSockPath)?
        .permissions();
    perms.set_mode(0o777);
    fs::set_permissions(path, perms).map_err(|_| RouterError::PermError)?;
    sock.set_nonblocking(true)
        .map_err(|_| RouterError::Internal("Failure setting non-blocking socket"))?;
    Ok(sock)
}

fn set_vtep(db: &mut RoutingDb, vtep_data: &Vtep) {
    if let Ok(mut vtep) = db.vtep.write() {
        if let Some(ip) = vtep_data.get_ip() {
            vtep.set_ip(ip);
            info!("VTEP ip address set to {ip}");
        } else {
            warn!("VTEP no longer has ip address");
            vtep.unset_ip();
        }
        if let Some(mac) = vtep_data.get_mac() {
            vtep.set_mac(mac);
            info!("VTEP mac address set to {mac}");
        } else {
            warn!("VTEP no longer has mac address");
            vtep.unset_mac();
        }
    }
}

#[allow(unused)]
#[allow(clippy::too_many_lines)]
#[allow(clippy::missing_errors_doc)]
pub fn start_cpi(
    conf: &CpiConf,
    fibtw: FibTableWriter,
    iftw: IfTableWriter,
    atabler: AtableReader,
) -> Result<CpiHandle, RouterError> {
    /* get desired loglevel and set it */
    let loglevel = conf.rpc_loglevel.as_ref().map_or_else(
        || Level::DEBUG,
        |level| Level::from_str(level).unwrap_or(Level::DEBUG),
    );

    info!("Launching CPI, loglevel is {loglevel:?}...");

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
    let (tx, mut rx) = channel::<CpiCtlMsg>(CTL_CHANNEL_CAPACITY);

    /* Routing socket */
    const CPSOCK: Token = Token(0);
    let cpsock_fd = cpsock.as_raw_fd();
    let mut ev_cpsock = SourceFd(&cpsock_fd);

    /* Build a cached socket */
    let mut cached_sock = RpcCachedSock::from_sock(cpsock);

    /* cli socket */
    const CLISOCK: Token = Token(1);
    let clisock_fd = clisock.as_raw_fd();
    let mut ev_clisock = SourceFd(&clisock_fd);

    /* create poller and register cp_sock and cli_sock */
    let mut poller = Poll::new().map_err(|_| RouterError::Internal("Poll creation failed"))?;
    poller
        .registry()
        .register(&mut ev_cpsock, CPSOCK, Interest::READABLE)
        .map_err(|_| RouterError::Internal("Failed to register CPI sock"))?;
    poller
        .registry()
        .register(&mut ev_clisock, CLISOCK, Interest::READABLE)
        .map_err(|_| RouterError::Internal("Failed to register CLI sock"))?;

    /* CPI & CLI loop */
    let cpi_loop = move || {
        info!("CPI Listening at {}.", cp_sock_path);
        info!("CLI Listening at {}.", cli_sock_path);
        info!("Entering main IO loop....");
        let mut events = Events::with_capacity(64);
        let mut buf = vec![0; 1024];
        let mut run = true;

        /* create routing database: this is fully owned by the CPI */
        let mut db = RoutingDb::new(Some(fibtw), iftw, atabler);

        while run {
            if let Err(e) = poller.poll(&mut events, Some(Duration::from_secs(1))) {
                error!("Poller error!: {e}");
                continue;
            }

            /* control channel */
            match rx.try_recv() {
                Ok(CpiCtlMsg::Finish) => {
                    info!("Got request to shutdown. Au revoir ...");
                    run = false;
                }
                Ok(CpiCtlMsg::SetVtep(vtep_data)) => set_vtep(&mut db, &vtep_data),
                Err(TryRecvError::Empty) => {}
                Err(e) => {
                    error!("Error receiving from ctl channel {e:?}");
                }
            }

            /* events on unix sockets */
            for event in &events {
                match event.token() {
                    CPSOCK => {
                        while event.is_readable() {
                            if let Ok((len, peer)) = cached_sock.recv_from(buf.as_mut_slice()) {
                                process_rx_data(&mut cached_sock, &peer, &buf[..len], &mut db);
                            } else {
                                break;
                            }
                        }
                        if event.is_writable() {
                            cached_sock.flush_out_fast();
                            if !cached_sock.interests().is_writable() {
                                poller.registry().reregister(
                                    &mut SourceFd(&cached_sock.get_raw_fd()),
                                    CPSOCK,
                                    cached_sock.interests(),
                                );
                            }
                        }
                    }
                    CLISOCK => {
                        while event.is_readable() {
                            if let Ok((len, peer)) = clisock.recv_from(buf.as_mut_slice()) {
                                if let Ok(request) = CliRequest::deserialize(&buf[0..len]) {
                                    handle_cli_request(&clisock, &peer, request, &db);
                                }
                            } else {
                                break;
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    };
    let handle = thread::Builder::new()
        .name("CPI".to_string())
        .spawn(cpi_loop)
        .map_err(|_| RouterError::CpiFailure)?;

    Ok(CpiHandle {
        ctl: tx,
        handle: Some(handle),
    })
}

#[allow(unused)]
#[cfg(test)]
#[allow(dead_code)]
mod tests {
    use crate::atable::atablerw::AtableWriter;
    use crate::cpi::{CpiConf, start_cpi};
    use crate::errors::RouterError;
    use crate::evpn::RmacStore;
    use crate::fib::fibtable::FibTableWriter;
    use crate::interfaces::iftable::IfTable;
    use crate::interfaces::iftablerw::IfTableWriter;
    use crate::interfaces::interface::Interface;
    use crate::routingdb::{RoutingDb, VrfTable};
    use crate::vrf::Vrf;
    use std::fs::remove_file;
    use std::sync::Arc;
    use std::sync::RwLock;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_cpi_ctl() {
        let cpi_bind_addr = "/tmp/hh_dataplane.sock".to_string();
        let _ = std::fs::remove_file(&cpi_bind_addr);

        /* Build cpi configuration */
        let conf = CpiConf {
            rpc_loglevel: Some("debug".to_string()),
            cpi_sock_path: Some(cpi_bind_addr),
            cli_sock_path: None,
        };

        /* create interface table */
        let (mut iftw, iftr) = IfTableWriter::new();

        /* create fib table */
        let (mut fibtw, fibtr) = FibTableWriter::new();

        /* create atable */
        let (mut atablew, atabler) = AtableWriter::new();

        /* start CPI */
        let mut cpi = start_cpi(&conf, fibtw, iftw, atabler).expect("Should succeed");
        thread::sleep(Duration::from_secs(3));
        assert_eq!(cpi.finish(), Ok(()));
    }
    #[test]
    fn test_cpi_failure_bad_path() {
        /* Build cpi configuration with bad path for unix sock */
        let conf = CpiConf {
            rpc_loglevel: Some("debug".to_string()),
            cpi_sock_path: Some("/nonexistent/hh_dataplane.sock".to_string()),
            cli_sock_path: None,
        };

        /* create interface table */
        let (mut iftw, iftr) = IfTableWriter::new();

        /* create fib table */
        let (mut fibtw, fibtr) = FibTableWriter::new();

        /* create atable */
        let (mut atablew, atabler) = AtableWriter::new();

        /* start CPI */
        let cpi = start_cpi(&conf, fibtw, iftw, atabler);
        assert!(cpi.is_err_and(|e| e == RouterError::InvalidSockPath));
    }
}
