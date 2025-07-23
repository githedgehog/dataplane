// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Router IO, which includes the control-plane interface CPI and the FRR management interface (FRRMI)

#![allow(clippy::items_after_statements)]

use crate::cli::handle_cli_request;
use crate::config::FrrConfig;
use crate::cpi::{CpiStats, process_rx_data, rpc_send_control};
use crate::ctl::{RouterCtlMsg, RouterCtlSender, handle_ctl_msg};
use crate::errors::RouterError;
use crate::fib::fibtable::FibTableWriter;
use crate::frr::frrmi::{FrrErr, Frrmi, FrrmiRequest};
use crate::interfaces::iftablerw::IfTableWriter;
use crate::revent::{ROUTER_EVENTS, RouterEvent};
use crate::routingdb::RoutingDb;
use crate::{atable::atablerw::AtableReader, cpi::CpiStatus};

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

#[allow(unused)]
use tracing::{debug, error, info, warn};

// capacity of rio control channel. This should have very little impact on performance.
const CTL_CHANNEL_CAPACITY: usize = 100;

pub struct RioHandle {
    pub ctl: Sender<RouterCtlMsg>,
    pub handle: Option<JoinHandle<()>>,
}
impl RioHandle {
    /// Terminate the router IO loop / thread
    ///
    /// # Errors
    /// Fails if the channel has been dropped or the thread cannot be joined
    pub fn finish(&mut self) -> Result<(), RouterError> {
        debug!("Requesting router IO to stop..");
        self.ctl
            .try_send(RouterCtlMsg::Finish)
            .map_err(|_| RouterError::Internal("Error sending over ctl channel"))?;

        let handle = self.handle.take();
        if let Some(handle) = handle {
            debug!("Waiting for the router IO to terminate..");
            handle
                .join()
                .map_err(|_| RouterError::Internal("Error joining thread"))?;
            debug!("Router IO ended successfully");
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
pub const DEFAULT_DP_UX_PATH_CLI: &str = "/var/run/dataplane/cli.sock";
pub const DEFAULT_FRR_AGENT_PATH: &str = "/var/run/frr/frr-agent.sock";

pub struct RioConf {
    pub cpi_sock_path: Option<String>,
    pub cli_sock_path: Option<String>,
    pub frrmi_sock_path: Option<String>,
}
impl Default for RioConf {
    fn default() -> Self {
        Self {
            cpi_sock_path: Some(DEFAULT_DP_UX_PATH.to_string()),
            cli_sock_path: Some(DEFAULT_DP_UX_PATH_CLI.to_string()),
            frrmi_sock_path: Some(DEFAULT_FRR_AGENT_PATH.to_string()),
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
pub(crate) const FRRMISOCK: Token = Token(2);
/// `Rio` is the router IO loop state
pub(crate) struct Rio {
    pub(crate) run: bool,
    pub(crate) frozen: bool,
    pub(crate) cp_sock_path: String,
    pub(crate) cli_sock_path: String,
    pub(crate) poller: Poll,
    pub(crate) clisock: UnixDatagram,
    pub(crate) cpi_sock: RpcCachedSock,
    pub(crate) frrmi: Frrmi,
    pub(crate) ctl_tx: Sender<RouterCtlMsg>,
    pub(crate) ctl_rx: Receiver<RouterCtlMsg>,
    pub(crate) cpistats: CpiStats,
}
impl Rio {
    fn new(conf: &RioConf) -> Result<Rio, RouterError> {
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

        /* path of frr-agent */
        let frrmi_sock_path = conf.frrmi_sock_path.as_ref().map_or_else(
            || DEFAULT_FRR_AGENT_PATH.to_owned(),
            std::borrow::ToOwned::to_owned,
        );

        /* create unix sock for routing function and bind it */
        let cpsock = open_unix_sock(&cp_sock_path)?;

        /* create unix sock for cli and bind it */
        let clisock = open_unix_sock(&cli_sock_path)?;

        /* frrmi - communication to frr-agent */
        let frrmi = Frrmi::new(&frrmi_sock_path);

        /* internal ctl channel */
        let (ctl_tx, ctl_rx) = channel::<RouterCtlMsg>(CTL_CHANNEL_CAPACITY);

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
            .register(&mut ev_cpsock, CPSOCK, Interest::PRIORITY)
            .map_err(|_| RouterError::Internal("Failed to register CPI sock"))?;
        poller
            .registry()
            .register(&mut ev_clisock, CLISOCK, Interest::READABLE)
            .map_err(|_| RouterError::Internal("Failed to register CLI sock"))?;

        Ok(Rio {
            run: true,
            frozen: false,
            cp_sock_path,
            cli_sock_path,
            poller,
            clisock,
            cpi_sock: cached_sock,
            frrmi,
            ctl_tx,
            ctl_rx,
            cpistats: CpiStats::default(),
        })
    }
    pub(crate) fn register(&self, token: Token, fd: i32, interests: Interest) {
        debug!("Registering fd {fd}...");
        let mut ev_sock = SourceFd(&fd);
        if let Err(e) = self
            .poller
            .registry()
            .register(&mut ev_sock, token, interests)
        {
            error!("Fatal: could not register descriptor {fd}: {e}");
        }
    }
    pub(crate) fn reregister(
        &self,
        token: Token,
        fd: i32,
        interests: Interest,
    ) -> Result<(), RouterError> {
        debug!("Re-registering fd {fd}...");
        let mut ev_sock = SourceFd(&fd);
        self.poller
            .registry()
            .reregister(&mut ev_sock, token, interests)
            .map_err(|e| {
                error!("Could not re-register descriptor {fd}: {e}");
                RouterError::Internal("Re-register failure")
            })
    }
    fn deregister(&self, fd: i32) {
        debug!("Deregistering fd {fd}...");
        let mut ev_sock = SourceFd(&fd);
        if let Err(e) = self.poller.registry().deregister(&mut ev_sock) {
            warn!("Error deregistering descriptor {fd}: {e}")
        }
    }
    fn frrmi_connect(&mut self) {
        if !self.frrmi.has_sock() {
            self.frrmi.connect();
            if let Some(sock_fd) = self.frrmi.get_sock_fd() {
                debug!("Registering frrmi sock (fd:{sock_fd})...");
                self.register(FRRMISOCK, sock_fd, Interest::READABLE);
            }
        }
    }
    fn frrmi_disconnect(&mut self) {
        if let Some(sock_fd) = self.frrmi.get_sock_fd() {
            debug!("Disconnecting frrmi (fd:{sock_fd})...");
            self.deregister(sock_fd);
            self.frrmi.disconnect();
        }
    }
    pub(crate) fn frrmi_restart(&mut self) {
        debug!("Restarting frrmi...");
        self.frrmi_disconnect();
        self.frrmi_connect();
    }
    fn service_frrmi_requests(&mut self) {
        if self.frrmi.has_sock() {
            match self.frrmi.service_request() {
                Ok(()) => {} // nothing to do. If a request was sent, wait for response.
                Err(FrrErr::IOBusy) => {
                    if let Some(fd) = self.frrmi.get_sock_fd() {
                        let _ =
                            self.reregister(FRRMISOCK, fd, Interest::WRITABLE | Interest::READABLE);
                    }
                }
                Err(e) => {
                    warn!("Error sending over frrmi: {e}");
                    self.frrmi_restart();
                }
            }
        }
    }
    pub(crate) fn request_frr_config(&mut self, genid: i64, cfg: FrrConfig) {
        let req = FrrmiRequest::new(genid, cfg, 0);
        self.frrmi.queue_request(req);
    }
    /// Request to reapply the last configuration
    pub(crate) fn reapply_frr_config(&mut self, db: &RoutingDb) {
        if let Some(rconfig) = &db.config {
            if let Some(frr_cfg) = rconfig.get_frr_config() {
                self.request_frr_config(rconfig.genid(), frr_cfg.clone());
            }
        }
    }

    /// Check the status of the CPI and react accordingly
    pub(crate) fn cpi_status_check(&mut self, db: &RoutingDb) {
        match self.cpistats.status {
            CpiStatus::NotConnected => {}
            CpiStatus::Connected => {}
            CpiStatus::Incompatible => {}
            CpiStatus::FrrRestarted => {
                warn!("FRR appears to have restarted. Applying last config...");
                self.frrmi.clear_applied_cfg(); /* we know Frr has no config */
                self.reapply_frr_config(&db); /* request agent to apply last config */
                self.cpistats.status.change(CpiStatus::Connected);
            }
            CpiStatus::NeedRefresh => {
                warn!("We appear to have restarted. Requesting refresh to FRR...");
                if let Some(peer) = &self.cpistats.peer {
                    rpc_send_control(&mut self.cpi_sock, peer, true);
                    revent!(RouterEvent::CpiRefreshRequested);
                    self.cpistats.status.change(CpiStatus::Connected);
                }
            }
        }
    }
}

#[allow(clippy::missing_errors_doc)]
pub fn start_rio(
    conf: &RioConf,
    fibtw: FibTableWriter,
    iftw: IfTableWriter,
    atabler: AtableReader,
) -> Result<RioHandle, RouterError> {
    let mut rio = Rio::new(conf)?;
    let ctl_tx = rio.ctl_tx.clone();

    /* router IO loop */
    let rio_loop = move || {
        info!("CPI: Listening at {}.", &rio.cp_sock_path);
        info!("CLI: Listening at {}.", &rio.cli_sock_path);
        info!("FRRMI: will connect to {}.", &rio.frrmi.get_remote());
        let mut events = Events::with_capacity(64);
        let mut buf = vec![0; 1024];

        /* create routing database: this is fully owned by the CPI */
        let mut db = RoutingDb::new(fibtw, iftw, atabler);

        revent!(RouterEvent::Started);

        info!("Entering router IO loop....");
        while rio.run {
            if let Err(e) = rio.poller.poll(&mut events, Some(Duration::from_secs(1))) {
                error!("Poller error!: {e}");
                continue;
            }

            /* connect to frr-agent if we're not connected*/
            rio.frrmi_connect();

            /* service pending frr reconfig requests if any */
            rio.service_frrmi_requests();

            /* did any request time out? */
            rio.frrmi.timeout();

            /* events on unix sockets */
            for event in &events {
                match event.token() {
                    CPSOCK => {
                        while event.is_readable() {
                            if let Ok((len, peer)) = rio.cpi_sock.recv_from(buf.as_mut_slice()) {
                                process_rx_data(&mut rio, &peer, &buf[..len], &mut db);
                            } else {
                                break;
                            }
                        }
                        if event.is_writable() && !rio.frozen {
                            rio.cpi_sock.flush_out_fast();
                            if !rio.cpi_sock.interests().is_writable() {
                                let _ = rio.reregister(
                                    CPSOCK,
                                    rio.cpi_sock.get_raw_fd(),
                                    rio.cpi_sock.interests(),
                                );
                            }
                        }
                        rio.cpi_status_check(&db);
                    }
                    CLISOCK => {
                        while event.is_readable() {
                            if let Ok((len, peer)) = rio.clisock.recv_from(buf.as_mut_slice()) {
                                if let Ok(request) = CliRequest::deserialize(&buf[0..len]) {
                                    handle_cli_request(&mut rio, &peer, request, &db);
                                }
                            } else {
                                break;
                            }
                        }
                    }
                    FRRMISOCK => {
                        if event.is_error() {
                            rio.frrmi_restart();
                            continue;
                        }
                        if event.is_readable() {
                            match rio.frrmi.recv_msg() {
                                Ok(None) => {} // do nothing; continue receiving
                                Ok(Some(response)) => rio.frrmi.process_response(response),
                                Err(e) => {
                                    error!("Failed to receive over frrmi: {e}");
                                    rio.frrmi_restart();
                                }
                            }
                        }
                        if event.is_writable() {
                            // resume xmit of any outstanding request that may have been partially sent
                            let res = rio.frrmi.send_msg_resume();
                            if !matches!(res, Err(FrrErr::IOBusy)) {
                                // unregister in all cases except if we get IOBusy again.
                                if let Some(fd) = rio.frrmi.get_sock_fd() {
                                    let _ = rio.reregister(FRRMISOCK, fd, Interest::READABLE);
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }

            /* handle control-channel messages */
            handle_ctl_msg(&mut rio, &mut db);
        }
    };
    let handle = thread::Builder::new()
        .name("routerIO".to_string())
        .spawn(rio_loop)
        .map_err(|_| RouterError::Internal("Failure spawning thread"))?;

    Ok(RioHandle {
        ctl: ctl_tx,
        handle: Some(handle),
    })
}

#[cfg(test)]
mod tests {
    use crate::atable::atablerw::AtableWriter;
    use crate::errors::RouterError;
    use crate::fib::fibtable::FibTableWriter;
    use crate::interfaces::iftablerw::IfTableWriter;
    use crate::rio::{RioConf, start_rio};
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_rio_ctl() {
        let cpi_bind_addr = "/tmp/hh_dataplane.sock".to_string();
        let cli_bind_addr = "/tmp/hh_cli.sock".to_string();
        let frra_path = "/tmp/frr-agent.sock".to_string();
        let _ = std::fs::remove_file(&cpi_bind_addr);

        /* Build cpi configuration */
        let conf = RioConf {
            cpi_sock_path: Some(cpi_bind_addr),
            cli_sock_path: Some(cli_bind_addr),
            frrmi_sock_path: Some(frra_path),
        };

        /* create interface table */
        let (iftw, _iftr) = IfTableWriter::new();

        /* create fib table */
        let (fibtw, _fibtr) = FibTableWriter::new();

        /* create atable */
        let (_atablew, atabler) = AtableWriter::new();

        /* start CPI */
        let mut cpi = start_rio(&conf, fibtw, iftw, atabler).expect("Should succeed");
        thread::sleep(Duration::from_secs(3));
        assert_eq!(cpi.finish(), Ok(()));
    }
    #[test]
    fn test_rio_bad_path() {
        /* Build rio configuration with bad path for unix sock */
        let conf = RioConf {
            cpi_sock_path: Some("/nonexistent/hh_dataplane.sock".to_string()),
            cli_sock_path: None,
            frrmi_sock_path: None,
        };

        /* create interface table */
        let (iftw, _iftr) = IfTableWriter::new();

        /* create fib table */
        let (fibtw, _fibtr) = FibTableWriter::new();

        /* create atable */
        let (_atablew, atabler) = AtableWriter::new();

        /* start router IO */
        let rio = start_rio(&conf, fibtw, iftw, atabler);
        assert!(rio.is_err_and(|e| matches!(e, RouterError::InvalidPath(_))));
    }
}
