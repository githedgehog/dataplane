// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Router IO, which includes the control-plane interface CPI and the FRR management interface (FRRMI)

use crate::atable::atablerw::AtableReader;
use crate::cli::handler::handle_cli_request;
use crate::config::FrrConfig;
use crate::errors::RouterError;
use crate::fib::fibtable::FibTableWriter;
use crate::frr::frrmi::{FrrErr, Frrmi, FrrmiRequest};
use crate::interfaces::iftablerw::IfTableWriter;

use crate::router::CliSources;
use crate::router::cpi::{CpiStats, CpiStatus, process_cpi_data, rpc_send_control};
use crate::router::ctl::{RouterCtlMsg, RouterCtlSender, handle_ctl_msg};
use crate::router::revent::{ROUTER_EVENTS, RouterEvent};
use crate::routingdb::RoutingDb;

use bytes::BytesMut;
use cli::IoCache;
use cli::cliproto::{CLI_RX_BUFF_SIZE, CliRequest};
use config::{GwConfigMeta, ValidatedGwConfig};
use dplane_rpc::socks::RpcCachedSock;
use inotify::{EventMask, Inotify, WatchMask};
use lifecycle::{CancellationToken, Subsystem};
use std::os::fd::AsRawFd;
use std::path::Path;

use mio::unix::SourceFd;
use mio::{Events, Interest, Poll, Token, Waker};

use concurrency::sync::Arc;
use concurrency::thread::{self, JoinHandle};
use nix::sys::socket::{getsockopt, setsockopt, sockopt::SndBuf};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixDatagram;
use std::time::{Duration, Instant};
use tokio::sync::mpsc::{Receiver, Sender, channel};

#[allow(unused)]
use tracing::{debug, error, info, trace, warn};

// capacity of rio control channel
const CTL_CHANNEL_CAPACITY: usize = 100;

/// An object to control a router IO, [`Rio`]
pub(crate) struct RioHandle {
    cancel: CancellationToken,
    ctl: Sender<RouterCtlMsg>,
    waker: Arc<Waker>,
    handle: Option<JoinHandle<()>>,
}
impl RioHandle {
    /// Trip the router cancel and join the RIO thread. Idempotent — a
    /// second call after the thread has been joined returns `Ok(())`.
    /// Worst-case exit latency is one poll timeout (1 second).
    ///
    /// # Errors
    /// Fails if the thread panicked during join.
    pub(crate) fn finish(&mut self) -> Result<(), RouterError> {
        debug!("Requesting router IO to stop..");
        self.cancel.cancel();

        let Some(handle) = self.handle.take() else {
            return Ok(());
        };
        handle
            .join()
            .map_err(|_| RouterError::Internal("Error joining thread"))?;
        Ok(())
    }
    #[must_use]
    pub(crate) fn get_ctl_tx(&self) -> RouterCtlSender {
        RouterCtlSender::new(self.ctl.clone(), self.waker.clone())
    }
}

pub(crate) struct RioConf {
    pub name: String,
    pub cpi_sock_path: Option<String>,
    pub cli_sock_path: Option<String>,
    pub frrmi_sock_path: Option<String>,
}

fn open_unix_sock(path: &String) -> Result<UnixDatagram, RouterError> {
    debug!("Opening UNIX sock; target bind point is {path}");
    let _ = std::fs::remove_file(path);
    let sock = UnixDatagram::bind(path).map_err(|_| RouterError::InvalidPath(path.to_owned()))?;
    let mut perms = fs::metadata(path)
        .map_err(|_| RouterError::Internal("Failure retrieving socket metadata"))?
        .permissions();
    perms.set_mode(0o777);
    fs::set_permissions(path, perms).map_err(|_| RouterError::PermError)?;
    sock.set_nonblocking(true)
        .map_err(|_| RouterError::Internal("Failure setting non-blocking socket"))?;
    debug!("Successfully opened UX sock @ {path}");
    Ok(sock)
}

fn open_cli_sock(path: &String) -> Result<UnixDatagram, RouterError> {
    let sock = open_unix_sock(path)?;
    setsockopt(&sock, SndBuf, &CLI_RX_BUFF_SIZE)
        .map_err(|_| RouterError::Internal("Failure setting snd buffer size"))?;
    if let Ok(size) = getsockopt(&sock, SndBuf) {
        debug!("Cli sock send buffer set to {size}");
    }
    Ok(sock)
}

// set up an inotify watcher for the directory where the CLI socket path lives.
// This is way more reliable than tracking the file itself, since unlinking the path
// only removes the directory entry, but the inode remains if the sock is open; so
// no DELETE_SELF would be emitted.
fn setup_clipath_watcher(path: &str) -> Result<Inotify, RouterError> {
    let inotify = Inotify::init().map_err(|_| RouterError::Internal("Failed to init inotify"))?;
    let dir = Path::new(path)
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or(RouterError::Internal("CLI socket path has no parent dir"))?;

    let mask = WatchMask::DELETE | WatchMask::MOVED_FROM;
    inotify
        .watches()
        .add(dir, mask)
        .map_err(|_| RouterError::Internal("Failed to add watcher for inotify"))?;

    debug!("Will track {path} via ({})", dir.display());
    Ok(inotify)
}

pub(crate) const CPSOCK: Token = Token(0);
pub(crate) const CLISOCK: Token = Token(1);
pub(crate) const FRRMISOCK: Token = Token(2);
pub(crate) const CTL_CHANNEL: Token = Token(3);
pub(crate) const CLIPATH_WATCHER: Token = Token(4);

/// `Rio` is the router IO loop state
pub(crate) struct Rio {
    #[allow(unused)]
    pub(crate) name: String,
    pub(crate) frozen: bool,
    pub(crate) cp_sock_path: String,
    pub(crate) cli_sock_path: String,
    pub(crate) poller: Poll,
    pub(crate) clisock: UnixDatagram,
    pub(crate) cpi_sock: RpcCachedSock,
    pub(crate) frrmi: Frrmi,
    pub(crate) ctl_tx: Sender<RouterCtlMsg>,
    pub(crate) ctl_rx: Receiver<RouterCtlMsg>,
    pub(crate) waker: Arc<Waker>,
    pub(crate) cpistats: CpiStats,
    stale_timeout: Option<Instant>,
    pub(crate) gwconfig: Option<Arc<ValidatedGwConfig>>,
    pub(crate) cfg_history: Arc<Vec<GwConfigMeta>>,
    pub(crate) cli_cache: IoCache,
    pub(crate) inotify: Inotify,
}
impl Rio {
    fn new(conf: &RioConf) -> Result<Rio, RouterError> {
        /* path to bind to for routing function */
        let cp_sock_path = conf.cpi_sock_path.as_ref().map_or_else(
            || args::DEFAULT_DP_UX_PATH.to_owned(),
            std::borrow::ToOwned::to_owned,
        );

        /* path to bind to for cli */
        let cli_sock_path = conf.cli_sock_path.as_ref().map_or_else(
            || args::DEFAULT_DP_UX_PATH_CLI.to_owned(),
            std::borrow::ToOwned::to_owned,
        );

        /* path of frr-agent */
        let frrmi_sock_path = conf.frrmi_sock_path.as_ref().map_or_else(
            || args::DEFAULT_FRR_AGENT_PATH.to_owned(),
            std::borrow::ToOwned::to_owned,
        );

        /* create unix sock for routing function and bind it */
        let cpsock = open_unix_sock(&cp_sock_path)?;

        /* create unix sock for cli and bind it */
        let clisock = open_cli_sock(&cli_sock_path)?;

        /* add a watcher to the cli sock directory to detect if the file is removed */
        let inotify = setup_clipath_watcher(&cli_sock_path)?;
        let inotify_fd = inotify.as_raw_fd();
        let mut inotify_src_fd = SourceFd(&inotify_fd);

        /* frrmi - communication to frr-agent */
        let frrmi = Frrmi::new(&frrmi_sock_path);

        /* ctl channel */
        let (ctl_tx, ctl_rx) = channel::<RouterCtlMsg>(CTL_CHANNEL_CAPACITY);

        /* Routing socket */
        let cpsock_fd = cpsock.as_raw_fd();
        let mut ev_cpsock = SourceFd(&cpsock_fd);

        /* Build a cached socket */
        let cached_sock = RpcCachedSock::from_sock(cpsock);

        /* cli socket */
        let clisock_fd = clisock.as_raw_fd();
        let mut ev_clisock = SourceFd(&clisock_fd);

        /* create poller and register cp_sock, cli_sock, ctl waker and cli path inotify watcher */
        let poller = Poll::new().map_err(|_| RouterError::Internal("Poll creation failed"))?;
        poller
            .registry()
            .register(&mut ev_cpsock, CPSOCK, Interest::PRIORITY)
            .map_err(|_| RouterError::Internal("Failed to register CPI sock"))?;
        poller
            .registry()
            .register(&mut ev_clisock, CLISOCK, Interest::READABLE)
            .map_err(|_| RouterError::Internal("Failed to register CLI sock"))?;

        poller
            .registry()
            .register(&mut inotify_src_fd, CLIPATH_WATCHER, Interest::READABLE)
            .map_err(|_| RouterError::Internal("Failed to register CLIPATH watcher"))?;

        // Waker to integrate the async ctl channel with the poller
        let waker = Arc::new(
            Waker::new(poller.registry(), CTL_CHANNEL)
                .map_err(|_| RouterError::Internal("Failed to create ctl channel waker"))?,
        );

        Ok(Rio {
            name: conf.name.clone(),
            frozen: false,
            cp_sock_path,
            cli_sock_path,
            poller,
            clisock,
            cpi_sock: cached_sock,
            frrmi,
            ctl_tx,
            ctl_rx,
            waker,
            cpistats: CpiStats::new(),
            stale_timeout: None,
            gwconfig: None,
            cfg_history: Arc::from(vec![]),
            cli_cache: IoCache::new(),
            inotify,
        })
    }

    pub(crate) fn cli_sock_restore(&mut self) {
        let raw_fd = self.clisock.as_raw_fd();
        debug!("Restoring CLI socket. Current fd is {raw_fd}...");
        self.deregister(raw_fd);
        let _ = self.clisock.shutdown(std::net::Shutdown::Both);

        // open new sock, bind it and register it
        let Ok(new_sock) = open_cli_sock(&self.cli_sock_path) else {
            error!("Failed to open CLI sock");
            return;
        };
        self.clisock = new_sock;
        self.register(CLISOCK, self.clisock.as_raw_fd(), Interest::READABLE);
        debug!("CLI socket restored at {}", self.cli_sock_path);
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
        let r = if interests.is_readable() { "r" } else { "-" };
        let w = if interests.is_writable() { "w" } else { "-" };
        debug!("Re-registering fd {fd} for {r}{w}");
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
            warn!("Error deregistering descriptor {fd}: {e}");
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
    pub(crate) fn cpi_status_check(&mut self, db: &mut RoutingDb) {
        match self.cpistats.status {
            CpiStatus::NotConnected | CpiStatus::Connected | CpiStatus::Incompatible => {}
            CpiStatus::FrrRestarted => {
                warn!("FRR appears to have restarted!!!...");
                db.vrftable.remove_deleting_vrfs(&mut db.iftw);
                db.vrftable.set_stale(true);
                self.set_stale_timeout();
                debug!("Will now re-apply the last config to FRR...");
                self.frrmi.clear_applied_cfg(); /* we know Frr has no config */
                self.reapply_frr_config(db); /* request agent to apply last config */
                self.cpistats.status.change(CpiStatus::Connected); /* we now frr is connected */
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
    fn set_stale_timeout(&mut self) {
        let duration = 60;
        debug!("Set stale timeout ({duration} seconds)");
        let duration = Duration::from_secs(duration);
        self.stale_timeout = clock::now().checked_add(duration);
    }
    fn check_stale_timeout(&mut self, db: &mut RoutingDb) {
        if self.stale_timeout.take_if(|t| *t < clock::now()).is_some() {
            info!("Stale timeout expired");
            db.vrftable.remove_stale_routes(&db.rmac_store);
            db.vrftable.remove_deleted_vrfs(&mut db.iftw);
        }
    }
    fn cli_wake_on_writeable(&self, writeable: bool) {
        let interests = if writeable {
            Interest::READABLE | Interest::WRITABLE
        } else {
            Interest::READABLE
        };
        let _ = self.reregister(CLISOCK, self.clisock.as_raw_fd(), interests);
    }
}

#[allow(clippy::missing_errors_doc, clippy::too_many_lines)]
pub(crate) fn start_rio(
    subsystem: &Subsystem,
    conf: &RioConf,
    fibtw: FibTableWriter,
    iftw: IfTableWriter,
    atabler: AtableReader,
    cli_sources: Option<CliSources>,
) -> Result<RioHandle, RouterError> {
    let mut rio = Rio::new(conf)?;
    let ctl_tx = rio.ctl_tx.clone();
    let waker = rio.waker.clone();
    let cli_sources = cli_sources.unwrap_or_default();
    let cancel = subsystem.cancel_token();
    let loop_cancel = cancel.clone();
    let guard_subsystem = subsystem.clone();

    /* router IO loop */
    let rio_loop = move || {
        // drop-guard to detect loop termination
        let _guard = guard_subsystem.new_exit_guard("RIO".to_string(), true);

        info!("CPI: Listening at {}.", &rio.cp_sock_path);
        info!("CLI: Listening at {}.", &rio.cli_sock_path);
        info!("FRRMI: will connect to {}.", &rio.frrmi.get_remote());
        let mut events = Events::with_capacity(64);
        let mut cpi_buf = BytesMut::with_capacity(2048);

        /* create routing database: this is fully owned by the CPI */
        let mut db = RoutingDb::new(fibtw, iftw, atabler);

        revent!(RouterEvent::Started);

        info!("Entering router IO loop....");
        // Observe the router subsystem cancellation between poll cycles.
        // Worst-case exit latency is the poll timeout (1 second).
        while !loop_cancel.is_cancelled() {
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

            /* handle events */
            for event in &events {
                match event.token() {
                    CPSOCK => {
                        while event.is_readable() {
                            cpi_buf.resize(2048, 0);
                            if let Ok((len, peer)) = rio.cpi_sock.recv_from(cpi_buf.as_mut()) {
                                let mut data = cpi_buf.split_to(len).freeze();
                                process_cpi_data(&mut rio, &peer, &mut data, &mut db);
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
                        rio.cpi_status_check(&mut db);
                    }
                    CLISOCK => {
                        if event.is_writable() {
                            rio.cli_cache.drain(&rio.clisock);
                            if rio.cli_cache.is_empty() {
                                rio.cli_wake_on_writeable(false);
                            }
                        }
                        while event.is_readable() {
                            if let Ok((peer, request)) = CliRequest::recv(&rio.clisock) {
                                handle_cli_request(&mut rio, &peer, request, &db, &cli_sources);
                                if !rio.cli_cache.is_empty() {
                                    rio.cli_wake_on_writeable(true);
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
                                Ok(Some(response)) => rio.frrmi.process_response(&response),
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
                    CLIPATH_WATCHER => {
                        let mut buffer = [0u8; 4096];
                        let sock_name = Path::new(&rio.cli_sock_path).file_name();
                        match rio.inotify.read_events(&mut buffer) {
                            Ok(evs) => {
                                let removed = evs.into_iter().any(|e| {
                                    e.mask.intersects(EventMask::DELETE | EventMask::MOVED_FROM)
                                        && e.name == sock_name
                                });
                                if removed && !Path::new(&rio.cli_sock_path).exists() {
                                    debug!("CLI socket file was removed...");
                                    rio.cli_sock_restore();
                                }
                            }
                            Err(e) => warn!("Error reading inotify events: {e}"),
                        }
                    }
                    CTL_CHANNEL => handle_ctl_msg(&mut rio, &mut db),
                    _ => {}
                }
            }

            /* check stale timeout. If expired, remove stale routes */
            rio.check_stale_timeout(&mut db);

            /* remove stale router mac entries (if aged). If rmacs were deleted, refresh the
            fibs for the vrfs with the corresponding vnis */
            let vnis = db.rmac_store.flush_stale_rmacs();
            if !vnis.is_empty() {
                db.vrftable.refresh_fibs_by_vni(&vnis, &db.rmac_store);
            }
        }
        info!("RIO is now exiting");
    };
    let handle = thread::Builder::new()
        .name("routerIO".to_string())
        .spawn(rio_loop)
        .map_err(|_| RouterError::Internal("Failure spawning thread"))?;

    Ok(RioHandle {
        cancel,
        ctl: ctl_tx,
        waker,
        handle: Some(handle),
    })
}

#[cfg(test)]
mod tests {
    use crate::atable::atablerw::AtableWriter;
    use crate::errors::RouterError;
    use crate::fib::fibtable::FibTableWriter;
    use crate::interfaces::iftablerw::IfTableWriter;
    use crate::rib::vrf::{RouterVrfConfig, VrfStatus};
    use crate::router::cpi::CpiStatus;
    use crate::router::rio::{Rio, RioConf, RioHandle, start_rio};
    use crate::routingdb::RoutingDb;
    use cli::cliproto::{CliAction, CliRequest, CliResponse, RequestArgs};
    use concurrency::sync::atomic::{AtomicUsize, Ordering};
    use concurrency::thread;
    use dplane_rpc::msg::{
        ConnectInfo, IpRoute, RouteType, RpcMsg, RpcObject, RpcOp, RpcRequest, RpcResultCode,
        VerInfo,
    };
    use dplane_rpc::wire::Wire;
    use lifecycle::{CancellationToken, Subsystem};
    use std::io::Write;
    use std::os::unix::net::{UnixDatagram, UnixListener, UnixStream};
    use std::path::Path;
    use std::time::Duration;

    fn test_router_subsystem() -> Subsystem {
        Subsystem::new("router", CancellationToken::new())
    }

    #[test]
    #[cfg_attr(emulated, ignore = "binds Unix domain sockets at /tmp/hh_*.sock")]
    fn test_rio_ctl() {
        // Paths unique to this test. The fixed `/tmp/hh_dataplane.sock` this
        // used to bind is the path a *running* dataplane uses, and
        // `open_unix_sock` unlinks before it binds -- so under nextest, which
        // runs test binaries concurrently, this test could pull the socket out
        // from under a real dataplane or another copy of itself.
        let dir = SockDir::new();
        let conf = dir.conf();

        /* create interface table */
        let (iftw, _iftr) = IfTableWriter::new();

        /* create fib table */
        let (fibtw, _fibtr) = FibTableWriter::new();

        /* create atable */
        let (_atablew, atabler) = AtableWriter::new();

        /* start CPI */
        let router = test_router_subsystem();
        let mut cpi =
            start_rio(&router, &conf, fibtw, iftw, atabler, None).expect("Should succeed");
        thread::sleep(Duration::from_secs(3));
        assert_eq!(cpi.finish(), Ok(()));
    }
    #[test]
    #[cfg_attr(emulated, ignore = "exercises Unix domain socket bind paths")]
    fn test_rio_bad_path() {
        /* Build rio configuration with bad path for unix sock */
        let conf = RioConf {
            name: "test-routter".to_string(),
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
        let router = test_router_subsystem();
        let rio = start_rio(&router, &conf, fibtw, iftw, atabler, None);
        assert!(rio.is_err_and(|e| matches!(e, RouterError::InvalidPath(_))));
    }

    // ---------------------------------------------------------------------
    // The stale timeout.
    //
    // When FRR restarts, every route we hold becomes suspect: FRR will re-send
    // what it still believes, and whatever it does not re-send within the
    // window was withdrawn while we were not listening. `set_stale_timeout`
    // opens that window and `check_stale_timeout` closes it, sweeping what did
    // not come back.
    //
    // Sixty seconds of wall clock per attempt is why none of this was covered.
    // On a paused clock the window costs nothing, so the boundary can be
    // pinned exactly rather than approached from a safe distance.
    // ---------------------------------------------------------------------

    /// A directory of socket paths that belong to exactly one test, removed
    /// when the test ends.
    ///
    /// The paths have to be unique rather than fixed, and they have to be
    /// unique under two different execution models: `cargo test` runs every
    /// test in one process on many threads, and `nextest` runs each test in a
    /// process of its own. A process-global counter covers the first and the
    /// pid covers the second, so the pair covers both without any coordination
    /// between tests.
    ///
    /// The CPI socket could avoid the filesystem altogether -- Linux abstract
    /// sockets have no directory entry and disappear when closed -- but the CLI
    /// socket cannot: `setup_clipath_watcher` watches the *parent directory*
    /// precisely because unlinking the path leaves the inode alive while the
    /// socket is open, so no `DELETE_SELF` is ever emitted. An abstract name
    /// has no parent, and `Rio::new` would refuse it.
    struct SockDir(std::path::PathBuf);
    impl SockDir {
        fn new() -> Self {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let dir = std::env::temp_dir().join(format!(
                "hh-rio-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&dir).expect("temp dir for test sockets");
            Self(dir)
        }
        fn path(&self, name: &str) -> String {
            self.0.join(name).to_string_lossy().into_owned()
        }
        fn conf(&self) -> RioConf {
            RioConf {
                name: "rio-under-test".to_string(),
                cpi_sock_path: Some(self.path("cpi.sock")),
                cli_sock_path: Some(self.path("cli.sock")),
                frrmi_sock_path: Some(self.path("frr-agent.sock")),
            }
        }
    }
    impl Drop for SockDir {
        fn drop(&mut self) {
            // Best effort: a leaked directory is untidy, not a failure, and a
            // panicking test should report its own failure rather than this.
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// Build a `Rio` whose sockets cannot collide with another test's.
    ///
    /// The returned `SockDir` must outlive the `Rio`: dropping it removes the
    /// paths the sockets are bound to.
    fn rio_for_test() -> (Rio, SockDir) {
        let dir = SockDir::new();
        let rio = Rio::new(&dir.conf()).expect("rio should build on fresh socket paths");
        (rio, dir)
    }

    /// A routing database, plus the handles that must outlive it.
    ///
    /// The readers are held rather than dropped: the tables are left-right
    /// structures, and dropping the far side while the database still refers
    /// to it is not what production does.
    struct TestDb {
        db: RoutingDb,
        #[allow(dead_code)]
        held: (
            crate::interfaces::iftablerw::IfTableReader,
            crate::fib::fibtable::FibTableReader,
            crate::atable::atablerw::AtableWriter,
        ),
    }
    fn db_for_test() -> TestDb {
        let (iftw, iftr) = IfTableWriter::new();
        let (fibtw, fibtr) = FibTableWriter::new();
        let (atablew, atabler) = AtableWriter::new();
        TestDb {
            db: RoutingDb::new(fibtw, iftw, atabler),
            held: (iftr, fibtr, atablew),
        }
    }

    /// The window `set_stale_timeout` opens: sixty seconds. Restated here so
    /// the tests below fail loudly if production ever changes it silently.
    const STALE_WINDOW: Duration = Duration::from_mins(1);

    /// Arming the timeout does not itself sweep anything.
    ///
    /// The sweep is what makes a route disappear, so an implementation that
    /// swept on arm rather than on expiry would drop every route FRR was about
    /// to re-send -- a blackhole for the length of the window.
    #[tokio::test(start_paused = true)]
    #[cfg_attr(emulated, ignore = "binds Unix domain sockets")]
    async fn arming_the_stale_timeout_sweeps_nothing() {
        let (mut rio, _dir) = rio_for_test();
        let mut t = db_for_test();

        assert!(rio.stale_timeout.is_none(), "starts unarmed");
        rio.set_stale_timeout();
        assert!(rio.stale_timeout.is_some(), "arming records a deadline");

        rio.check_stale_timeout(&mut t.db);
        assert!(
            rio.stale_timeout.is_some(),
            "a check at arm time must not consume the deadline"
        );
    }

    /// The deadline is not inclusive.
    ///
    /// `check_stale_timeout` asks `deadline < now`, so arriving exactly on the
    /// deadline leaves the window open for one more check. That is a real
    /// boundary rather than an accident of rounding, and it is only observable
    /// on a clock the test drives: on the wall clock no caller can land on the
    /// instant exactly.
    #[tokio::test(start_paused = true)]
    #[cfg_attr(emulated, ignore = "binds Unix domain sockets")]
    async fn the_stale_timeout_survives_its_own_deadline() {
        let (mut rio, _dir) = rio_for_test();
        let mut t = db_for_test();

        rio.set_stale_timeout();
        tokio::time::advance(STALE_WINDOW).await;

        rio.check_stale_timeout(&mut t.db);
        assert!(
            rio.stale_timeout.is_some(),
            "at exactly the deadline the window is still open"
        );

        tokio::time::advance(Duration::from_nanos(1)).await;
        rio.check_stale_timeout(&mut t.db);
        assert!(
            rio.stale_timeout.is_none(),
            "one nanosecond later it must close"
        );
    }

    /// The timeout fires once and disarms itself.
    ///
    /// `take_if` is what makes this true. Were it a plain comparison, every
    /// later poll would sweep again -- harmless for routes that are already
    /// gone, but it would keep re-deleting vrfs the control plane had since
    /// re-created.
    #[tokio::test(start_paused = true)]
    #[cfg_attr(emulated, ignore = "binds Unix domain sockets")]
    async fn the_stale_timeout_fires_once_and_then_disarms() {
        let (mut rio, _dir) = rio_for_test();
        let mut t = db_for_test();

        rio.set_stale_timeout();
        tokio::time::advance(STALE_WINDOW + Duration::from_secs(1)).await;

        rio.check_stale_timeout(&mut t.db);
        assert!(rio.stale_timeout.is_none(), "expiry consumes the deadline");

        // Any number of further polls are no-ops, at any distance past it.
        for _ in 0..3 {
            tokio::time::advance(STALE_WINDOW).await;
            rio.check_stale_timeout(&mut t.db);
            assert!(rio.stale_timeout.is_none(), "it must not re-arm itself");
        }
    }

    /// A timeout that was never armed never fires, however long we wait.
    #[tokio::test(start_paused = true)]
    #[cfg_attr(emulated, ignore = "binds Unix domain sockets")]
    async fn an_unarmed_stale_timeout_never_fires() {
        let (mut rio, _dir) = rio_for_test();
        let mut t = db_for_test();

        for _ in 0..4 {
            tokio::time::advance(STALE_WINDOW * 10).await;
            rio.check_stale_timeout(&mut t.db);
            assert!(rio.stale_timeout.is_none());
        }
    }

    /// A vrf the control plane finished deleting outlives the window, and only
    /// the window.
    ///
    /// This is the sweep the timeout exists to schedule, seen from the table
    /// rather than from the deadline: `Deleted` vrfs are held for the whole
    /// window and removed on expiry.
    #[tokio::test(start_paused = true)]
    #[cfg_attr(emulated, ignore = "binds Unix domain sockets")]
    async fn a_deleted_vrf_outlives_the_window_and_no_longer() {
        let (mut rio, _dir) = rio_for_test();
        let mut t = db_for_test();

        let cfg = RouterVrfConfig::new(909, "doomed");
        t.db.vrftable.add_vrf(&cfg).expect("vrf should be created");
        assert_eq!(t.db.vrftable.len(), 2, "the default vrf plus ours");
        t.db.vrftable
            .get_vrf_mut(909)
            .expect("just created")
            .set_status(VrfStatus::Deleted);

        rio.set_stale_timeout();
        tokio::time::advance(STALE_WINDOW).await;
        rio.check_stale_timeout(&mut t.db);
        assert_eq!(
            t.db.vrftable.len(),
            2,
            "a deleted vrf is held for the whole window"
        );

        tokio::time::advance(Duration::from_secs(1)).await;
        rio.check_stale_timeout(&mut t.db);
        assert_eq!(
            t.db.vrftable.len(),
            1,
            "and is swept when the window closes"
        );
    }

    // ---------------------------------------------------------------------
    // The CPI status machine.
    // ---------------------------------------------------------------------

    /// An FRR restart opens the stale window and returns the link to healthy.
    ///
    /// It also drops vrfs that were mid-deletion outright: nobody is going to
    /// finish deleting them now, and holding them would make the restarted FRR
    /// disagree with us about which vrfs exist.
    #[tokio::test(start_paused = true)]
    #[cfg_attr(emulated, ignore = "binds Unix domain sockets")]
    async fn an_frr_restart_opens_the_stale_window() {
        let (mut rio, _dir) = rio_for_test();
        let mut t = db_for_test();

        let cfg = RouterVrfConfig::new(910, "half-deleted");
        t.db.vrftable.add_vrf(&cfg).expect("vrf should be created");
        t.db.vrftable
            .get_vrf_mut(910)
            .expect("just created")
            .set_status(VrfStatus::Deleting);

        rio.cpistats.status = CpiStatus::FrrRestarted;
        rio.cpi_status_check(&mut t.db);

        assert!(
            rio.stale_timeout.is_some(),
            "the restart must open the stale window"
        );
        assert!(
            rio.cpistats.status == CpiStatus::Connected,
            "and leave the link healthy again"
        );
        assert_eq!(
            t.db.vrftable.len(),
            1,
            "a vrf that was mid-deletion goes immediately, not on the timeout"
        );
    }

    /// A refresh we cannot send is not a refresh we performed.
    ///
    /// `NeedRefresh` means *we* restarted and must ask FRR to re-send. Without
    /// a peer address there is nobody to ask, so the status deliberately stays
    /// put and the request is retried once a peer appears. Transitioning to
    /// `Connected` here would silently accept a database that was never
    /// refilled.
    #[tokio::test(start_paused = true)]
    #[cfg_attr(emulated, ignore = "binds Unix domain sockets")]
    async fn a_refresh_with_no_peer_to_ask_is_not_marked_done() {
        let (mut rio, _dir) = rio_for_test();
        let mut t = db_for_test();

        assert!(rio.cpistats.peer.is_none(), "no peer has connected");
        rio.cpistats.status = CpiStatus::NeedRefresh;
        rio.cpi_status_check(&mut t.db);

        assert!(
            rio.cpistats.status == CpiStatus::NeedRefresh,
            "with no peer to ask, the refresh stays outstanding"
        );
        assert!(
            rio.stale_timeout.is_none(),
            "and no stale window is opened: our own restart leaves nothing stale"
        );
    }

    /// The settled states do nothing at all.
    ///
    /// `cpi_status_check` runs on every pass of the IO loop, so the states it
    /// is not interested in must be free of side effects -- otherwise the loop
    /// would re-arm the stale window continuously and never sweep.
    #[tokio::test(start_paused = true)]
    #[cfg_attr(emulated, ignore = "binds Unix domain sockets")]
    async fn the_settled_cpi_states_do_nothing() {
        for status in [
            CpiStatus::NotConnected,
            CpiStatus::Connected,
            CpiStatus::Incompatible,
        ] {
            let (mut rio, _dir) = rio_for_test();
            let mut t = db_for_test();
            let cfg = RouterVrfConfig::new(911, "bystander");
            t.db.vrftable.add_vrf(&cfg).expect("vrf should be created");

            rio.cpistats.status = status;
            for _ in 0..3 {
                rio.cpi_status_check(&mut t.db);
            }

            assert!(
                rio.stale_timeout.is_none(),
                "a settled state must not open the stale window"
            );
            assert!(rio.cpistats.status == status, "nor change the status");
            assert_eq!(t.db.vrftable.len(), 2, "nor touch the vrf table");
        }
    }

    // -----------------------------------------------------------------------
    // The CPI socket, end to end.
    //
    // These drive the real IO loop through a real unix datagram socket: the
    // test binds the other end and speaks dplane-rpc at it, exactly as FRR's
    // plugin does. Nothing is stubbed, so the poller, the readiness handling
    // and the reply path are under test rather than around it.
    // -----------------------------------------------------------------------

    /// The peer side of the CPI socket -- what FRR's dplane plugin would be.
    struct CpiPeer {
        sock: UnixDatagram,
        rio: std::os::unix::net::SocketAddr,
    }
    impl CpiPeer {
        fn attach(dir: &SockDir) -> Self {
            let sock = UnixDatagram::bind(dir.path("peer.sock")).expect("peer sock should bind");
            sock.set_read_timeout(Some(Duration::from_secs(10)))
                .expect("read timeout should be settable");
            let _ = &sock;
            let rio = std::os::unix::net::SocketAddr::from_pathname(dir.path("cpi.sock"))
                .expect("rio's cpi path should be addressable");
            Self { sock, rio }
        }
        fn send(&self, msg: &RpcMsg) {
            dplane_rpc::socks::send_msg(&self.sock, msg, &self.rio).expect("send to rio");
        }
        fn send_raw(&self, bytes: &[u8]) {
            self.sock
                .send_to_addr(bytes, &self.rio)
                .expect("raw send to rio");
        }
        /// Assert that nothing comes back within `patience`.
        fn expect_silence(&self, patience: Duration) {
            self.sock
                .set_read_timeout(Some(patience))
                .expect("read timeout should be settable");
            let mut buf = [0u8; 4096];
            let outcome = self.sock.recv_from(&mut buf);
            self.sock
                .set_read_timeout(Some(Duration::from_secs(10)))
                .expect("read timeout should be settable");
            assert!(
                outcome.is_err(),
                "expected no answer at all, got {} bytes",
                outcome.map_or(0, |(len, _)| len)
            );
        }
        /// Wait for one message back, failing rather than hanging.
        fn recv(&self) -> RpcMsg {
            let mut buf = [0u8; 4096];
            let (len, _) = self
                .sock
                .recv_from(&mut buf)
                .expect("rio should answer within the read timeout");
            let mut data = bytes::Bytes::copy_from_slice(&buf[..len]);
            RpcMsg::decode(&mut data).expect("rio should answer with a well-formed message")
        }
        fn connect_request(seqn: u64, pid: u32) -> RpcMsg {
            RpcMsg::Request(RpcRequest::new(RpcOp::Connect, seqn).set_object(
                RpcObject::ConnectInfo(ConnectInfo {
                    pid,
                    name: "test-plugin".to_string(),
                    verinfo: VerInfo::default(),
                    synt: 0,
                }),
            ))
        }
        fn route_request(op: RpcOp, seqn: u64) -> RpcMsg {
            RpcMsg::Request(
                RpcRequest::new(op, seqn).set_object(RpcObject::IpRoute(IpRoute {
                    prefix: "10.0.0.0".parse().expect("literal"),
                    prefix_len: 24,
                    vrfid: 0,
                    tableid: 254,
                    rtype: RouteType::Bgp,
                    distance: 20,
                    metric: 100,
                    nhops: vec![],
                })),
            )
        }
    }

    /// A running IO loop, stopped when the test ends.
    struct RunningRio {
        handle: RioHandle,
        dir: SockDir,
        /// Held, not dropped: see `TestDb::held`.
        #[allow(dead_code)]
        held: (
            crate::interfaces::iftablerw::IfTableReader,
            crate::fib::fibtable::FibTableReader,
            crate::atable::atablerw::AtableWriter,
        ),
    }
    impl RunningRio {
        fn start() -> Self {
            let dir = SockDir::new();
            let (iftw, iftr) = IfTableWriter::new();
            let (fibtw, fibtr) = FibTableWriter::new();
            let (atablew, atabler) = AtableWriter::new();
            let handle = start_rio(
                &test_router_subsystem(),
                &dir.conf(),
                fibtw,
                iftw,
                atabler,
                None,
            )
            .expect("rio should start on fresh socket paths");
            Self {
                handle,
                dir,
                held: (iftr, fibtr, atablew),
            }
        }
    }
    impl RunningRio {
        /// Start attending the CPI, as applying a configuration does.
        ///
        /// Until this happens the CPI socket is registered `Interest::PRIORITY`
        /// -- out-of-band data only, which a unix datagram socket never carries
        /// -- so the loop is deaf to it by construction rather than by a flag it
        /// has to remember to check.
        fn attend_cpi(&self) {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("a runtime to drive the ctl channel")
                .block_on(self.handle.get_ctl_tx().unlock())
                .expect("the cpi should unlock");
        }
    }
    impl Drop for RunningRio {
        fn drop(&mut self) {
            let _ = self.handle.finish();
        }
    }

    /// The CPI is deaf until a configuration says otherwise.
    ///
    /// A dataplane that restarts keeps receiving updates over the CPI until
    /// FRR notices and re-syncs. Acting on them would build a routing table out
    /// of a fragment; ignoring them politely would tell the plugin they were
    /// delivered. So the loop does not answer at all, and the plugin caches and
    /// retries.
    ///
    /// The mechanism is worth knowing about before touching this registration:
    /// the socket is registered `Interest::PRIORITY`, which mio maps to
    /// `EPOLLPRI` alone. A unix datagram socket never carries out-of-band data,
    /// so no readable event is ever raised -- deafness by construction rather
    /// than by a flag somewhere in the dispatch. Registering it `READABLE`
    /// "to fix a bug" would silently undo the feature, and every assertion
    /// below would still pass.
    #[test]
    #[cfg_attr(emulated, ignore = "binds Unix domain sockets")]
    fn the_cpi_is_not_attended_until_it_is_unlocked() {
        let rio = RunningRio::start();
        let peer = CpiPeer::attach(&rio.dir);

        peer.send(&CpiPeer::connect_request(1, 4242));
        peer.expect_silence(Duration::from_secs(2));

        // Deafness defers rather than drops: the datagram sat in the socket's
        // receive queue the whole time, and unlocking serves it. Worth knowing,
        // because it means unlocking replays whatever arrived while we were not
        // listening -- bounded by SO_RCVBUF, not by anything this code decides.
        // The `last_pid` guard in `handle_request` is what keeps that safe:
        // anything but a connect is refused until a connect has been seen.
        rio.attend_cpi();
        let RpcMsg::Response(deferred) = peer.recv() else {
            panic!("an attended cpi should answer what it deferred");
        };
        assert_eq!(
            deferred.seqn, 1,
            "the request sent while deaf is served, not discarded"
        );
        assert_eq!(deferred.rescode, RpcResultCode::Ok);

        // And it keeps answering from then on.
        peer.send(&CpiPeer::connect_request(2, 4242));
        let RpcMsg::Response(resp) = peer.recv() else {
            panic!("an attended cpi should keep answering");
        };
        assert_eq!(resp.seqn, 2);
        assert_eq!(resp.rescode, RpcResultCode::Ok);
    }

    /// A connect is answered, which is the whole CPI round trip.
    ///
    /// Readiness on the socket, the read, the decode, the dispatch and the
    /// addressed reply all have to work for this to return: the reply comes
    /// back to the peer address the datagram arrived from, so nothing here is
    /// satisfied by the loop merely running.
    #[test]
    #[cfg_attr(emulated, ignore = "binds Unix domain sockets")]
    fn a_connect_over_the_cpi_socket_is_answered() {
        let rio = RunningRio::start();
        let peer = CpiPeer::attach(&rio.dir);
        rio.attend_cpi();

        peer.send(&CpiPeer::connect_request(1, 4242));

        let RpcMsg::Response(resp) = peer.recv() else {
            panic!("a request should draw a response");
        };
        assert_eq!(resp.op, RpcOp::Connect);
        assert_eq!(resp.seqn, 1, "the response is matched to the request");
        assert_eq!(resp.rescode, RpcResultCode::Ok);
        assert!(
            matches!(resp.objs.first(), Some(RpcObject::ConnectInfo(_))),
            "a connect is answered with the sync token, not bare"
        );
    }

    /// A request that arrives before any connect is refused, not applied.
    ///
    /// The plugin always connects first, so a request without one means *we*
    /// restarted and lost the state. Applying it would build a routing table
    /// out of whatever fragment happened to be in flight; the plugin has to
    /// push the whole state again instead.
    ///
    /// This deliberately sends a **deletion**. An addition is refused twice
    /// over -- once here and once by the no-configuration guard below it --
    /// and both refusals are spelled `Ignored`, so an addition cannot tell the
    /// two apart. Removing this guard entirely leaves an `Add` test passing.
    /// A deletion is allowed through the no-configuration guard, so it reaches
    /// this one and nothing else.
    #[test]
    #[cfg_attr(emulated, ignore = "binds Unix domain sockets")]
    fn a_request_before_any_connect_is_ignored() {
        let rio = RunningRio::start();
        let peer = CpiPeer::attach(&rio.dir);
        rio.attend_cpi();

        peer.send(&CpiPeer::route_request(RpcOp::Del, 7));

        let RpcMsg::Response(resp) = peer.recv() else {
            panic!("a request should draw a response");
        };
        assert_eq!(resp.seqn, 7);
        assert_eq!(
            resp.rescode,
            RpcResultCode::Ignored,
            "a route withdrawal offered before a connect must not be acted on"
        );
    }

    /// With no configuration, additions are refused but deletions are not.
    ///
    /// A deletion can only ever remove state we should not be holding, so it
    /// is safe without a config; an addition would install a route into a
    /// table nobody has described yet.
    #[test]
    #[cfg_attr(emulated, ignore = "binds Unix domain sockets")]
    fn without_a_config_additions_are_refused_and_deletions_are_not() {
        let rio = RunningRio::start();
        let peer = CpiPeer::attach(&rio.dir);
        rio.attend_cpi();

        peer.send(&CpiPeer::connect_request(1, 4242));
        let RpcMsg::Response(connected) = peer.recv() else {
            panic!("connect should be answered");
        };
        assert_eq!(connected.rescode, RpcResultCode::Ok);

        peer.send(&CpiPeer::route_request(RpcOp::Add, 2));
        let RpcMsg::Response(added) = peer.recv() else {
            panic!("add should be answered");
        };
        assert_eq!(
            added.rescode,
            RpcResultCode::Ignored,
            "an addition with no config is refused"
        );

        peer.send(&CpiPeer::route_request(RpcOp::Del, 3));
        let RpcMsg::Response(deleted) = peer.recv() else {
            panic!("del should be answered");
        };
        assert_ne!(
            deleted.rescode,
            RpcResultCode::Ignored,
            "a deletion with no config is allowed through, to wipe stale state"
        );
    }

    /// A datagram that is not a message at all draws a notification.
    ///
    /// The loop must not treat a decode failure as a reason to stop reading
    /// the socket: the peer is told, the failure is counted, and the next
    /// datagram is still served.
    #[test]
    #[cfg_attr(emulated, ignore = "binds Unix domain sockets")]
    fn a_malformed_datagram_draws_a_notification_and_does_not_wedge_the_loop() {
        let rio = RunningRio::start();
        let peer = CpiPeer::attach(&rio.dir);
        rio.attend_cpi();

        peer.send_raw(&[0xff; 32]);
        assert!(
            matches!(peer.recv(), RpcMsg::Notification(_)),
            "garbage should be answered with a notification"
        );

        // The socket is still being served afterwards.
        peer.send(&CpiPeer::connect_request(9, 4242));
        let RpcMsg::Response(resp) = peer.recv() else {
            panic!("the loop should still answer after a decode failure");
        };
        assert_eq!(resp.seqn, 9);
        assert_eq!(resp.rescode, RpcResultCode::Ok);
    }

    /// A CLI client: connects to rio's cli socket and asks it something.
    fn ask_the_cli(dir: &SockDir, tag: &str) -> CliResponse {
        let sock = UnixDatagram::bind(dir.path(&format!("cli-client-{tag}.sock")))
            .expect("cli client sock should bind");
        sock.connect(dir.path("cli.sock"))
            .expect("rio's cli socket should be connectable");
        sock.set_read_timeout(Some(Duration::from_secs(10)))
            .expect("read timeout should be settable");
        CliRequest::new(CliAction::ShowCpiStats, RequestArgs::default())
            .send(&sock)
            .expect("cli request should send");
        CliResponse::recv_sync(&sock).expect("rio should answer the cli within the timeout")
    }

    /// The CLI keeps working when its socket path is removed underneath it.
    ///
    /// Unlinking the path only removes the directory entry -- the socket stays
    /// open and keeps serving anyone already holding it, while every new client
    /// finds nothing there. That is why the watcher is on the parent directory
    /// rather than the file: no `DELETE_SELF` is ever emitted for an open
    /// socket.
    ///
    /// The assertion is that a *new client is served*, not that a path exists.
    /// Rebinding without re-registering the new socket with the poller would
    /// put a file back and answer nobody, and a test that only stats the path
    /// cannot tell those apart.
    #[test]
    #[cfg_attr(emulated, ignore = "binds Unix domain sockets")]
    fn the_cli_survives_having_its_socket_path_removed() {
        let rio = RunningRio::start();
        let cli = rio.dir.path("cli.sock");

        let before = ask_the_cli(&rio.dir, "before");
        assert_eq!(
            before.request.action,
            CliAction::ShowCpiStats,
            "the cli answers before the path is disturbed"
        );

        std::fs::remove_file(&cli).expect("the path should be removable");

        // The watcher is edge-triggered through the poller, so this is prompt
        // rather than a poll interval; the deadline is generous only so that a
        // loaded machine does not fail the run.
        let deadline = clock::now() + Duration::from_secs(10);
        while clock::now() < deadline && !Path::new(&cli).exists() {
            thread::sleep(Duration::from_millis(20));
        }
        assert!(
            Path::new(&cli).exists(),
            "the loop should notice the unlink and rebind"
        );

        let after = ask_the_cli(&rio.dir, "after");
        assert_eq!(
            after.request.action,
            CliAction::ShowCpiStats,
            "and the rebound socket must actually be served, not merely exist"
        );
    }

    // -----------------------------------------------------------------------
    // The frrmi lifecycle.
    //
    // The frrmi does not talk to FRR. It talks to `frr-agent`, a Hedgehog
    // component that sits beside FRR and applies configuration to it, over a
    // Hedgehog wire format. So the stand-in below impersonates our own agent
    // and nothing else: no FRR, no bgpd, no zebra, and nothing that would need
    // one to run.
    //
    // The wire format itself is already covered in `frr::frrmi` against a
    // `UnixStream::pair()`. What is not covered, and what these reach, is the
    // loop's lifecycle around it -- connect, disconnect, restart.
    // -----------------------------------------------------------------------

    /// A stand-in for `frr-agent`: something listening at the frrmi path.
    struct FakeAgent {
        listener: UnixListener,
    }
    impl FakeAgent {
        fn listening_at(dir: &SockDir) -> Self {
            let listener =
                UnixListener::bind(dir.path("frr-agent.sock")).expect("the agent should bind");
            listener
                .set_nonblocking(true)
                .expect("the agent should be pollable");
            Self { listener }
        }
        /// Wait for the loop to connect, failing rather than hanging.
        fn accept(&self, expectation: &str) -> UnixStream {
            let deadline = clock::now() + Duration::from_secs(10);
            loop {
                match self.listener.accept() {
                    Ok((stream, _)) => return stream,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(clock::now() < deadline, "rio never {expectation}");
                        thread::sleep(Duration::from_millis(20));
                    }
                    Err(e) => panic!("the agent could not accept: {e}"),
                }
            }
        }
    }

    /// The loop keeps trying until the agent turns up.
    ///
    /// Rio starts here with nothing listening, so its first connect fails.
    /// That is the normal case rather than an edge one -- the dataplane and
    /// the FRR container come up in whatever order they come up in -- and a
    /// loop that gave up after the first refusal would need a restart to
    /// recover.
    #[test]
    #[cfg_attr(emulated, ignore = "binds Unix domain sockets")]
    fn the_loop_connects_to_the_agent_whenever_it_appears() {
        let rio = RunningRio::start();
        let agent = FakeAgent::listening_at(&rio.dir);
        let _conn = agent.accept("connected to an agent that appeared after it started");
    }

    /// The loop reconnects when the agent goes away.
    ///
    /// `frr-agent` restarts whenever FRR does, which is the very moment the
    /// dataplane most needs to push configuration back. A loop that held the
    /// dead socket would go on believing it had a link and quietly stop
    /// applying anything.
    #[test]
    #[cfg_attr(emulated, ignore = "binds Unix domain sockets")]
    fn the_loop_reconnects_when_the_agent_goes_away() {
        let rio = RunningRio::start();
        let agent = FakeAgent::listening_at(&rio.dir);

        let first = agent.accept("connected to the agent");
        drop(first); // the agent restarts

        let _second = agent.accept("reconnected after the agent left");
    }

    /// A response the agent could not have meant restarts the link.
    ///
    /// The first four octets are an announced length, so a burst of `0xff`
    /// announces a message of absurd size. `frr::frrmi` refuses it; this
    /// asserts what the loop does *with* that refusal, which is to rebuild the
    /// link rather than to keep reading a stream it has lost its place in.
    ///
    /// The connection is deliberately held open, so the restart can only have
    /// come from the refusal and not from an end-of-file.
    #[test]
    #[cfg_attr(emulated, ignore = "binds Unix domain sockets")]
    fn nonsense_from_the_agent_restarts_the_link() {
        let rio = RunningRio::start();
        let agent = FakeAgent::listening_at(&rio.dir);

        let mut first = agent.accept("connected to the agent");
        first
            .write_all(&[0xff; 64])
            .expect("the agent should be able to write nonsense");

        let _second = agent.accept("rebuilt the link after a message it could not read");
        drop(first);
    }
}
