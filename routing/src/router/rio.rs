// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Router IO, which includes the control-plane interface CPI and the FRR management interface (FRRMI)

use crate::atable::atablerw::AtableReader;
use crate::cli::handler::handle_cli_request;
use crate::config::{FrrConfig, RouterConfig};
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
use config::{GenId, GwConfigMeta, ValidatedGwConfig};
use dplane_rpc::socks::RpcCachedSock;
use lifecycle::{CancellationToken, Subsystem};

use mio::unix::SourceFd;
use mio::{Events, Interest, Poll, Token};

use concurrency::sync::Arc;
use concurrency::thread::{self, JoinHandle};
use nix::sys::socket::{getsockopt, setsockopt, sockopt::SndBuf};
use std::fs;
use std::os::fd::AsRawFd;
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
        RouterCtlSender::new(self.ctl.clone())
    }
}

pub(crate) struct RioConf {
    pub name: String,
    pub cpi_sock_path: Option<String>,
    pub cli_sock_path: Option<String>,
    pub frrmi_sock_path: Option<String>,
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

fn open_cli_sock(path: &String) -> Result<UnixDatagram, RouterError> {
    let sock = open_unix_sock(path)?;
    setsockopt(&sock, SndBuf, &CLI_RX_BUFF_SIZE)
        .map_err(|_| RouterError::Internal("Failure setting snd buffer size"))?;
    if let Ok(size) = getsockopt(&sock, SndBuf) {
        debug!("Cli sock send buffer set to {size}");
    }
    Ok(sock)
}

pub(crate) const CPSOCK: Token = Token(0);
pub(crate) const CLISOCK: Token = Token(1);
pub(crate) const FRRMISOCK: Token = Token(2);
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
    pub(crate) cpistats: CpiStats,
    stale_timeout: Option<Instant>,
    reconcile_timeout: Option<Instant>,
    pub(crate) gwconfig: Option<Arc<ValidatedGwConfig>>,
    pub(crate) cfg_history: Arc<Vec<GwConfigMeta>>,
    pub(crate) cli_cache: IoCache,
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
            cpistats: CpiStats::new(),
            stale_timeout: None,
            reconcile_timeout: None,
            gwconfig: None,
            cfg_history: Arc::from(vec![]),
            cli_cache: IoCache::new(),
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
    /// How often [`Rio::reconcile_frr_config`] re-checks (and, on drift, re-pushes) the FRR config.
    const RECONCILE_INTERVAL: Duration = Duration::from_secs(5);

    /// Request to reapply the last configuration
    pub(crate) fn reapply_frr_config(&mut self, db: &RoutingDb) {
        if let Some(rconfig) = &db.config {
            if let Some(frr_cfg) = rconfig.get_frr_config() {
                self.request_frr_config(rconfig.genid(), frr_cfg.clone());
            }
        }
    }

    /// Reconcile FRR's configuration with the intended one.
    ///
    /// The genid the dataplane records as "applied" is set when the FRR config is *queued* on the
    /// frrmi, not when frr-agent confirms it. Any failure on the frrmi unix socket after that point
    /// (timeout on a slow reload, partial write, peer reset, a reload that returns an error) leaves
    /// FRR without the intended config while the dataplane believes it was applied, with nothing to
    /// re-drive it. This periodic check compares the genid frr-agent actually confirmed
    /// (`frrmi.applied_cfg`, set only on a successful response) against the intended one (`db.config`)
    /// and re-pushes on mismatch, so a dropped/failed delivery self-heals without a process restart.
    ///
    /// It only acts when the frrmi is connected and idle (no request in flight or queued) so it never
    /// races a delivery that is still in progress.
    pub(crate) fn reconcile_frr_config(&mut self, db: &RoutingDb) {
        /* throttle: only check periodically to bound the re-push rate on a persistent failure */
        if self.reconcile_timeout.is_some_and(|t| t > Instant::now()) {
            return;
        }
        self.reconcile_timeout = Instant::now().checked_add(Self::RECONCILE_INTERVAL);

        let intended = intended_frr_genid(db.config.as_ref());
        let applied = self.frrmi.get_applied_cfg().map(|cfg| cfg.genid);
        if frr_resync_needed(
            self.frrmi.has_sock(),
            self.frrmi.has_pending(),
            intended,
            applied,
        ) {
            warn!(
                "FRR config out of sync (frr-agent confirmed gen {applied:?}, intended gen {intended:?}); re-pushing..."
            );
            self.reapply_frr_config(db);
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
        self.stale_timeout = Instant::now().checked_add(duration);
    }
    fn check_stale_timeout(&mut self, db: &mut RoutingDb) {
        if self
            .stale_timeout
            .take_if(|t| *t < Instant::now())
            .is_some()
        {
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

/// The genid of the FRR config the dataplane intends FRR to have, if any.
///
/// Mirrors `handle_configure`, which pushes to frr-agent only when the router config actually carries
/// an FRR config: a config whose `get_frr_config()` is `None` has nothing to push, so it yields `None`
/// here and the reconcile loop neither warns nor performs a no-op re-push for it.
#[must_use]
fn intended_frr_genid(config: Option<&RouterConfig>) -> Option<GenId> {
    config
        .filter(|cfg| cfg.get_frr_config().is_some())
        .map(RouterConfig::genid)
}

/// Decide whether FRR's configuration must be re-pushed to frr-agent.
///
/// Returns true only when all of the following hold:
/// * `connected` — the frrmi has a live socket to frr-agent;
/// * `!pending` — no request is in flight or queued (so we never race an in-progress delivery);
/// * `intended` is a real, non-blank config (`Some(genid)` with `genid != 0`); and
/// * frr-agent has not confirmed that exact genid (`applied != Some(intended)`).
///
/// `applied` is the genid frr-agent actually acknowledged (`Frrmi::applied_cfg`, set only on a
/// successful response), so a delivery that was queued-but-never-confirmed shows up here as a
/// mismatch and triggers a re-push.
#[must_use]
fn frr_resync_needed(
    connected: bool,
    pending: bool,
    intended: Option<GenId>,
    applied: Option<GenId>,
) -> bool {
    match intended {
        Some(intended) if intended != 0 => connected && !pending && applied != Some(intended),
        _ => false,
    }
}

#[allow(clippy::missing_errors_doc, clippy::too_many_lines)]
pub(crate) fn start_rio(
    router: &Subsystem,
    conf: &RioConf,
    fibtw: FibTableWriter,
    iftw: IfTableWriter,
    atabler: AtableReader,
    cli_sources: Option<CliSources>,
) -> Result<RioHandle, RouterError> {
    let mut rio = Rio::new(conf)?;
    let ctl_tx = rio.ctl_tx.clone();
    let cli_sources = cli_sources.unwrap_or_default();
    let cancel = router.cancel_token();
    let loop_cancel = cancel.clone();
    let guard_subsystem = router.clone();

    /* router IO loop */
    let rio_loop = move || {
        // Drop-guard so panic-unwind or unexpected loop exit trips
        // report_fatal.
        struct ExitGuard {
            subsystem: Subsystem,
        }
        impl Drop for ExitGuard {
            fn drop(&mut self) {
                if self.subsystem.is_cancelled() {
                    return;
                }
                let reason = if std::thread::panicking() {
                    "RIO thread panicked"
                } else {
                    "RIO thread exited unexpectedly"
                };
                self.subsystem.report_fatal(reason);
            }
        }
        let _guard = ExitGuard {
            subsystem: guard_subsystem,
        };

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

            /* events on unix sockets */
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
                    _ => {}
                }
            }

            /* check stale timeout. If expired, remove stale routes */
            rio.check_stale_timeout(&mut db);

            /* re-push the FRR config if frr-agent's confirmed gen drifted from the intended one */
            rio.reconcile_frr_config(&db);

            /* handle control-channel messages */
            handle_ctl_msg(&mut rio, &mut db);
        }
    };
    let handle = thread::Builder::new()
        .name("routerIO".to_string())
        .spawn(rio_loop)
        .map_err(|_| RouterError::Internal("Failure spawning thread"))?;

    Ok(RioHandle {
        cancel,
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
    use crate::router::rio::{Rio, RioConf, start_rio};
    use concurrency::thread;
    use lifecycle::{CancellationToken, Subsystem};
    use std::time::Duration;

    fn test_router_subsystem() -> Subsystem {
        Subsystem::new("router", CancellationToken::new())
    }

    #[test]
    #[cfg_attr(emulated, ignore = "binds Unix domain sockets at /tmp/hh_*.sock")]
    fn test_rio_ctl() {
        let cpi_bind_addr = "/tmp/hh_dataplane.sock".to_string();
        let cli_bind_addr = "/tmp/hh_cli.sock".to_string();
        let frra_path = "/tmp/frr-agent.sock".to_string();
        let _ = std::fs::remove_file(&cpi_bind_addr);

        /* Build cpi configuration */
        let conf = RioConf {
            name: "test-routter".to_string(),
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

    /// Exhaustively cover the decision the reconcile loop makes. No sockets or timers involved.
    #[test]
    fn frr_resync_needed_decision() {
        use crate::router::rio::frr_resync_needed;

        // not connected to frr-agent: never re-push (would just fail)
        assert!(!frr_resync_needed(false, false, Some(7), None));
        // a delivery is in flight/queued: leave it alone, it will settle
        assert!(!frr_resync_needed(true, true, Some(7), None));
        // no intended config yet: nothing to converge to
        assert!(!frr_resync_needed(true, false, None, None));
        // blank (genid 0) config: nothing meaningful to push
        assert!(!frr_resync_needed(true, false, Some(0), None));
        // connected + idle + real config, frr-agent confirmed nothing: re-push
        assert!(frr_resync_needed(true, false, Some(7), None));
        // connected + idle, frr-agent confirmed an older gen than intended: re-push
        assert!(frr_resync_needed(true, false, Some(7), Some(6)));
        // already in sync (frr-agent confirmed the intended gen): do nothing
        assert!(!frr_resync_needed(true, false, Some(7), Some(7)));
    }

    /// Only a router config that actually carries an FRR config counts as "intended" — otherwise the
    /// reconcile loop would warn and no-op every interval (mirrors the guard in `handle_configure`).
    #[test]
    fn intended_frr_genid_requires_frr_config() {
        use crate::config::RouterConfig;
        use crate::router::rio::intended_frr_genid;

        // no config at all
        assert_eq!(intended_frr_genid(None), None);
        // config present but without an FRR config: nothing to push
        let bare = RouterConfig::new(7);
        assert_eq!(intended_frr_genid(Some(&bare)), None);
        // config carrying an FRR config: its genid
        let mut full = RouterConfig::new(7);
        full.set_frr_config("! frr config".to_string());
        assert_eq!(intended_frr_genid(Some(&full)), Some(7));
    }

    /// End-to-end: a connected, idle frrmi whose last-confirmed gen lags the intended config gets a
    /// re-push queued by the reconcile loop — the self-heal for a dropped/failed FRRMI delivery.
    #[test]
    #[cfg_attr(emulated, ignore = "binds Unix domain sockets at /tmp/hh_*.sock")]
    fn reconcile_repushes_when_frr_out_of_sync() {
        use crate::config::RouterConfig;
        use crate::routingdb::RoutingDb;

        let dp = "/tmp/hh_recon_dataplane.sock".to_string();
        let cli = "/tmp/hh_recon_cli.sock".to_string();
        let frra = "/tmp/hh_recon_frr-agent.sock".to_string();
        let _ = std::fs::remove_file(&dp);
        let _ = std::fs::remove_file(&cli);
        let _ = std::fs::remove_file(&frra);

        // A listener so frrmi_connect() establishes a live socket (has_sock() == true).
        let listener =
            std::os::unix::net::UnixListener::bind(&frra).expect("bind fake frr-agent sock");

        let conf = RioConf {
            name: "test-reconcile".to_string(),
            cpi_sock_path: Some(dp.clone()),
            cli_sock_path: Some(cli.clone()),
            frrmi_sock_path: Some(frra.clone()),
        };
        let (iftw, _iftr) = IfTableWriter::new();
        let (fibtw, _fibtr) = FibTableWriter::new();
        let (_atablew, atabler) = AtableWriter::new();

        let mut rio = Rio::new(&conf).expect("create rio");
        rio.frrmi_connect();
        assert!(
            rio.frrmi.has_sock(),
            "frrmi should be connected to the listener"
        );

        let mut db = RoutingDb::new(fibtw, iftw, atabler);
        let mut cfg = RouterConfig::new(7);
        cfg.set_frr_config("! frr config for gen 7".to_string());
        db.set_config(cfg);

        // frr-agent has confirmed nothing yet while gen 7 is intended -> out of sync.
        assert!(!rio.frrmi.has_pending());
        rio.reconcile_frr_config(&db);
        assert!(
            rio.frrmi.has_pending(),
            "reconcile should queue a re-push when the confirmed gen lags the intended gen",
        );

        drop(listener);
        let _ = std::fs::remove_file(&dp);
        let _ = std::fs::remove_file(&cli);
        let _ = std::fs::remove_file(&frra);
    }
}
