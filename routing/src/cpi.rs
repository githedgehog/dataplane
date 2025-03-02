// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Control-plane interface (CPI)

const DEFAULT_DP_UX_PATH: &str = "/var/run/frr/hh_dataplane.sock";
const DEFAULT_DP_UX_PATH_CLI: &str = "/tmp/dataplane_ctl.sock";

use crate::cli::handle_cli_request;
use crate::routingdb::RoutingDb;
use cli::cliproto::CliRequest;
use cli::cliproto::CliSerialize;
use dplane_rpc::log::Level;
use dplane_rpc::socks::RpcCachedSock;
use std::fs;
use std::os::unix::fs::PermissionsExt;

use mio::unix::SourceFd;
use mio::{Events, Interest, Poll, Token};
use std::sync::Arc;

use crate::cpi_process::process_rx_data;
use crate::errors::RouterError;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixDatagram;
use std::str::FromStr;
use std::sync::mpsc::Sender;
use std::sync::mpsc::TryRecvError;
use std::sync::mpsc::channel;
use std::thread::{self, JoinHandle};
use std::time::Duration;
use tracing::{debug, error, info};

#[allow(unused)]
pub enum CpiCtlMsg {
    Finish,
}

pub struct CpiHandle {
    pub ctl: Sender<CpiCtlMsg>,
    pub handle: JoinHandle<()>,
}
#[allow(unused)]
impl CpiHandle {
    fn finish(self) -> Result<(), RouterError> {
        debug!("Requesting CPI to stop..");
        self.ctl
            .send(CpiCtlMsg::Finish)
            .map_err(|_| RouterError::CpiFailure)?;

        debug!("Waiting for CPI to terminate..");
        self.handle.join().map_err(|_| RouterError::CpiFailure)?;
        debug!("CPI ended successfully");
        Ok(())
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
        .map_err(|_| RouterError::Internal)?;
    Ok(sock)
}

#[allow(unused)]
pub fn start_cpi(conf: &CpiConf, db: Arc<RoutingDb>) -> Result<CpiHandle, RouterError> {
    /* get desired loglevel and set it */
    let loglevel = conf
        .rpc_loglevel
        .as_ref()
        .map(|level| Level::from_str(level).expect("Wrong log level"))
        .unwrap_or_else(|| Level::DEBUG);

    /* set loglevel for RPC */
    //    let mut cfg = LogConfig::new(loglevel);
    //    cfg.display_thread_names = true;
    //    init_dplane_rpc_log(&cfg);

    info!("Launching CPI, loglevel is {:?}....", loglevel);

    /* path to bind to for routing function */
    let cp_sock_path = conf
        .cpi_sock_path
        .as_ref()
        .map_or_else(|| DEFAULT_DP_UX_PATH.to_owned(), |path| path.to_owned());

    /* path to bind to for cli */
    let cli_sock_path = conf
        .cli_sock_path
        .as_ref()
        .map_or_else(|| DEFAULT_DP_UX_PATH_CLI.to_owned(), |path| path.to_owned());

    /* create unix sock for routing function and bind it */
    let cpsock = open_unix_sock(&cp_sock_path)?;

    /* create unix sock for cli and bind it */
    let clisock = open_unix_sock(&cli_sock_path)?;

    /* internal ctl channel */
    let (tx, mut rx) = channel::<CpiCtlMsg>();

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
    let mut poller = Poll::new().expect("Failed to create poller");
    poller
        .registry()
        .register(&mut ev_cpsock, CPSOCK, Interest::READABLE)
        .expect("Failed to register CPI sock");
    poller
        .registry()
        .register(&mut ev_clisock, CLISOCK, Interest::READABLE)
        .expect("Failed to register CLI sock");

    let cpi_loop = move || {
        info!("CPI Listening at {}.", cp_sock_path);
        info!("CLI Listening at {}.", cli_sock_path);
        info!("Entering main IO loop....");
        let mut events = Events::with_capacity(64);
        let mut buf = vec![0; 1024];
        let mut run = true;

        while run {
            poller
                .poll(&mut events, Some(Duration::from_secs(1)))
                .expect("Poll error");

            /* control channel */
            match rx.try_recv() {
                Ok(CpiCtlMsg::Finish) => {
                    info!("Got request to shutdown. Au revoir ...");
                    run = false
                }
                Err(TryRecvError::Empty) => {}
                Err(e) => {
                    error!("Error receiving from ctl channel {e:?}")
                }
            }

            /* events on unix sockets */
            for event in &events {
                match event.token() {
                    CPSOCK => {
                        while event.is_readable() {
                            if let Ok((len, peer)) = cached_sock.recv_from(buf.as_mut_slice()) {
                                process_rx_data(&mut cached_sock, &peer, &buf[..len], &db);
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
    Ok(CpiHandle { ctl: tx, handle })
}

#[allow(unused)]
#[cfg(test)]
#[allow(dead_code)]
mod tests {
    use crate::cpi::{CpiConf, start_cpi};
    use crate::errors::RouterError;
    use crate::interface::{IfTable, Interface};
    use crate::rmac::RmacStore;
    use crate::routingdb::{RoutingDb, VrfTable};
    use crate::vrf::Vrf;
    use std::sync::Arc;
    use std::sync::RwLock;
    use std::thread;
    use std::time::Duration;
    #[test]
    fn test_cpi_ctl() {
        /* Build cpi configuration */
        let conf = CpiConf {
            rpc_loglevel: Some("debug".to_string()),
            cpi_sock_path: Some("/tmp/hh_dataplane.sock".to_string()),
            cli_sock_path: None,
        };

        /* create routing database */
        let db = Arc::new(RoutingDb::new());

        /* start CPI */
        let cpi = start_cpi(&conf, db.clone());

        if let Ok(mut iftable) = db.iftable.write() {
            let eth0 = Interface::new("eth0", 100);
            let eth1 = Interface::new("eth1", 200);
            iftable.add_interface(eth0);
            iftable.add_interface(eth1);
        }

        let cpi = cpi.expect("Should succeed");
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

        /* create routing database */
        let db = Arc::new(RoutingDb::new());

        /* start CPI */
        let cpi = start_cpi(&conf, db.clone());
        assert!(cpi.is_err_and(|e| e == RouterError::InvalidSockPath));
    }
}
