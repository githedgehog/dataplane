// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Module that implements a router instance

pub(crate) mod cpi;
pub(crate) mod ctl;
#[macro_use]
pub(crate) mod revent;
pub(crate) mod rio;
pub(crate) mod rpc_adapt;

use derive_builder::Builder;
use std::fmt::Display;
use std::path::PathBuf;
use tracing::{debug, error};

// sockets
use std::net::SocketAddr;

// keep async task handle for BMP
use tokio::task::JoinHandle;

use crate::atable::atablerw::{AtableReader, AtableReaderFactory};
use crate::atable::resolver::AtResolver;
use crate::bmp;
use crate::errors::RouterError;
use crate::fib::fibtable::{FibTableReader, FibTableReaderFactory, FibTableWriter};
use crate::interfaces::iftablerw::{IfTableReader, IfTableReaderFactory, IfTableWriter};
use crate::router::ctl::RouterCtlSender;
use crate::router::rio::{RioConf, RioHandle, start_rio};

use args::DEFAULT_DP_UX_PATH;
use args::DEFAULT_DP_UX_PATH_CLI;
use args::DEFAULT_FRR_AGENT_PATH;

// mandatory dataplane status handle
use concurrency::sync::Arc;
use config::internal::status::DataplaneStatus;
use tokio::sync::RwLock;

#[derive(Clone, Debug)]
pub struct BmpServerParams {
    /// TCP bind address for the BMP listener
    pub bind_addr: SocketAddr,
    /// Periodic stats emit interval (milliseconds)
    pub stats_interval_ms: u64,
    /// Optional reconnect/backoff lower bound (milliseconds)
    pub min_retry_ms: Option<u64>,
    /// Optional reconnect/backoff upper bound (milliseconds)
    pub max_retry_ms: Option<u64>,
}

/// Struct to configure router object. N.B we derive a builder type `RouterConfig`
/// and provide defaults for each field.
#[derive(Builder, Debug)]
pub struct RouterParams {
    #[builder(setter(into), default = "router".to_string())]
    name: String,

    #[builder(setter(into), default = DEFAULT_DP_UX_PATH.to_string().into())]
    pub cpi_sock_path: PathBuf,

    #[builder(setter(into), default = DEFAULT_DP_UX_PATH_CLI.to_string().into())]
    pub cli_sock_path: PathBuf,

    #[builder(setter(into), default = DEFAULT_FRR_AGENT_PATH.to_string().into())]
    pub frr_agent_path: PathBuf,

    // Optional BMP server parameters: whether to start server.
    #[builder(setter(strip_option), default)]
    pub bmp: Option<BmpServerParams>,

    // Mandatory dataplane status handle
    pub dp_status: Arc<RwLock<DataplaneStatus>>,
}

impl Display for RouterParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        writeln!(f, "Router config")?;
        writeln!(f, "  name     : {}", self.name)?;
        writeln!(f, "  CPI path : {}", self.cpi_sock_path.display())?;
        writeln!(f, "  CLI path : {}", self.cli_sock_path.display())?;
        writeln!(f, "  FRR-agent: {}", self.frr_agent_path.display())
    }
}

/// Top-most object representing a router
pub struct Router {
    name: String,
    params: RouterParams,
    resolver: AtResolver,
    rio_handle: RioHandle,
    iftr: IfTableReader,
    fibtr: FibTableReader,
    // keep BMP task alive while Router lives
    bmp_handle: Option<JoinHandle<()>>,
}

impl Router {
    /// Build the router IO configuration from the router configuration
    fn build_rio_config(params: &RouterParams) -> Result<RioConf, RouterError> {
        Ok(RioConf {
            name: params.name.clone(),
            cpi_sock_path: Some(
                params
                    .cpi_sock_path
                    .to_str()
                    .ok_or(RouterError::InvalidPath("(cpi path)".to_string()))?
                    .to_owned(),
            ),
            cli_sock_path: Some(
                params
                    .cli_sock_path
                    .to_str()
                    .ok_or(RouterError::InvalidPath("(cli path)".to_string()))?
                    .to_owned(),
            ),
            frrmi_sock_path: Some(
                params
                    .frr_agent_path
                    .to_str()
                    .ok_or(RouterError::InvalidPath("(frr-agent path)".to_string()))?
                    .to_owned(),
            ),
        })
    }

    /// Start a `Router`
    #[allow(clippy::new_without_default)]
    pub fn new(params: RouterParams) -> Result<Router, RouterError> {
        let name = &params.name;

        debug!("{name}: Building RIO config...");
        let rioconf = Self::build_rio_config(&params)?;

        debug!("{name}: Creating interface table...");
        let (iftw, iftr) = IfTableWriter::new();

        debug!("{name}: Creating FIB table...");
        let (fibtw, fibtr) = FibTableWriter::new();

        debug!("{name}: Creating Adjacency resolver...");
        let (mut resolver, atabler) = AtResolver::new(true);
        resolver.start(3);

        debug!("{name}: Starting router IO...");
        let rio_handle = start_rio(&rioconf, fibtw, iftw, atabler)?;

        // Start BMP server in background if configured, always with mandatory dp_status
        let bmp_handle = if let Some(bmp_params) = &params.bmp {
            debug!(
                "{name}: Starting BMP server on {} (interval={}ms)",
                bmp_params.bind_addr, bmp_params.stats_interval_ms
            );
            Some(bmp::spawn_background(
                bmp_params.bind_addr,
                params.dp_status.clone(),
            ))
        } else {
            None
        };

        debug!("{name}: Successfully started router with parameters:\n{params}");
        let router = Router {
            name: name.to_owned(),
            params,
            resolver,
            rio_handle,
            iftr,
            fibtr,
            bmp_handle,
        };
        Ok(router)
    }

    /// Stop this router. This stops the router IO thread and drops the interface table, adjacency table
    /// vrf table and the fib table.
    pub fn stop(&mut self) {
        if let Err(e) = self.rio_handle.finish() {
            error!("Failed to stop IO for router '{}': {e}", self.name);
        }
        self.resolver.stop();

        // Abort BMP server task if running (Tokio handle).
        if let Some(handle) = self.bmp_handle.take() {
            handle.abort();
        }

        debug!("Router '{}' is now stopped", self.name);
    }

    #[must_use]
    pub fn get_atabler(&self) -> AtableReader {
        self.resolver.get_reader()
    }

    #[must_use]
    pub fn get_atabler_factory(&self) -> AtableReaderFactory {
        self.resolver.get_reader().factory()
    }

    #[must_use]
    pub fn get_iftabler_factory(&self) -> IfTableReaderFactory {
        self.iftr.factory()
    }

    #[must_use]
    pub fn get_fibtr_factory(&self) -> FibTableReaderFactory {
        self.fibtr.factory()
    }

    #[must_use]
    pub fn get_ctl_tx(&self) -> RouterCtlSender {
        self.rio_handle.get_ctl_tx()
    }
    #[must_use]
    pub fn get_cpi_sock_path(&self) -> &PathBuf {
        &self.params.cpi_sock_path
    }
    #[must_use]
    pub fn get_cli_sock_path(&self) -> &PathBuf {
        &self.params.cli_sock_path
    }
    #[must_use]
    pub fn get_frr_agent_path(&self) -> &PathBuf {
        &self.params.frr_agent_path
    }
}
