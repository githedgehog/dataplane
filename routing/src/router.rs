// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Module that implements a router instance

use derive_builder::Builder;
use std::fmt::Display;
use std::path::PathBuf;
use tracing::{debug, error};

use crate::atable::atablerw::AtableReader;
use crate::atable::resolver::AtResolver;
use crate::cpi::{CpiConf, CpiHandle, start_cpi};
use crate::ctl::RouterCtlSender;
use crate::errors::RouterError;
use crate::fib::fibtable::{FibTableReader, FibTableWriter};
use crate::interfaces::iftablerw::{IfTableReader, IfTableWriter};

use crate::cpi::DEFAULT_DP_UX_PATH;
use crate::cpi::DEFAULT_DP_UX_PATH_CLI;
use crate::cpi::DEFAULT_FRR_AGENT_PATH;
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
    cpi: CpiHandle,
    iftr: IfTableReader,
    fibtr: FibTableReader,
}

// Build cpi configuration from the router configuration
fn init_router(params: &RouterParams) -> Result<CpiConf, RouterError> {
    Ok(CpiConf {
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
    })
}

#[allow(clippy::new_without_default)]
impl Router {
    /// Start a router object
    pub fn new(params: RouterParams) -> Result<Router, RouterError> {
        let name = &params.name;

        debug!("{name}: Initializing...");
        let cpiconf = init_router(&params)?;

        debug!("{name}: Creating interface table...");
        let (iftw, iftr) = IfTableWriter::new();

        debug!("{name}: Creating FIB table...");
        let (fibtw, fibtr) = FibTableWriter::new();

        debug!("{name}: Creating Adjacency resolver...");
        let (mut resolver, atabler) = AtResolver::new(true);
        resolver.start(3);

        debug!("{name}: Starting CPI...");
        let cpi = start_cpi(&cpiconf, fibtw, iftw, atabler)?;

        debug!("{name}: Successfully started with parameters:\n{params}");
        let router = Router {
            name: name.to_owned(),
            params,
            resolver,
            cpi,
            iftr,
            fibtr,
        };
        Ok(router)
    }

    /// Stop this router instance
    pub fn stop(&mut self) {
        if let Err(e) = self.cpi.finish() {
            error!("Failed to stop the cpi for router '{}': {e}", self.name);
        }
        self.resolver.stop();
        debug!("Router instance '{}' is now stopped", self.name);
    }

    #[must_use]
    pub fn get_atabler(&self) -> AtableReader {
        self.resolver.get_reader()
    }

    #[must_use]
    pub fn get_iftabler(&self) -> IfTableReader {
        self.iftr.clone()
    }

    #[must_use]
    pub fn get_fibtr(&self) -> FibTableReader {
        self.fibtr.clone()
    }

    #[must_use]
    pub fn get_ctl_tx(&self) -> RouterCtlSender {
        self.cpi.get_ctl_tx()
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
