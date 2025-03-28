// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Module that implements a router instance

use std::str::FromStr;
use tracing::{debug, error};

use crate::atable::atablerw::AtableReader;
use crate::atable::resolver::AtResolver;
use crate::cpi::{CpiConf, CpiHandle, start_cpi};
use crate::fib::fibtable::{FibTableReader, FibTableWriter};
use crate::interfaces::iftablerw::{IfTableReader, IfTableWriter};
use dplane_rpc::log::{Level, LogConfig, init_dplane_rpc_log};

// TODO: fredi, make this configurable
fn init_router() -> CpiConf {
    let conf = CpiConf {
        rpc_loglevel: Some("debug".to_string()),
        cpi_sock_path: Some("/var/run/frr/hh/dataplane.sock".to_string()),
        cli_sock_path: Some("/tmp/dataplane_ctl.sock".to_string()),
    };

    let loglevel = conf
        .rpc_loglevel
        .as_ref()
        .map(|level| Level::from_str(level).expect("Wrong log level"))
        .unwrap_or_else(|| Level::DEBUG);

    // set loglevel for RPC
    let mut cfg = LogConfig::new(loglevel);
    cfg.display_thread_names = true;
    cfg.show_line_numbers = true;
    cfg.display_target = true;
    init_dplane_rpc_log(&cfg);
    debug!("Router instance initialization completed");
    conf
}

#[allow(unused)]
pub struct Router {
    name: String,
    resolver: AtResolver,
    cpi: CpiHandle,
    iftr: IfTableReader,
    fibtr: FibTableReader,
}

#[allow(clippy::new_without_default)]
impl Router {
    pub fn new(name: &str) -> Self {
        debug!("{name}: Initializing");
        let cpiconf = init_router();

        debug!("{name}: Creating interface table...");
        let (iftw, iftr) = IfTableWriter::new();

        debug!("{name}: Creating FIB table...");
        let (fibtw, fibtr) = FibTableWriter::new();

        debug!("{name}: Creating Adjacency resolver...");
        let (mut resolver, atabler) = AtResolver::new(true);
        resolver.start(3);

        debug!("{name}: Starting CPI...");
        let Ok(cpi) = start_cpi(&cpiconf, fibtw, iftw, atabler) else {
            error!("Failed to start CPI");
            panic!("Failed to start CPI");
        };

        Self {
            name: name.to_owned(),
            resolver,
            cpi,
            iftr,
            fibtr,
        }
    }
    // Todo: allow starting the router after creating it.

    pub fn stop(&mut self) {
        if let Err(e) = self.cpi.finish() {
            error!("Failed to stop the cpi for router '{}': {e}", self.name);
        }

        self.resolver.stop();
        debug!("Router instance '{}' is now stopped", self.name);
    }

    pub fn get_atabler(&self) -> AtableReader {
        self.resolver.get_reader()
    }
    pub fn get_iftabler(&self) -> IfTableReader {
        self.iftr.clone()
    }
    pub fn get_fibtr(&self) -> FibTableReader {
        self.fibtr.clone()
    }
}
