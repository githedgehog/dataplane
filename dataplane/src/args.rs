// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![allow(unused)]

pub(crate) use clap::Parser;
use std::net::SocketAddr;
use tracing::debug;

#[derive(Parser)]
#[command(name = "Hedgehog Fabric Gateway dataplane")]
#[command(version = "1.0")] // FIXME
#[command(about = "A next-gen dataplane for next-gen fabric gateway", long_about = None)]
pub(crate) struct CmdArgs {
    #[arg(long, value_name = "core-id used as main", default_value_t = 2)]
    main_lcore: u8,
    #[arg(long, value_name = "map lcore set to cpu set")]
    lcores: Option<String>,
    #[arg(long, value_name = "PCI devices to probe")]
    allow: Vec<String>,
    #[arg(long, value_name = "huge pages", default_value_t = 8192)]
    huge_worker_stack: u32,
    #[arg(long, value_name = "socket memory")]
    socket_mem: Option<String>,
    #[arg(long, value_name = "iova mode(va|pa)")]
    iova_mode: Option<String>,
    #[arg(long, value_name = "loglevel for a specific component")]
    log_level: Vec<String>,
    // Non-eal params
    #[arg(long, value_name = "packet driver to use: kernel or dpdk")]
    driver: Option<String>,
    #[arg(long, value_name = "name of kernel interface")]
    interface: Vec<String>,

    // gRPC server address
    #[arg(
        long,
        value_name = "gRPC server address",
        default_value = "[::1]:50051"
    )]
    grpc_address: String,
}

impl CmdArgs {
    pub fn get_driver_name(&self) -> &str {
        match &self.driver {
            None => "dpdk",
            Some(name) => name,
        }
    }
    #[allow(clippy::unused_self)]
    pub fn kernel_params(&self) -> Vec<String> {
        self.interface.clone()
    }
    pub fn eal_params(&self) -> Vec<String> {
        let mut out = Vec::new();
        /* hardcoded (always) */
        out.push("--in-memory".to_string());

        out.push("--main-lcore".to_owned());
        out.push(self.main_lcore.to_string());

        out.push("--lcores".to_string());
        out.push(
            self.lcores
                .clone()
                .map_or_else(|| "2-4".to_owned(), |lcores| lcores.clone()),
        );

        /* IOVA mode */
        out.push(format!(
            "--iova-mode={}",
            &self
                .iova_mode
                .clone()
                .map_or_else(|| { "va".to_owned() }, |mode| mode.clone())
        ));

        /* worker huge page stack size */
        out.push(format!("--huge-worker-stack={}", self.huge_worker_stack));

        /* --allow */
        for a in &self.allow {
            out.push("--allow".to_string());
            out.push(a.to_owned());
        }

        // To be removed
        if self.allow.is_empty() {
            out.push("--allow".to_string());
            out.push("0000:01:00.0,dv_flow_en=1".to_string());
        }

        /* --log-level */
        for level in &self.log_level {
            out.push("--log-level".to_string());
            out.push(level.to_owned());
        }

        // To replace by log
        debug!("DPDK EAL init params: {out:?}");

        out
    }

    /// Get the gRPC server address
    pub fn get_grpc_address(&self) -> SocketAddr {
        match self.grpc_address.parse() {
            Ok(addr) => addr,
            Err(e) => {
                eprintln!("Error: Invalid gRPC address '{}': {}", self.grpc_address, e);
                panic!("Process receives unexpected gRPC address. Aborting...");
            }
        }
    }
}
