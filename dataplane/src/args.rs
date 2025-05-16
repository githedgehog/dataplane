// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![allow(unused)]

pub(crate) use clap::Parser;
use mgmt::processor::proc::GrpcAddress;
use std::net::SocketAddr;
use std::path::PathBuf;
use tracing::{debug, error};

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

    /// gRPC server address (IP:PORT for TCP or path for UNIX socket)
    #[arg(long, value_name = "ADDRESS", default_value = "[::1]:50051")]
    grpc_address: String,

    /// Treat grpc-address as a UNIX socket path
    #[arg(long, help = "Use UNIX socket instead of TCP")]
    grpc_unix_socket: bool,
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

    /// Get the gRPC server address configuration
    pub fn get_grpc_address(&self) -> Result<GrpcAddress, String> {
        // If UNIX socket flag is set, treat the address as a UNIX socket path
        if self.grpc_unix_socket {
            // Validate that the address is a valid UNIX socket path
            let grpc_path = PathBuf::from(&self.grpc_address);
            if !grpc_path.is_absolute() {
                return Err(format!(
                    "Invalid configuration: --grpc-unix-socket flag is set, but --grpc-address '{}' is not a valid absolute UNIX socket path",
                    self.grpc_address
                ));
            }
            return Ok(GrpcAddress::UnixSocket(grpc_path));
        }

        // Otherwise, parse as a TCP socket address
        match self.grpc_address.parse::<SocketAddr>() {
            Ok(addr) => Ok(GrpcAddress::Tcp(addr)),
            Err(e) => Err(format!(
                "Invalid gRPC TCP address '{}': {e}",
                self.grpc_address
            )),
        }
    }
}
