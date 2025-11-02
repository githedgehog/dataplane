// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

pub use clap::Parser;
use hardware::pci::address::PciAddress;
use mgmt::processor::launch::GrpcAddress;
use net::interface::InterfaceName;
use routing::rio::DEFAULT_DP_UX_PATH;
use routing::rio::DEFAULT_DP_UX_PATH_CLI;
use routing::rio::DEFAULT_FRR_AGENT_PATH;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use tracing::debug;

#[derive(Debug, Clone)]
#[allow(unused)]
pub struct InterfaceArg {
    interface: InterfaceName,
    pciaddr: Option<PciAddress>,
}
impl FromStr for InterfaceArg {
    type Err = String;
    fn from_str(input: &str) -> Result<Self, Self::Err> {
        match input.split_once('=') {
            Some((ifname, optional)) => {
                let interface = InterfaceName::try_from(ifname)
                    .map_err(|e| format!("Bad interface name: {e}"))?;
                let pciaddr = if optional.is_empty() {
                    None
                } else {
                    let pciaddr = PciAddress::try_from(optional)
                        .map_err(|e| format!("Invalid PCI address: {e}"))?;
                    Some(pciaddr)
                };
                Ok(InterfaceArg { interface, pciaddr })
            }
            None => {
                let interface = InterfaceName::try_from(input)
                    .map_err(|e| format!("Bad interface name: {e}"))?;
                Ok(InterfaceArg {
                    interface,
                    pciaddr: None,
                })
            }
        }
    }
}
#[cfg(test)]
mod tests {
    use hardware::pci::address::PciAddress;
    use hardware::pci::bus::Bus;
    use hardware::pci::device::Device;
    use hardware::pci::domain::Domain;
    use hardware::pci::function::Function;

    use crate::InterfaceArg;
    use std::str::FromStr;

    #[test]
    fn test_parse_interface() {
        // interface + port desc
        let spec = InterfaceArg::from_str("GbEth1.9000=0000:02:01.7").unwrap();
        assert_eq!(spec.interface.as_ref(), "GbEth1.9000");

        assert_eq!(
            spec.pciaddr,
            Some(PciAddress::new(
                Domain::from(0),
                Bus::new(2),
                Device::try_from(1).unwrap(),
                Function::try_from(7).unwrap()
            ))
        );

        // interface only
        let spec = InterfaceArg::from_str("GbEth1.9000").unwrap();
        assert_eq!(spec.interface.as_ref(), "GbEth1.9000");
        assert_eq!(spec.pciaddr, None);

        // interface= we treat it as none
        let spec = InterfaceArg::from_str("GbEth1.9000=").unwrap();
        assert_eq!(spec.interface.as_ref(), "GbEth1.9000");
        assert_eq!(spec.pciaddr, None);

        // bad interface name
        assert!(InterfaceArg::from_str("Blah-blah-blah-blah").is_err());

        // bad pci address
        assert!(InterfaceArg::from_str("GbEth1.9000=0000:02:01").is_err());
    }
}

#[derive(Parser)]
#[command(name = "Hedgehog Fabric Gateway dataplane")]
#[command(version = "1.0")] // FIXME
#[command(about = "A next-gen dataplane for next-gen fabric gateway", long_about = None)]
#[allow(clippy::struct_excessive_bools)]
pub struct CmdArgs {
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
    #[arg(
        long,
        value_name = "interface name",
        value_parser=InterfaceArg::from_str,
        value_delimiter=',',
        help = "Interface name (kernel naming restrictions apply), with optional PCI address in the format INTERFACE[=PCIaddress].
E.g. --interface eth1 --interface eth0=0000:02:01.0. Note that multiple interfaces can be specified, comma-separated.
E.g. --interface eth1,eth0=0000:02:01.0"
    )]
    interface: Vec<InterfaceArg>,

    /// Number of worker threads for the kernel driver.
    #[arg(
        long,
        value_name = "N",
        default_value_t = 1,
        value_parser = clap::value_parser!(u16).range(1..=64),
        help = "Number of worker threads for the kernel driver in [1..64]"
    )]
    num_workers: u16,

    /// gRPC server address (IP:PORT for TCP or path for UNIX socket)
    #[arg(
        long,
        value_name = "ADDRESS",
        default_value = "[::1]:50051",
        help = "IP Address and port or UNIX socket path to listen for management connections"
    )]
    grpc_address: String,

    /// Treat grpc-address as a UNIX socket path
    #[arg(long, help = "Use a unix socket to listen for management connections")]
    grpc_unix_socket: bool,

    #[arg(
        long,
        value_name = "CPI Unix socket path",
        help = "Unix socket for FRR to send route update messages to the dataplane",
        default_value = DEFAULT_DP_UX_PATH
    )]
    cpi_sock_path: String,

    #[arg(
        long,
        value_name = "CLI Unix socket path",
        help = "Unix socket to listen for dataplane cli connections",
        default_value = DEFAULT_DP_UX_PATH_CLI
    )]
    cli_sock_path: String,

    #[arg(
        long,
        value_name = "FRR Agent Unix socket path",
        help = "Unix socket to connect to FRR agent that controls FRR configuration reload",
        default_value = DEFAULT_FRR_AGENT_PATH
    )]
    frr_agent_path: String,

    /// Prometheus metrics server bind address
    #[arg(
        long,
        value_name = "Metrics Address and Port",
        default_value_t = SocketAddr::from(([127, 0, 0, 1], 9090)),
        help = "Bind address and port for Prometheus metrics HTTP endpoint"
    )]
    metrics_address: SocketAddr,

    #[arg(
        long,
        default_value_t = false,
        help = "Show the available tracing tags and exit"
    )]
    show_tracing_tags: bool,

    #[arg(
        long,
        default_value_t = false,
        help = "Show configurable tracing targets and exit"
    )]
    show_tracing_targets: bool,

    #[arg(long, help = "generate tracing configuration as a string and exit")]
    tracing_config_generate: bool,

    #[arg(
        long,
        value_name = "tracing configuration",
        help = "Tracing config string as comma-separated sequence of tag=level, with level one in [off,error,warn,info,debug,trace].
Passing default=level sets the default log-level.
Passing all=level allows setting the log-level of all targets to level.
E.g. default=error,all=info,nat=debug will set the default target to error, and all the registered targets to info, but enable debug for nat"
    )]
    tracing: Option<String>,
}

impl CmdArgs {
    pub fn get_driver_name(&self) -> &str {
        match &self.driver {
            None => "dpdk",
            Some(name) => name,
        }
    }

    pub fn show_tracing_tags(&self) -> bool {
        self.show_tracing_tags
    }
    pub fn show_tracing_targets(&self) -> bool {
        self.show_tracing_targets
    }
    pub fn tracing_config_generate(&self) -> bool {
        self.tracing_config_generate
    }
    pub fn tracing(&self) -> Option<&String> {
        self.tracing.as_ref()
    }

    pub fn kernel_num_workers(&self) -> usize {
        self.num_workers.into()
    }
    // backwards-compatible, to deprecate
    pub fn kernel_interfaces(&self) -> Vec<String> {
        self.interface
            .iter()
            .map(|spec| spec.interface.to_string())
            .collect()
    }

    // interface getter. This should be used by all drivers
    pub fn interfaces(&self) -> impl Iterator<Item = &InterfaceArg> {
        self.interface.iter()
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

    pub fn cpi_sock_path(&self) -> String {
        self.cpi_sock_path.clone()
    }

    pub fn cli_sock_path(&self) -> String {
        self.cli_sock_path.clone()
    }

    pub fn frr_agent_path(&self) -> String {
        self.frr_agent_path.clone()
    }

    /// Get the metrics bind address, returns None if metrics are disabled
    pub fn metrics_address(&self) -> SocketAddr {
        self.metrics_address
    }
}
