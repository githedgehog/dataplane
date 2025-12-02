// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Cmd line to start cli

use clap::Parser;

pub(crate) const DEFAULT_DATAPLANE_PATH: &str = "/var/run/dataplane/cli.sock";
pub(crate) const DEFAULT_CLI_BIND: &str = "/var/run/dataplane/cliclient.sock";

#[derive(Parser)]
#[command(about = "Hedgehog Fabric Gateway CLI", long_about = None)]
pub struct Cmdline {
    #[arg(
        long,
        value_name = "Dataplane ocket path",
        default_value = DEFAULT_DATAPLANE_PATH,
        help = "Path where dataplane listens for CLI requests"
    )]
    pub path: String,

    #[arg(
        long,
        value_name = "Local socket path",
        default_value = DEFAULT_CLI_BIND,
        help = "Path to bind this CLI to"
    )]
    pub bind_address: String,
}
