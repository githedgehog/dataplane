// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![deny(clippy::all, clippy::pedantic)]
#![deny(rustdoc::all)]
#![allow(rustdoc::missing_crate_level_docs)]

mod drivers;
mod packet_processor;
mod statistics;


use crate::drivers::dpdk::Dataplane;
use args::{LaunchConfiguration, TracingConfigSection};

use tracectl::{custom_target, get_trace_ctl, trace_target};

use tracing::{error, info, level_filters::LevelFilter};

trace_target!("dataplane", LevelFilter::DEBUG, &[]);
custom_target!("tonic", LevelFilter::ERROR, &[]);
custom_target!("h2", LevelFilter::ERROR, &[]);

fn init_logging() {
    let tctl = get_trace_ctl();
    tctl.set_default_level(LevelFilter::DEBUG)
        .expect("Setting default loglevel failed");
}

fn process_tracing_cmds(cfg: &TracingConfigSection) {
    if let Some(tracing) = &cfg.config
        && let Err(e) = get_trace_ctl().setup_from_string(tracing)
    {
        error!("Invalid tracing configuration: {e}");
        panic!("Invalid tracing configuration: {e}");
    }
    match cfg.show.tags {
        args::TracingDisplayOption::Hide => {}
        args::TracingDisplayOption::Show => {
            let out = get_trace_ctl()
                .as_string_by_tag()
                .unwrap_or_else(|e| e.to_string());
            println!("{out}");
            std::process::exit(0);
        }
    }
    if cfg.show.targets == args::TracingDisplayOption::Show {
        let out = get_trace_ctl()
            .as_string()
            .unwrap_or_else(|e| e.to_string());
        println!("{out}");
        std::process::exit(0);
    }
    // TODO: Temporary feature regression
    // if args.tracing_config_generate() {
    //     let out = get_trace_ctl()
    //         .as_config_string()
    //         .unwrap_or_else(|e| e.to_string());
    //     println!("{out}");
    //     std::process::exit(0);
    // }
}

fn main() {
    let launch_config = LaunchConfiguration::inherit();
    init_logging();
    info!("launch config: {launch_config:?}");
    process_tracing_cmds(&launch_config.tracing);

    info!("Starting gateway process...");

    let (stop_tx, stop_rx) = std::sync::mpsc::channel();
    ctrlc::set_handler(move || stop_tx.send(()).expect("Error sending SIGINT signal"))
        .expect("failed to set SIGINT handler");
    let dataplane = Dataplane::new(launch_config);
    let mut dataplane = dataplane.start();
    stop_rx.recv().expect("failed to receive stop signal");
    dataplane.stop();
    info!("Shutting down dataplane");
    std::process::exit(0);
}

#[cfg(test)]
mod test {
    use n_vm::in_vm;

    #[test]
    #[in_vm]
    fn root_filesystem_in_vm_is_read_only() {
        let error = std::fs::File::create_new("/some.file").unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::ReadOnlyFilesystem);
    }

    #[test]
    #[in_vm]
    fn run_filesystem_in_vm_is_read_write() {
        std::fs::File::create_new("/run/some.file").unwrap();
    }

    #[test]
    #[in_vm]
    fn tmp_filesystem_in_vm_is_read_write() {
        std::fs::File::create_new("/tmp/some.file").unwrap();
    }
}
