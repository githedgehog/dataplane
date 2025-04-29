// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

// An FRR config reloader object

use std::str;

use crate::frr::renderer::builder::ConfigBuilder;
use crate::models::external::configdb::gwconfig::GenId;

use std::fs;
use std::net::Shutdown;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixDatagram;
use std::path::Path;
use thiserror::Error;
use tracing::{debug, error, info};

#[derive(Error, Debug)]
pub enum FrrErr {
    #[error("Failed to open FrrMi: {0}")]
    FailOpen(&'static str),

    #[error("Failed to connect to FRR agent: {0}")]
    FailConnect(String),

    #[error("Failed to send to FRR agent: {0}")]
    FailSend(String),

    #[error("Error receving from FRR agent: {0}")]
    ErrorRx(String),

    #[error("Reloading error")]
    ReloadErr(String),
}

fn open_unix_sock<P: AsRef<Path> + ?Sized + std::fmt::Display>(
    bind_addr: &P,
    non_blocking: bool,
) -> Result<UnixDatagram, &'static str> {
    let _ = std::fs::remove_file(bind_addr);
    let sock = UnixDatagram::bind(bind_addr).map_err(|_| "Failed to bind socket")?;
    let mut perms = fs::metadata(bind_addr)
        .map_err(|_| "Failed to retrieve path metadata")?
        .permissions();
    perms.set_mode(0o777); // fixme: make this more restrictive
    fs::set_permissions(bind_addr, perms).map_err(|_| "Failure setting permissions")?;
    sock.set_nonblocking(non_blocking)
        .map_err(|_| "Failed to set non-blocking")?;
    debug!("Created unix sock and bound to {bind_addr}");
    Ok(sock)
}

pub struct FrrMi {
    sock: UnixDatagram,
}
impl FrrMi {
    pub fn new(bind_addr: &str, remote_addr: &str) -> Result<FrrMi, FrrErr> {
        // fixme: use non-blocking
        let sock = open_unix_sock(bind_addr, false).map_err(FrrErr::FailOpen)?;
        sock.connect(remote_addr).map_err(|e| {
            error!("Failed to connect to {remote_addr}");
            FrrErr::FailConnect(e.to_string())
        })?;
        info!("Successfully opened frrmi. Local: {bind_addr} remote: {remote_addr}");
        Ok(Self { sock })
    }
    pub fn close(&mut self) {
        info!("Shutting down frrmi...");
        let _ = self.sock.shutdown(Shutdown::Both);
    }
    pub fn apply_config(&self, genid: GenId, config: &ConfigBuilder) -> Result<(), FrrErr> {
        info!("Applying config {genid} over frrmi...");
        let conf_str = config.to_string();
        let length = conf_str.len() as u64;

        /* send config length */
        self.sock.send(&length.to_ne_bytes()).map_err(|e| {
            error!("Fatal: Failed to send msg length: {}", e.kind());
            FrrErr::FailSend(e.to_string())
        })?;

        /* send config */
        self.sock.send(conf_str.as_bytes()).map_err(|e| {
            error!("Fatal: Failed to send config for gen {genid}: {}", e.kind());
            FrrErr::FailSend(e.to_string())
        })?;

        debug!("Waiting for reply...");

        /* recv (blocking) - fixme: make non-blocking w/ tokio */
        let mut rx_buff = vec![0u8; 1024];
        self.sock
            .recv(&mut rx_buff)
            .map_err(|e| FrrErr::ErrorRx(e.to_string()))?;

        info!("Successfully applied config with id {genid}");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frr::renderer::builder::Render;
    use crate::models::external::configdb::gwconfig::GwConfig;
    use crate::processor::tests::test::sample_external_config;
    use tracing_test::traced_test;

    #[test]
    #[traced_test]
    fn test_reloader() {
        /* build some sample config */
        let external = sample_external_config();
        let mut config = GwConfig::new(external);
        config.validate().expect("Validation should succeed");
        config.build_internal_config().expect("Should succeed");
        let rendered = config.internal.as_ref().unwrap().render(&config);

        /* open frrmi */
        let frrmi = FrrMi::new("/var/run/frr/frrmi.sock", "/var/run/frr/frr-agent.sock").unwrap();

        /* apply config over frrmi */
        if let Err(e) = frrmi.apply_config(config.genid(), &rendered) {
            error!("Failed to apply config: {e:?}");
        } else {
            info!("Successfully applied config");
        }

        /* FIXME: this will only work if|once we have an image with the frr-agent */
    }
}
