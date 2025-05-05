// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

// An FRR config reloader object

use std::str;

use crate::frr::renderer::builder::ConfigBuilder;
use crate::models::external::configdb::gwconfig::GenId;

use std::fs;
use std::net::Shutdown;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use thiserror::Error;
use tracing::{debug, error, info};

use tokio::net::UnixDatagram;

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

pub fn open_unix_sock_async<P: AsRef<Path> + ?Sized + std::fmt::Display>(
    bind_addr: &P,
) -> Result<UnixDatagram, &'static str> {
    debug!("Opening sock at {bind_addr}...");

    /* remove entry from filesystem */
    let _ = std::fs::remove_file(bind_addr);

    /* create intermediate directories */
    let path = Path::new(bind_addr.as_ref());
    if let Some(parent_dir) = path.parent() {
        debug!("Creating directory at {parent_dir:?}...");
        fs::create_dir_all(parent_dir)
            .map_err(|_| "Failed to create path to unix sock local address")?;
    }

    /* create sock */
    let sock = UnixDatagram::bind(bind_addr).map_err(|_| "Failed to bind socket")?;
    let mut perms = fs::metadata(bind_addr)
        .map_err(|_| "Failed to retrieve path metadata")?
        .permissions();
    perms.set_mode(0o777); // fixme: make this more restrictive
    fs::set_permissions(bind_addr, perms).map_err(|_| "Failure setting permissions")?;
    debug!("Created unix sock and bound to {bind_addr}");
    Ok(sock)
}

pub struct FrrMi {
    sock: UnixDatagram,
}
impl FrrMi {
    pub fn new(bind_addr: &str, remote_addr: &str) -> Result<FrrMi, FrrErr> {
        let sock = open_unix_sock_async(bind_addr).map_err(FrrErr::FailOpen)?;
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
    pub async fn apply_config(&self, genid: GenId, config: &ConfigBuilder) -> Result<(), FrrErr> {
        info!("Applying FRR config for genid {genid} over frrmi...");
        let conf_str = config.to_string();
        let length = conf_str.len() as u64;

        /* send config length */
        self.sock.send(&length.to_ne_bytes()).await.map_err(|e| {
            error!("Fatal: Failed to send msg length: {}", e.kind());
            FrrErr::FailSend(e.to_string())
        })?;

        /* send config */
        self.sock.send(conf_str.as_bytes()).await.map_err(|e| {
            error!("Fatal: Failed to send config for gen {genid}: {}", e.kind());
            FrrErr::FailSend(e.to_string())
        })?;

        debug!("AWaiting for a reply from frr-agent...");

        /* recv */
        let mut rx_buff = vec![0u8; 1024];
        self.sock
            .recv(&mut rx_buff)
            .await
            .map_err(|e| FrrErr::ErrorRx(e.to_string()))?;

        info!("Successfully applied FRR config with id {genid}");
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

    #[tokio::test]
    #[traced_test]
    async fn test_frrmi() {
        /* build some sample config */
        let external = sample_external_config();
        let mut config = GwConfig::new(external);
        config.validate().expect("Validation should succeed");
        config.build_internal_config().expect("Should succeed");
        let rendered = config.internal.as_ref().unwrap().render(&config);

        /* create faked frr-agent: socknames include name of test to avoid issues with other tests
        running concurrently */
        let sock = open_unix_sock_async("/tmp/frrmi-test/frr-agent.sock").expect("Should succeed");
        tokio::spawn(async move {
            let mut rx_buff = vec![0u8; 8192];
            let (_, _) = sock.recv_from(&mut rx_buff).await.unwrap();
            let (_, _) = sock.recv_from(&mut rx_buff).await.unwrap();
            sock.send_to("Ok".to_string().as_bytes(), "/tmp/frrmi-test/frrmi.sock")
                .await
                .unwrap();
        });

        /* open frrmi */
        let frrmi = FrrMi::new(
            "/tmp/frrmi-test/frrmi.sock",
            "/tmp/frrmi-test/frr-agent.sock",
        )
        .unwrap();

        /* apply config over frrmi */
        if let Err(e) = frrmi.apply_config(config.genid(), &rendered).await {
            error!("Failed to apply config: {e:?}");
        } else {
            info!("Successfully applied config");
        }
    }
}
