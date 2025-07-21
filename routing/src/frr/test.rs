// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Tests for frrmi

#[cfg(test)]
pub mod fake_frr_agent {
    use bytes::Buf;
    use bytes::BytesMut;
    use config::GenId;
    use std::io::Cursor;
    use std::path::Path;
    use std::str::from_utf8;
    use tokio::fs;
    use tokio::io::{AsyncWriteExt, ErrorKind};
    use tokio::net::{UnixListener, UnixStream};
    use tokio::task::JoinHandle;
    use tracing::{debug, error};

    /// Receive **EXACTLY** len octets of data over the specified [`UnixStream`] socket
    async fn do_recv(sock: &mut UnixStream, len: usize) -> Result<Vec<u8>, String> {
        let mut data = BytesMut::with_capacity(len);
        let mut chunk_buffer = vec![0u8; len];
        while data.len() < len {
            sock.readable().await.map_err(|e| e.to_string())?;
            match sock.try_read(&mut chunk_buffer) {
                Ok(0) => return Err("Peer left".to_string()),
                Ok(n) => data.extend_from_slice(&chunk_buffer[..n]),
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                    continue;
                }
                Err(e) => return Err(e.to_string()),
            };
        }
        Ok(data.into())
    }

    /// Receive a message made of |length|genid|data. This applies to both requests and responses.
    async fn receive_msg(sock: &mut UnixStream) -> Result<(GenId, String), String> {
        /* data length as 8 octets*/
        let len_buf = do_recv(sock, 8).await?;
        let len_buf: [u8; 8] = len_buf
            .try_into()
            .map_err(|_| "Error decoding msg length".to_string())?;
        let msg_len = u64::from_ne_bytes(len_buf) as usize;

        /* genid */
        let genid_buf = do_recv(sock, 8).await?;
        let genid_buf: [u8; 8] = genid_buf
            .try_into()
            .map_err(|_| "Error decoding genid".to_string())?;
        let genid = i64::from_ne_bytes(genid_buf) as GenId;

        /* data with length msg_len */
        let buf = do_recv(sock, msg_len).await?;
        let message = from_utf8(&buf).map_err(|_| "Error decoding message".to_string())?;
        debug!("Got message with {msg_len} octets for genid {genid}");
        Ok((genid, message.to_string()))
    }

    /// Send a buffer over the provided [`UnixStream`]
    async fn send_buf(sock: &mut UnixStream, buf: &[u8]) -> Result<(), String> {
        let mut cursor = Cursor::new(buf);
        while cursor.has_remaining() {
            sock.write_buf(&mut cursor).await.map_err(|e| {
                error!("Failed to send buffer: {e}");
                e.to_string()
            })?;
        }
        Ok(())
    }

    async fn send_msg(sock: &mut UnixStream, genid: GenId, msg: &[u8]) -> Result<(), String> {
        /* length of data */
        let length = msg.len() as u64;
        debug!("Sending message. Genid: {genid} size: {length}");

        /* assemble wire message: |length|genid|data| */
        let mut wire_msg = BytesMut::with_capacity(msg.len() + 16);
        wire_msg.extend_from_slice(&length.to_ne_bytes());
        wire_msg.extend_from_slice(&genid.to_ne_bytes());
        wire_msg.extend_from_slice(msg);

        /* send wire message */
        send_buf(sock, &wire_msg).await?;
        debug!("Successfully sent msg. data-len: {length} genid: {genid}");
        Ok(())
    }

    /// Create a fake frr-agent async task for testing.
    /// The agent can be stopped by calling abort() on the returned handle.
    pub async fn fake_frr_agent(agent_address: &str) -> JoinHandle<()> {
        debug!("Starting fake frr-agent at {agent_address}...");

        /* remove stale entries in FS and create new */
        let _ = std::fs::remove_file(agent_address);
        let bind_path = Path::new(agent_address);
        if let Some(parent_dir) = bind_path.parent() {
            debug!("Creating directory at {parent_dir:?}...");
            fs::create_dir_all(parent_dir).await.unwrap();
        }
        let listener = UnixListener::bind(bind_path).unwrap();

        /* spawn */
        let task = tokio::spawn(async move {
            debug!("frr-agent will accept connections now");
            let (mut sock, peer) = listener.accept().await.unwrap();
            debug!("frr-agent got connection from {peer:?}");
            loop {
                let (genid, request) = receive_msg(&mut sock).await.unwrap();
                debug!("frr-agent got request:\n{request}");
                // always respond Ok
                send_msg(&mut sock, genid, "Ok".to_string().as_bytes())
                    .await
                    .unwrap();
            }
        });
        debug!("Spawned fake frr-agent");
        task
    }
}

#[cfg(test)]
pub mod tests {
    use super::fake_frr_agent::*;
    use crate::config::RouterConfig;
    use crate::{Router, RouterParamsBuilder};
    use std::thread;
    use std::time::Duration;
    use tracing_test::traced_test;

    #[traced_test]
    #[tokio::test]
    async fn test_fake_frr_agent() {
        /* set router params */
        let router_params = RouterParamsBuilder::default()
            .cpi_sock_path("/tmp/cpi.sock")
            .cli_sock_path("/tmp/cli.sock")
            .frr_agent_path("/tmp/frr-agent.sock")
            .build()
            .expect("Should succeed due to defaults");

        /* start router */
        let mut router = Router::new(router_params).unwrap();
        let mut ctl = router.get_ctl_tx();

        /* start fake frr agent */
        let frr_agent_path = router.get_frr_agent_path().to_str().expect("Bad path");
        let frr_agent = fake_frr_agent(frr_agent_path).await;

        /* dummy FRR configuration to request */
        let frr_config = "
!
frr version 10.3.1
frr defaults datacenter
hostname GW1
log stdout
service integrated-vtysh-config
!
interface eth0
 ip address 10.0.0.14/30
 ip ospf area 0.0.0.0
 ip ospf network point-to-point
exit
!
";
        /* send a config to the router (as the mgmt would do), give it time to apply it by the
        fake frr agent. Finish when it is reported as applied */
        let mut done = false;
        while !done {
            /* build a minimal config -- we only care about FRR config */
            let mut router_config = RouterConfig::new(13);
            router_config.set_frr_config(frr_config.to_string());

            /* request the configuration */
            ctl.configure(router_config).await.unwrap();

            /* give some time to rio to send the request / frr-agent to reply */
            thread::sleep(Duration::from_secs(1));

            /* poll the config */
            let frr_applied = ctl.get_frr_applied_config().await.unwrap();
            if let Some(frr_applied) = &frr_applied {
                assert_eq!(frr_applied.genid, 13);
                assert_eq!(frr_applied.cfg, frr_config);
                done = true;
            }
        }

        /* stop fake frr agent */
        frr_agent.abort();

        /* stop the router */
        router.stop();
    }
}
