// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Tap initialization

use std::{collections::HashMap, pin::Pin, sync::Arc};

use args::InterfaceArg;
use interface_manager::interface::TapDevice;
use net::{
    buffer::{Append, BufferPool, Tailroom, TrimFromEnd},
    interface::InterfaceIndex,
    packet::Packet,
};
use tracing::{debug, error, info, trace, warn};

/// Receive packets from trap points and write them to a tap device.
pub struct TrapAndInjectionHandler<Pool: BufferPool> {
    /// pool of memory buffers from which to allocate injected packets
    pool: Pool,
    from_pipeline: tokio::sync::mpsc::Receiver<Box<Packet<Pool::Buffer>>>,
    to_pipeline: tokio::sync::mpsc::Sender<Box<Packet<Pool::Buffer>>>,
    taps: HashMap<InterfaceIndex, TapDevice>,
}

// todo: use async-scoped or something to reduce 'static to 'dataplane
impl<Pool: BufferPool + 'static> TrapAndInjectionHandler<Pool> {
    pub const CHANNEL_BOUND: usize = 1024;

    pub async fn biscuit(pool: Arc<Pool>, ifargs: &[InterfaceArg]) {
        let table = Self::create_taps(ifargs).await.unwrap();
        let (to_pipeline, injected) = tokio::sync::mpsc::channel(Self::CHANNEL_BOUND);
        let (trap, from_pipeline) = tokio::sync::mpsc::channel(Self::CHANNEL_BOUND);
        let mut join_set = tokio::task::JoinSet::new();
        let tap_reader = table.into_iter().map(|(ifarg, tap)| {
            let to_pipeline = to_pipeline.clone();
            let pool = pool.clone();
            async move {
                loop {
                    let mut buffer = pool.new_buffer().unwrap();
                    tokio::select! {
                        recvd = tap.read(&mut buffer) => {
                            match recvd {
                                Ok(recvd) => {
                                    trace!("packet of size {recvd} injected");
                                    // todo: watch for wrap.
                                    match Packet::new(buffer) {
                                        Ok(pkt) => to_pipeline.send(Box::new(pkt)).await.unwrap(),
                                        Err(err) => {
                                            debug!("injected packet failed to parse: {err:?}");
                                            continue;
                                        }
                                    }
                                }
                                Err(err) => {
                                    warn!("unable to read from tap device: {err:?}");
                                    panic!("unable to read from tap device: {err:?}");
                                }
                            }
                        }

                    }
                }
            }
            
        });
        for job in tap_reader {
            join_set.spawn(job);
        }
        while let Some(res) = join_set.join_next().await {
            match res {
                Ok(()) => todo!(),
                Err(err) => {
                    error!("unable to join task: {err:?}");
                    panic!("unable to join task: {err:?}");
                }
            }
        }
    }
    /// Creates a tap device for each of the [`InterfaceArg`]s provided.
    ///
    /// # Errors
    ///
    /// This function fails if any of the taps cannot be created.
    async fn create_taps(
        ifargs: &[InterfaceArg],
    ) -> std::io::Result<HashMap<InterfaceArg, TapDevice>> {
        info!("Creating tap devices");
        let mut out = HashMap::with_capacity(ifargs.len());
        for interface in ifargs {
            let response = TapDevice::open(&interface.interface).await;
            match response {
                Ok(tap) => {
                    out.insert(interface.clone(), tap);
                }
                Err(e) => {
                    error!("Failed to create tap '{}': {e}", interface.interface);
                    return Err(e);
                }
            }
        }
        Ok(out)
    }
}
