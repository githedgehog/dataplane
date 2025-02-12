// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![deny(
    unsafe_code,
    missing_docs,
    clippy::all,
    clippy::pedantic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use std::error::Error;

use dpdk::mem::Mbuf;
use net::packet::Packet;
use net::vxlan::Vni;

use crate::config::Config;

// FIXME(mvachhar) add actual data here
pub struct Metadata {
    #[allow(dead_code)]
    pub vni: Option<Vni>,
}

pub struct MetaPacket {
    pub packet: Packet,
    #[allow(dead_code)]
    pub metadata: Metadata,
    #[allow(dead_code)]
    pub outer_packet: Option<Box<Packet>>,
    pub mbuf: Mbuf,
}

pub trait PipelineStage {
    fn start(&mut self) -> Result<(), Box<dyn Error>>;

    // FIXME(mvachhar) This interface is likely to change once we figure out
    // how to do this in a thread-safe manner, please use sparingly while
    // we figure out the best way to do this.
    fn update_config(&mut self, config: &Config) -> Result<(), Box<dyn Error>>;

    fn process(
        &mut self,
        packets: Box<dyn Iterator<Item = MetaPacket>>,
    ) -> Box<dyn Iterator<Item = MetaPacket>>;
}

pub struct Pipeline {
    stages: Vec<Box<dyn PipelineStage>>,
    started: bool,
}

#[derive(thiserror::Error, Clone, Debug)]
pub enum PipelineError {
    #[error("Pipeline already started")]
    AlreadyStarted,
}

impl Pipeline {
    pub fn new() -> Self {
        Self {
            stages: vec![],
            started: false,
        }
    }

    pub fn add_stage(&mut self, stage: Box<dyn PipelineStage>) -> Result<(), PipelineError> {
        if self.started {
            return Err(PipelineError::AlreadyStarted);
        }
        self.stages.push(stage);
        Ok(())
    }

    pub fn start(&mut self) -> Result<(), Box<dyn Error>> {
        if self.started {
            return Err(Box::new(PipelineError::AlreadyStarted));
        }
        self.started = true;
        let result: Result<Vec<_>, _> = self.stages.iter_mut().map(|stage| stage.start()).collect();
        result.map(|_| ())
    }

    pub fn update_config(&mut self, config: &Config) -> Result<(), Box<dyn Error>> {
        let result: Result<Vec<_>, _> = self
            .stages
            .iter_mut()
            .map(|stage| stage.update_config(config))
            .collect();
        result.map(|_| ())
    }

    pub fn process_packets(
        &mut self,
        packets: Box<dyn Iterator<Item = MetaPacket>>,
    ) -> Box<dyn Iterator<Item = MetaPacket>> {
        self.stages
            .iter_mut()
            .fold(packets, |packets, stage| stage.process(packets))
    }
}

#[non_exhaustive]
pub struct Passthrough;

impl Passthrough {
    pub fn new() -> Self {
        Self {}
    }
}

impl PipelineStage for Passthrough {
    fn start(&mut self) -> Result<(), Box<dyn Error>> {
        // nothing to do
        Ok(())
    }

    fn update_config(&mut self, _: &Config) -> Result<(), Box<dyn Error>> {
        Ok(())
    }

    fn process(
        &mut self,
        packets: Box<dyn Iterator<Item = MetaPacket>>,
    ) -> Box<dyn Iterator<Item = MetaPacket>> {
        packets
    }
}
