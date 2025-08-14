// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::register::Registered;
use crate::{MetricSpec, PacketAndByte, Register};
use metrics::{Level, Unit};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use vpcmap::VpcDiscriminant;

pub trait Specification {
    type Output;
    fn build(self) -> Self::Output;
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CountAndRateSpec {
    pub count: MetricSpec,
    pub rate: MetricSpec,
}

impl CountAndRateSpec {
    fn new(base_id: impl Into<String>, action: impl Into<String>) -> CountAndRateSpec {
        let base_id = base_id.into();
        let count_id = base_id.clone() + "_count";
        let rate_id = base_id + "_rate";
        let count_action = action.into();
        let rate_action = count_action.clone();
        CountAndRateSpec {
            count: MetricSpec::new(count_id, count_action, Unit::Count),
            rate: MetricSpec::new(rate_id, rate_action, Unit::BitsPerSecond),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct RegisteredCountAndRate {
    pub count: Registered<metrics::Counter>,
    pub rate: Registered<metrics::Gauge>,
}

impl Specification for CountAndRateSpec {
    type Output = RegisteredCountAndRate;

    fn build(self) -> RegisteredCountAndRate {
        RegisteredCountAndRate {
            count: self.count.register(),
            rate: self.rate.register(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PacketAndByteSpec {
    pub packet: CountAndRateSpec,
    pub byte: CountAndRateSpec,
}

impl PacketAndByteSpec {
    fn new(base_id: impl Into<String>, action: impl Into<String>) -> PacketAndByteSpec {
        let base_id = base_id.into();
        let packet_id = base_id.clone() + "_packet";
        let byte_id = base_id + "_byte";
        let packet_action = action.into();
        let byte_action = packet_action.clone();
        PacketAndByteSpec {
            packet: CountAndRateSpec::new(packet_id, packet_action),
            byte: CountAndRateSpec::new(byte_id, byte_action),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct RegisteredPacketAndByte {
    pub packet: RegisteredCountAndRate,
    pub byte: RegisteredCountAndRate,
}

impl Specification for PacketAndByteSpec {
    type Output = RegisteredPacketAndByte;

    fn build(self) -> RegisteredPacketAndByte {
        RegisteredPacketAndByte {
            packet: self.packet.build(),
            byte: self.byte.build(),
        }
    }
}

#[derive(Debug)]
pub struct BasicActionSpec {
    pub rx: PacketAndByteSpec,
    pub tx: PacketAndByteSpec,
}

#[derive(Debug, Serialize)]
pub struct BasicAction<T> {
    pub rx: PacketAndByte<T>,
    pub tx: PacketAndByte<T>,
}

impl BasicActionSpec {
    fn new(base_id: impl Into<String>) -> BasicActionSpec {
        let base_id = base_id.into();
        let rx_id = base_id.clone() + "_rx";
        let tx_id = base_id + "_tx";
        BasicActionSpec {
            rx: PacketAndByteSpec::new(rx_id, "rx"),
            tx: PacketAndByteSpec::new(tx_id, "tx"),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct RegisteredBasicAction {
    pub rx: RegisteredPacketAndByte,
    pub tx: RegisteredPacketAndByte,
}

impl Specification for BasicActionSpec {
    type Output = RegisteredBasicAction;

    fn build(self) -> RegisteredBasicAction {
        RegisteredBasicAction {
            rx: self.rx.build(),
            tx: self.tx.build(),
        }
    }
}

pub struct VpcMetricsSpec {
    pub total: BasicActionSpec,
    pub peering: HashMap<VpcDiscriminant, BasicActionSpec>,
}

impl VpcMetricsSpec {
    pub fn new(
        names: impl Iterator<Item = (impl AsRef<VpcDiscriminant>, impl Into<String>)>,
    ) -> VpcMetricsSpec {
        VpcMetricsSpec {
            total: BasicActionSpec::new("pipeline"),
            peering: names
                .map(|(disc, name)| (*disc.as_ref(), BasicActionSpec::new(name)))
                .collect(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct RegisteredVpcMetrics {
    pub total: RegisteredBasicAction,
    pub peering: BTreeMap<VpcDiscriminant, RegisteredBasicAction>,
}

#[derive(Debug, Serialize)]
pub struct VpcMetrics<T> {
    pub total: BasicAction<T>,
    pub peering: BTreeMap<VpcDiscriminant, BasicAction<T>>,
}

impl Specification for VpcMetricsSpec {
    type Output = RegisteredVpcMetrics;

    fn build(self) -> RegisteredVpcMetrics {
        RegisteredVpcMetrics {
            total: self.total.build(),
            peering: self
                .peering
                .into_iter()
                .map(|(disc, spec)| (disc, spec.build()))
                .collect(),
        }
    }
}

pub struct PipelineMetricsSpec {
    pub total: BasicActionSpec,
    pub vpc: BTreeMap<VpcDiscriminant, VpcMetricsSpec>,
}

#[derive(Debug, Serialize)]
pub struct RegisteredPipelineMetrics {
    pub total: RegisteredBasicAction,
    vpc: BTreeMap<VpcDiscriminant, RegisteredVpcMetrics>,
}

impl Specification for PipelineMetricsSpec {
    type Output = RegisteredPipelineMetrics;

    fn build(self) -> RegisteredPipelineMetrics {
        RegisteredPipelineMetrics {
            total: self.total.build(),
            vpc: self
                .vpc
                .into_iter()
                .map(|(disc, spec)| (disc, spec.build()))
                .collect(),
        }
    }
}

impl RegisteredPipelineMetrics {
    pub fn vpc(&self, disc: &VpcDiscriminant) -> Option<&RegisteredVpcMetrics> {
        self.vpc.get(disc)
    }

    pub fn vpcs(&self) -> impl Iterator<Item = (&VpcDiscriminant, &RegisteredVpcMetrics)> {
        self.vpc.iter()
    }
}

impl RegisteredVpcMetrics {
    pub fn peer(&self, disc: &VpcDiscriminant) -> Option<&RegisteredBasicAction> {
        self.peering.get(disc)
    }

    pub fn peers(&self) -> impl Iterator<Item = (&VpcDiscriminant, &RegisteredBasicAction)> {
        self.peering.iter()
    }
}
