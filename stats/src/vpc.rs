// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::register::Registered;
use crate::{MetricSpec, PacketAndByte, Register};
use metrics::Unit;
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
    fn new(base_id: impl Into<String>, labels: Vec<(String, String)>) -> CountAndRateSpec {
        let base_id = base_id.into();
        let count_id = base_id.clone() + "_count";
        let rate_id = base_id + "_rate";
        CountAndRateSpec {
            count: MetricSpec::new(count_id, Unit::Count, labels.clone()),
            rate: MetricSpec::new(rate_id, Unit::BitsPerSecond, labels), // todo: bits or bytes?
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
    fn new(base_id: impl Into<String>, labels: Vec<(String, String)>) -> PacketAndByteSpec {
        let base_id = base_id.into();
        let packet_id = base_id.clone() + "_packet";
        let byte_id = base_id + "_byte";

        PacketAndByteSpec {
            packet: CountAndRateSpec::new(packet_id, labels.clone()),
            byte: CountAndRateSpec::new(byte_id, labels),
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
    pub tx: PacketAndByteSpec,
}

#[derive(Debug, Serialize)]
pub struct BasicAction<T> {
    pub tx: PacketAndByte<T>,
}

impl BasicActionSpec {
    fn new(base_id: impl Into<String>, labels: Vec<(String, String)>) -> BasicActionSpec {
        let base_id = base_id.into();
        BasicActionSpec {
            tx: PacketAndByteSpec::new(base_id, labels),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct RegisteredBasicAction {
    pub tx: RegisteredPacketAndByte,
}

impl Specification for BasicActionSpec {
    type Output = RegisteredBasicAction;

    fn build(self) -> RegisteredBasicAction {
        RegisteredBasicAction {
            tx: self.tx.build(),
        }
    }
}

pub struct VpcMetricsSpec {
    pub total: BasicActionSpec,
    pub peering: HashMap<VpcDiscriminant, BasicActionSpec>,
}

impl VpcMetricsSpec {
    #[allow(clippy::type_complexity)]
    pub fn new(
        vpc_data: Vec<(VpcDiscriminant, String, Vec<(String, String)>)>,
    ) -> Vec<(VpcDiscriminant, VpcMetricsSpec)> {
        vpc_data
            .iter()
            .map(|(src_disc, src_name, labels)| {
                let mut total_labels = labels.clone();
                total_labels.push(("total".to_string(), src_name.clone()));
                (
                    *src_disc,
                    VpcMetricsSpec {
                        total: BasicActionSpec::new("vpc", total_labels),
                        peering: vpc_data
                            .iter()
                            .map(|(dst_disc, dst_name, labels)| {
                                let mut labels = labels.clone();
                                labels.push(("from".to_string(), src_name.clone()));
                                labels.push(("to".to_string(), dst_name.clone()));
                                (*dst_disc, BasicActionSpec::new("vpc", labels))
                            })
                            .collect(),
                    },
                )
            })
            .collect()
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
