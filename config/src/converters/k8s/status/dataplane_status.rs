// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};

use k8s_intf::gateway_agent_crd::{
    GatewayAgentStatus, GatewayAgentStatusState, GatewayAgentStatusStateDataplane,
    GatewayAgentStatusStateFrr, GatewayAgentStatusStatePeerings, GatewayAgentStatusStateVpcs,
};

use crate::converters::k8s::ToK8sConversionError;
use crate::internal::status::DataplaneStatus;

pub struct DataplaneStatusForK8sConversion<'a> {
    pub last_applied_gen: Option<i64>,
    pub last_applied_time: Option<&'a DateTime<Utc>>,
    pub last_collected_time: Option<&'a DateTime<Utc>>,
    pub last_heartbeat: Option<&'a DateTime<Utc>>,
    pub status: Option<&'a DataplaneStatus>,
}

impl TryFrom<&DataplaneStatusForK8sConversion<'_>> for GatewayAgentStatus {
    type Error = ToK8sConversionError;

    fn try_from(status: &DataplaneStatusForK8sConversion<'_>) -> Result<Self, Self::Error> {
        if status.last_applied_time.is_none() && status.last_applied_gen.is_some() {
            return Err(ToK8sConversionError::MissingData(
                "last_applied_gen is set, but last_applied_time is not".to_string(),
            ));
        }

        if status.last_collected_time.is_none() && status.status.is_some() {
            return Err(ToK8sConversionError::MissingData(
                "status is set, but last_collected_time is not".to_string(),
            ));
        }

        let frr_status = status
            .status
            .and_then(|status| {
                status
                    .frr_status
                    .as_ref()
                    .map(GatewayAgentStatusStateFrr::try_from)
            })
            .transpose()?;

        let vpcs = status
            .status
            .map(|status| {
                status
                    .vpc_counters
                    .iter()
                    .map(|(k, v)| Ok((k.clone(), GatewayAgentStatusStateVpcs::try_from(v)?)))
                    .collect::<Result<BTreeMap<_, _>, _>>()
            })
            .transpose()?;

        let peerings = status
            .status
            .map(|status| {
                status
                    .vpc_peering_counters
                    .iter()
                    .map(|(k, v)| Ok((k.clone(), GatewayAgentStatusStatePeerings::try_from(v)?)))
                    .collect::<Result<BTreeMap<_, _>, _>>()
            })
            .transpose()?;

        Ok(GatewayAgentStatus {
            agent_version: None,
            last_applied_gen: status.last_applied_gen,
            last_applied_time: status
                .last_applied_time
                .map(|lat| lat.to_rfc3339_opts(chrono::SecondsFormat::Nanos, true)),
            last_heartbeat: status
                .last_heartbeat
                .map(|lhb| lhb.to_rfc3339_opts(chrono::SecondsFormat::Nanos, true)),
            state: status.status.map(|_| GatewayAgentStatusState {
                dataplane: Some(GatewayAgentStatusStateDataplane {
                    version: Some(option_env!("VERSION").unwrap_or("dev").to_string()),
                }),
                frr: frr_status,
                last_collected_time: status
                    .last_collected_time
                    .map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Nanos, true)),
                peerings: peerings.filter(|c| !c.is_empty()),
                vpcs: vpcs.filter(|c| !c.is_empty()),
            }),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use bolero::generator::*;
    use bolero::{Driver, TypeGenerator};
    use chrono::TimeZone;

    use crate::internal::status::DataplaneStatus;
    use crate::internal::status::contract::LegalValue;

    fn datetime_gen() -> impl ValueGenerator<Output = DateTime<Utc>> {
        (0..=i64::from(i32::MAX)).map_gen(|ts| Utc.timestamp_opt(ts, 0).unwrap())
    }

    #[derive(Debug)]
    struct DataplaneStatusForK8sConversionOwned {
        last_applied_gen: Option<i64>,
        last_applied_time: Option<DateTime<Utc>>,
        last_collected_time: Option<DateTime<Utc>>,
        last_heartbeat: Option<DateTime<Utc>>,
        status: Option<DataplaneStatus>,
    }

    impl TypeGenerator for LegalValue<DataplaneStatusForK8sConversionOwned> {
        fn generate<D: Driver>(d: &mut D) -> Option<Self> {
            let time_gen = datetime_gen();
            let last_applied_gen = d.produce()?;
            let last_applied_time = time_gen.generate(d)?;
            let status = d
                .produce::<Option<LegalValue<DataplaneStatus>>>()?
                .map(|v| v.take());
            let last_collected_time_raw = time_gen.generate(d)?;
            let last_collected_time = status.as_ref().map(|_| last_collected_time_raw);
            let last_heartbeat_raw = time_gen.generate(d)?;
            let last_heartbeat = status.as_ref().map(|_| last_heartbeat_raw);
            Some(LegalValue::new(DataplaneStatusForK8sConversionOwned {
                status,
                last_collected_time,
                last_heartbeat,
                last_applied_gen,
                last_applied_time: last_applied_gen.map(|_| last_applied_time),
            }))
        }
    }

    #[test]
    fn test_dataplane_status_conversion() {
        bolero::check!()
            .with_type::<LegalValue<DataplaneStatusForK8sConversionOwned>>()
            .for_each(|status_owned| {
                let status_owned = status_owned.as_ref();
                let conv_status = DataplaneStatusForK8sConversion {
                    status: status_owned.status.as_ref(),
                    last_collected_time: status_owned.last_collected_time.as_ref(),
                    last_heartbeat: status_owned.last_heartbeat.as_ref(),
                    last_applied_gen: status_owned.last_applied_gen,
                    last_applied_time: status_owned.last_applied_time.as_ref(),
                };

                let gateway_agent_status = GatewayAgentStatus::try_from(&conv_status).unwrap();

                assert_eq!(
                    gateway_agent_status.last_applied_gen,
                    conv_status.last_applied_gen
                );
                assert_eq!(
                    gateway_agent_status.last_applied_time,
                    conv_status
                        .last_applied_time
                        .map(|lat| lat.to_rfc3339_opts(chrono::SecondsFormat::Nanos, true))
                );
                assert_eq!(
                    gateway_agent_status
                        .state
                        .as_ref()
                        .and_then(|s| s.last_collected_time.clone()),
                    conv_status
                        .last_collected_time
                        .map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Nanos, true))
                );

                assert_eq!(
                    conv_status.status.is_some(),
                    gateway_agent_status.state.is_some()
                );

                if let Some(state) = gateway_agent_status.state.as_ref() {
                    assert!(state.frr.is_some()); // Specifics tested elsewhere

                    match state.vpcs.as_ref() {
                        Some(vpcs) => {
                            // Specifics tested elsewhere
                            assert_eq!(
                                vpcs.len(),
                                conv_status
                                    .status
                                    .expect("status should not be None")
                                    .vpc_counters
                                    .len()
                            );
                        }
                        None => {
                            assert!(
                                conv_status.status.is_none()
                                    || conv_status.status.unwrap().vpc_counters.is_empty()
                            );
                        }
                    }

                    match state.peerings.as_ref() {
                        // Specifics tested elsewhere
                        Some(peerings) => assert_eq!(
                            peerings.len(),
                            conv_status
                                .status
                                .expect("status should not be None")
                                .vpc_peering_counters
                                .len()
                        ),
                        None => assert!(
                            conv_status.status.is_none()
                                || conv_status.status.unwrap().vpc_peering_counters.is_empty()
                        ),
                    }
                }
            });
    }
}
