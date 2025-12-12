// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use tracectl::LevelFilter;

use k8s_intf::gateway_agent_crd::GatewayAgentGatewayLogs;

use crate::{converters::k8s::FromK8sConversionError, internal::device::tracecfg::TracingConfig};

fn levelstring_to_levelfilter(value: Option<&str>) -> Result<LevelFilter, FromK8sConversionError> {
    match value {
        None | Some("off") => Ok(LevelFilter::OFF),
        Some("error") => Ok(LevelFilter::ERROR),
        Some("warning") => Ok(LevelFilter::WARN),
        Some("info") => Ok(LevelFilter::INFO),
        Some("debug") => Ok(LevelFilter::DEBUG),
        Some("trace") => Ok(LevelFilter::TRACE),
        Some(val) => Err(FromK8sConversionError::ParseError(format!(
            "Invalid log level value: {val}"
        ))),
    }
}

// API to internal
impl TryFrom<&GatewayAgentGatewayLogs> for TracingConfig {
    type Error = FromK8sConversionError;
    fn try_from(logs: &GatewayAgentGatewayLogs) -> Result<Self, Self::Error> {
        let default_loglevel = levelstring_to_levelfilter(logs.default.as_deref())?;
        let mut config = TracingConfig::new(default_loglevel);
        if let Some(tags) = logs.tags.as_ref() {
            for (tag, level) in tags {
                let level = levelstring_to_levelfilter(Some(level.as_str()))?;
                config.add_tag(tag, level);
            }
        }
        Ok(config)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use k8s_intf::bolero::LegalValue;

    fn test_levelstring_to_levelfilter(level: &str) -> LevelFilter {
        match level {
            "off" => LevelFilter::OFF,
            "error" => LevelFilter::ERROR,
            "warning" => LevelFilter::WARN,
            "info" => LevelFilter::INFO,
            "debug" => LevelFilter::DEBUG,
            "trace" => LevelFilter::TRACE,
            val => panic!("Invalid log level value: {val}"),
        }
    }

    #[test]
    fn test_tracing_config_conversion() {
        bolero::check!()
            .with_type::<LegalValue<GatewayAgentGatewayLogs>>()
            .for_each(|logs| {
                let logs = logs.as_ref();
                let tc = TracingConfig::try_from(logs).unwrap();
                if let Some(default) = logs.default.as_ref() {
                    let lf = test_levelstring_to_levelfilter(default.as_str());
                    assert_eq!(tc.default, lf);
                }
                if let Some(tags) = logs.tags.as_ref() {
                    for (tag, level) in tags {
                        let level = test_levelstring_to_levelfilter(level.as_str());
                        let tc_level = tc.tags.get(tag).unwrap();
                        assert_eq!(&level, tc_level);
                    }
                }
            });
    }
}
