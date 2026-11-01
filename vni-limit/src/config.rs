// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! The limits to install, read from YAML and validated before DPDK starts.
//!
//! ```yaml
//! vxlan_port: 4789            # optional, the default
//! limits:
//!   - vni: 100
//!     rate_bps: 100000000     # bits per second of outer IP packets
//!   - vni: 100
//!     inner_dst: 10.1.0.0/24  # optional: only traffic to this inner destination
//!     rate_bps: 20000000
//!     burst_bytes: 262144     # optional, defaults to 10 ms at the rate
//! ```

use std::fmt::Display;

use ipnet::IpNet;
use net::vxlan::{InvalidVni, Vni};
use serde::Deserialize;

/// The IANA VXLAN port.
const VXLAN_PORT: u16 = 4789;

/// The default burst, as a fraction of a second at the limit's rate.
const DEFAULT_BURST_PER_SECOND: u64 = 100;

/// The smallest default burst: room for a few jumbo frames.
const MIN_DEFAULT_BURST: u64 = 32 * 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    #[serde(default = "vxlan_port")]
    vxlan_port: u16,
    limits: Vec<RawLimit>,
}

fn vxlan_port() -> u16 {
    VXLAN_PORT
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawLimit {
    vni: u32,
    #[serde(default)]
    inner_dst: Option<IpNet>,
    rate_bps: u64,
    #[serde(default)]
    burst_bytes: Option<u64>,
}

/// Validated limits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// The UDP destination port of VXLAN traffic.
    pub vxlan_port: u16,
    /// The limits, each matching different traffic.
    pub limits: Vec<Limit>,
}

/// One limit: traffic of a VNI, optionally only to an inner destination prefix.
///
/// A packet is limited by the most specific limit that matches it, and only by that one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limit {
    /// The VNI.
    pub vni: Vni,
    /// The inner destination prefix, normalized to its network address.
    pub inner_dst: Option<IpNet>,
    /// The committed rate, in bytes of outer IP packets per second.
    pub cir_bytes: u64,
    /// The committed burst, in bytes.
    pub cbs_bytes: u64,
}

impl Display for Limit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "vni {}", self.vni)?;
        if let Some(dst) = self.inner_dst {
            write!(f, " to {dst}")?;
        }
        Ok(())
    }
}

/// Configuration errors.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// Not valid YAML for the schema.
    #[error("invalid configuration: {0}")]
    Yaml(#[from] serde_yaml_ng::Error),
    /// Nothing to do.
    #[error("no limits are configured")]
    Empty,
    /// Port 0 cannot be a VXLAN port.
    #[error("vxlan_port cannot be 0")]
    ZeroPort,
    /// A VNI out of range.
    #[error("limit {index}: {source}")]
    Vni {
        /// The limit's position in the list.
        index: usize,
        /// Why the VNI is invalid.
        source: InvalidVni,
    },
    /// A rate the meter rounds to nothing.
    #[error("limit {index}: {rate_bps} bit/s is less than a byte per second")]
    Rate {
        /// The limit's position in the list.
        index: usize,
        /// The configured rate.
        rate_bps: u64,
    },
    /// A burst of nothing passes nothing.
    #[error("limit {index}: the burst must be at least one byte")]
    Burst {
        /// The limit's position in the list.
        index: usize,
    },
    /// Two limits for the same traffic.
    #[error("limits {first} and {second} both limit {limit}")]
    Duplicate {
        /// The earlier limit's position.
        first: usize,
        /// The later limit's position.
        second: usize,
        /// What they limit.
        limit: String,
    },
}

/// A burst size mlx5 can encode: the largest at most `bytes` (and at least 255/256 of it).
///
/// mlx5 encodes a bucket as an 8-bit mantissa and an exponent, and rounds the mantissa of any size
/// strictly between 255·2^k and 256·2^k up to 256, which overflows to 0: such a bucket passes
/// almost nothing (`mlx5_flow_meter_xbs_man_exp_calc`; see the 2026-10-14 meter spike).
#[must_use]
pub fn encodable_burst(bytes: u64) -> u64 {
    (0..56)
        .map(|k| (255u64 << k, 256u64 << k))
        .find(|&(low, high)| low < bytes && bytes < high)
        .map_or(bytes, |(low, _)| low)
}

impl Config {
    /// Parse and validate a YAML configuration.
    ///
    /// # Errors
    ///
    /// Returns a [`ConfigError`] for malformed YAML, invalid values, or duplicate limits.
    pub fn parse(yaml: &str) -> Result<Config, ConfigError> {
        let raw: RawConfig = serde_yaml_ng::from_str(yaml)?;
        if raw.vxlan_port == 0 {
            return Err(ConfigError::ZeroPort);
        }
        if raw.limits.is_empty() {
            return Err(ConfigError::Empty);
        }
        let mut limits: Vec<Limit> = Vec::with_capacity(raw.limits.len());
        for (index, raw) in raw.limits.into_iter().enumerate() {
            let vni =
                Vni::new_checked(raw.vni).map_err(|source| ConfigError::Vni { index, source })?;
            let cir_bytes = raw.rate_bps / 8;
            if cir_bytes == 0 {
                return Err(ConfigError::Rate {
                    index,
                    rate_bps: raw.rate_bps,
                });
            }
            let burst = raw
                .burst_bytes
                .unwrap_or_else(|| (cir_bytes / DEFAULT_BURST_PER_SECOND).max(MIN_DEFAULT_BURST));
            if burst == 0 {
                return Err(ConfigError::Burst { index });
            }
            let limit = Limit {
                vni,
                inner_dst: raw.inner_dst.map(|dst| dst.trunc()),
                cir_bytes,
                cbs_bytes: encodable_burst(burst),
            };
            if let Some(first) = limits
                .iter()
                .position(|l| (l.vni, l.inner_dst) == (limit.vni, limit.inner_dst))
            {
                return Err(ConfigError::Duplicate {
                    first,
                    second: index,
                    limit: limit.to_string(),
                });
            }
            limits.push(limit);
        }
        Ok(Config {
            vxlan_port: raw.vxlan_port,
            limits,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_full_configuration_parses_and_normalizes() {
        let config = Config::parse(
            "
limits:
  - vni: 100
    rate_bps: 100000000
  - vni: 100
    inner_dst: 10.1.0.7/24
    rate_bps: 20000000
    burst_bytes: 65535
",
        )
        .unwrap();
        assert_eq!(config.vxlan_port, 4789);
        let [whole, prefix] = config.limits.as_slice() else {
            panic!("two limits");
        };
        assert_eq!(whole.cir_bytes, 12_500_000);
        assert_eq!(whole.cbs_bytes, 125_000, "10 ms at the rate");
        assert_eq!(prefix.inner_dst, Some("10.1.0.0/24".parse().unwrap()));
        assert_eq!(
            prefix.cbs_bytes, 65_280,
            "65535 is in a range mlx5 encodes as 0"
        );
    }

    #[test]
    fn the_same_traffic_cannot_be_limited_twice() {
        let error = Config::parse(
            "
limits:
  - {vni: 7, inner_dst: 10.0.0.0/8, rate_bps: 8000}
  - {vni: 7, inner_dst: 10.9.9.9/8, rate_bps: 16000}
",
        )
        .unwrap_err();
        assert!(matches!(
            error,
            ConfigError::Duplicate {
                first: 0,
                second: 1,
                ..
            }
        ));
    }

    #[test]
    fn invalid_values_are_refused() {
        for yaml in [
            "limits: []",
            "vxlan_port: 0\nlimits: [{vni: 1, rate_bps: 8}]",
            "limits: [{vni: 0, rate_bps: 8}]",
            "limits: [{vni: 16777216, rate_bps: 8}]",
            "limits: [{vni: 1, rate_bps: 7}]",
            "limits: [{vni: 1, rate_bps: 8, burst_bytes: 0}]",
            "limits: [{vni: 1, rate_bps: 8, colour: red}]",
        ] {
            assert!(Config::parse(yaml).is_err(), "{yaml}");
        }
    }

    /// The burst never lands where mlx5 encodes it as nothing, and loses at most 1/256.
    #[test]
    fn encodable_bursts_avoid_the_overflowing_mantissa() {
        bolero::check!().with_type::<u64>().for_each(|&bytes| {
            let burst = encodable_burst(bytes);
            assert!(burst <= bytes);
            assert!(u128::from(burst) * 256 >= u128::from(bytes) * 255);
            assert!(
                (0..56).all(|k| !((255u64 << k) < burst && burst < (256u64 << k))),
                "{bytes} -> {burst}"
            );
        });
    }
}
