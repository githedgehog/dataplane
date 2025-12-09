// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use std::collections::BTreeMap;
use std::ops::Bound;

use bolero::{Driver, TypeGenerator};

use crate::bolero::LegalValue;
use crate::gateway_agent_crd::GatewayAgentGatewayLogs;

const LEVELS: &[&str] = &["off", "error", "warning", "info", "debug", "trace"];

struct LogLevel(String);
impl TypeGenerator for LogLevel {
    fn generate<D: Driver>(d: &mut D) -> Option<Self> {
        Some(LogLevel(
            LEVELS[d.gen_usize(Bound::Included(&0), Bound::Excluded(&LEVELS.len()))?].to_string(),
        ))
    }
}

const KNOWN_TAGS: &[&str] = &["kernel-driver", "driver", "unknown-1", "unknown-2"];

struct LogTag(String);
impl TypeGenerator for LogTag {
    fn generate<D: Driver>(d: &mut D) -> Option<Self> {
        Some(LogTag(
            KNOWN_TAGS[d.gen_usize(Bound::Included(&0), Bound::Excluded(&KNOWN_TAGS.len()))?]
                .to_string(),
        ))
    }
}

/// Generate a random log configuration
///
/// This does not attempt to be exhaustive over all possible tags, but
/// will generate every log level for any of the tags it can generate.
///
/// Tags may be repeated, but that should be handled by the parser gracefully
impl TypeGenerator for LegalValue<GatewayAgentGatewayLogs> {
    fn generate<D: Driver>(d: &mut D) -> Option<Self> {
        let mut tags = None;
        let num_tags = d.gen_usize(Bound::Included(&0), Bound::Excluded(&KNOWN_TAGS.len()))?;
        if num_tags > 0 {
            let mut tag_levels = BTreeMap::new();
            for _ in 0..num_tags {
                tag_levels.insert(d.produce::<LogTag>()?.0, d.produce::<LogLevel>()?.0);
            }
            tags = Some(tag_levels);
        }
        Some(LegalValue(GatewayAgentGatewayLogs {
            default: d
                .produce::<Option<LogLevel>>()?
                .map(|log_level| log_level.0),
            tags,
        }))
    }
}
