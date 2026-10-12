// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Rendering rate limits for the CLI.

use crate::rules::{RateLimitReader, RateLimits};
use common::cliprovider::CliDataProvider;
use config::external::overlay::ratelimit::ColorAction;
use policer::Color;
use std::fmt::{self, Display, Formatter};

fn action(action: ColorAction) -> String {
    match action {
        ColorAction::Pass => "pass".to_string(),
        ColorAction::Remark(dscp) => format!("remark dscp {dscp}"),
        ColorAction::Drop => "drop".to_string(),
    }
}

/// One block per rule:
///
/// ```text
/// rate limit web: from vpc-1 (vni 3000) to 10.1.0.0/16
///   limits: bytes: srTCM cir 1250000/s cbs 15000 ebs 0
///   green:  pass               1200 packets       1800000 bytes
///   yellow: remark dscp 10        0 packets             0 bytes
///   red:    drop                 37 packets         55500 bytes
/// ```
impl<C> Display for RateLimits<C> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if self.rules.is_empty() {
            return writeln!(f, "no rate limits are configured");
        }
        for rule in &self.rules {
            writeln!(f, "rate limit {}: {}", rule.name(), rule.matches())?;
            writeln!(f, "  limits: {}", rule.limits())?;
            for (label, color) in [
                ("green:", Color::Green),
                ("yellow:", Color::Yellow),
                ("red:", Color::Red),
            ] {
                let (packets, bytes) = rule.counted(color);
                writeln!(
                    f,
                    "  {label:<7} {:<16} {packets:>12} packets {bytes:>16} bytes",
                    action(rule.action(color))
                )?;
            }
        }
        Ok(())
    }
}

impl<C> CliDataProvider for RateLimitReader<C> {
    fn provide(&self) -> String {
        self.load().to_string()
    }
}
