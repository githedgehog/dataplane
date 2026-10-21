// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Named meter counters and their ordered rules.

use crate::rules::{RateLimitReader, RateLimits, Unit};
use common::cliprovider::CliDataProvider;
use policer::Color;
use std::fmt::{self, Display, Formatter};

impl<C> Display for RateLimits<C> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if self.meters().is_empty() {
            return writeln!(f, "no rate limits are configured");
        }
        for meter in self.meters() {
            writeln!(f, "meter {}", meter.name())?;
            for unit in Unit::ALL {
                let Some(component) = meter.component(unit) else {
                    continue;
                };
                writeln!(f, "  {}: {}", unit.label(), component.profile())?;
                for (label, color) in [
                    ("conforming", Color::Green),
                    ("excess", Color::Yellow),
                    ("over limit", Color::Red),
                ] {
                    let (packets, bytes) = component.counted(color);
                    writeln!(f, "  {label:<10} {packets:>12} packets {bytes:>16} bytes")?;
                }
            }
        }
        for (index, rule) in self.rules().iter().enumerate() {
            writeln!(
                f,
                "rule {index}: {} -> meter {}",
                rule.matches(),
                self.meters()[rule.meter()].name()
            )?;
        }
        Ok(())
    }
}
impl<C> CliDataProvider for RateLimitReader<C> {
    fn provide(&self) -> String {
        self.load().to_string()
    }
}
