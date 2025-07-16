// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Utils to build configs to load with frr-reload.py

#![allow(unused)]

use std::fmt::Display;
use std::ops::AddAssign;

pub const MARKER: &str = "!";

#[derive(Debug)]
/// Object to ease building FRR configs.
pub struct ConfigBuilder {
    lines: Vec<String>,
}

/// Impl Display for [`ConfigBuilder`]. This provides to_string().
impl Display for ConfigBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for s in &self.lines {
            writeln!(f, "{s}",)?;
        }
        Ok(())
    }
}

/// Main operations on a [`ConfigBuilder`]
impl ConfigBuilder {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            lines: Vec::with_capacity(2),
        }
    }
    pub fn from_string(string: String) -> Self {
        Self {
            lines: vec![string],
        }
    }
    fn append(&mut self, stanza: &str) {
        match self.lines.last() {
            Some(x) if x == MARKER && stanza == MARKER => {}
            _ => self.lines.push(stanza.to_owned()),
        }
    }
    fn merge(&mut self, other: &mut Self) {
        self.lines.append(&mut other.lines);
        self.dedup();
    }
    fn dedup(&mut self) {
        self.lines.dedup_by(|a, b| a == b && a == MARKER);
    }
}

/// Make it very easy to add config lines to a [`ConfigBuilder`]
impl AddAssign<Self> for ConfigBuilder {
    fn add_assign(&mut self, mut rhs: Self) {
        self.merge(&mut rhs);
    }
}
impl AddAssign<String> for ConfigBuilder {
    fn add_assign(&mut self, rhs: String) {
        self.append(&rhs);
    }
}
impl AddAssign<&str> for ConfigBuilder {
    fn add_assign(&mut self, rhs: &str) {
        self.append(rhs);
    }
}

/// Main trait to build FRR configs for frr-reload.py
pub(crate) trait Render {
    type Context; /* context passed to renderer */
    type Output; /* type of output produced */
    fn render(&self, ctx: &Self::Context) -> Self::Output;
}

pub(crate) trait Rendered {
    fn rendered(&self) -> String;
}
