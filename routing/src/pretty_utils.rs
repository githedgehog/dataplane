// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Some utility helpers to implement Display

use std::fmt::Display;

const LINE_WIDTH: usize = 81;

pub struct Frame(pub String);
impl Display for Frame {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let len = self.0.len() + 2;
        writeln!(f, "\n┏{:━<width$}┓", "━", width = len)?;
        writeln!(f, "┃ {} ┃", self.0)?;
        writeln!(f, "┗{:━<width$}┛", "━", width = len)
    }
}
pub struct Heading(pub String);
impl Display for Heading {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let len = (LINE_WIDTH - (self.0.len() + 2)) / 2;
        write!(f, " {0:─<width$}", "─", width = len)?;
        write!(f, " {} ", self.0)?;
        writeln!(f, " {0:─<width$}", "─", width = len)
    }
}
pub fn line(f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    writeln!(f, " {0:─<width$}", "─", width = LINE_WIDTH)
}
