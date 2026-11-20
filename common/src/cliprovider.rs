// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! A trait for a type that can provide CLI data

use clock::{Duration, Instant};
use concurrency::slot::{Slot, SlotOption};
use concurrency::sync::Arc;
use left_right::ReadHandle;
use std::fmt::Display;

/// A trait for types that can produce contents for the cli
pub trait CliDataProvider {
    fn provide(&self) -> String;
}

pub trait CliSource: Display {}

impl<T> CliDataProvider for T
where
    T: CliSource,
{
    fn provide(&self) -> String {
        self.to_string()
    }
}

impl<T> CliDataProvider for Arc<T>
where
    T: CliDataProvider,
{
    fn provide(&self) -> String {
        self.as_ref().provide()
    }
}

impl<T> CliDataProvider for Option<T>
where
    T: CliDataProvider,
{
    fn provide(&self) -> String {
        match self {
            Some(value) => value.provide(),
            None => "(none)".to_string(),
        }
    }
}

impl<T> CliDataProvider for ReadHandle<T>
where
    T: CliDataProvider,
{
    fn provide(&self) -> String {
        if let Some(data) = &self.enter() {
            data.provide()
        } else {
            "inaccessible".to_string()
        }
    }
}

impl<T> CliDataProvider for Slot<T>
where
    T: CliDataProvider,
{
    fn provide(&self) -> String {
        self.load().provide()
    }
}

impl<T> CliDataProvider for SlotOption<T>
where
    T: CliDataProvider,
{
    fn provide(&self) -> String {
        // No type annotation on `p`: `arc_swap::ArcSwapOption` always
        // yields `std::sync::Arc<T>`, which is not the same type as
        // `concurrency::sync::Arc<T>` under the `loom` backend.
        // Letting inference do its job keeps this `impl` compiling on
        // every backend.
        self.load()
            .as_ref()
            .map(|p| p.provide())
            .unwrap_or_else(|| "(none)".to_string())
    }
}

trait CliString: AsRef<str> + Display {}
impl CliString for String {}
impl CliString for &str {}

pub struct Heading<T>(pub T);
impl<T: CliString> Display for Heading<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, " {:━^100}", format!(" {} ", self.0))
    }
}

pub struct Frame<T>(pub T);
impl<T: CliString> Display for Frame<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let len = self.0.as_ref().len() + 2;
        writeln!(f, "\n┏{:━<width$}┓", "━", width = len)?;
        writeln!(f, "┃ {} ┃", self.0)?;
        writeln!(f, "┗{:━<width$}┛", "━", width = len)
    }
}

pub fn line(f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    Heading("─").fmt(f)
}

pub struct PrettyDuration(Duration);
impl PrettyDuration {
    #[must_use]
    pub fn new(d: Duration) -> Self {
        Self(d)
    }
}
impl Display for PrettyDuration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let secs = self.0.as_secs();
        let weeks = secs / (7 * 24 * 3600);
        let days = secs / (24 * 3600) % 7;
        let hours = secs / 3600 % 24;
        let minutes = secs / 60 % 60;
        let seconds = secs % 60;

        if weeks > 0 {
            write!(f, "{weeks:02}w")?;
        }
        if days > 0 {
            write!(f, "{days:02}d")?;
        }
        write!(f, "{hours:02}:{minutes:02}:{seconds:02}")?;
        Ok(())
    }
}

pub struct Age(Instant);
impl Age {
    #[must_use]
    pub fn from_instant(instant: Instant) -> Self {
        Self(instant)
    }
}
impl Display for Age {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        PrettyDuration::new(clock::elapsed(self.0)).fmt(f)
    }
}

/// A link speed, given in Mbit/s, the way switches write it: whole or fractional gigabits
/// ("25G", "2.5G"), or megabits below one ("100M").
pub struct PrettySpeed(u32);
impl PrettySpeed {
    #[must_use]
    pub fn new(mbps: u32) -> Self {
        Self(mbps)
    }
}
impl Display for PrettySpeed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mbps = self.0;
        if mbps < 1000 {
            write!(f, "{mbps}M")
        } else if mbps.is_multiple_of(1000) {
            write!(f, "{}G", mbps / 1000)
        } else {
            let fraction = format!("{:03}", mbps % 1000);
            write!(f, "{}.{}G", mbps / 1000, fraction.trim_end_matches('0'))
        }
    }
}

#[cfg(test)]
mod test {
    use super::{Frame, Heading, PrettySpeed};

    /// Speeds that are not whole gigabits keep their fraction, and slow links show megabits.
    #[test]
    fn speeds_are_not_truncated() {
        for (mbps, shown) in [
            (10, "10M"),
            (100, "100M"),
            (1_000, "1G"),
            (2_500, "2.5G"),
            (1_250, "1.25G"),
            (25_000, "25G"),
            (400_000, "400G"),
        ] {
            assert_eq!(PrettySpeed::new(mbps).to_string(), shown);
        }
    }

    #[test]
    fn test_heading() {
        println!("{}", Heading("Hi there!"));
        println!("{}", Heading("Hey ho!".to_string()));
        println!("{}", Heading(format!("I have {} cents", 5)));
        println!("{}", Frame("This is a box, not a Box<T> though"));
        println!("{}", Frame("smaller"));
    }
}
