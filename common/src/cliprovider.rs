// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! A trait for a type that can provide CLI data

use chrono::TimeDelta;
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

pub struct PrettyDuration(TimeDelta);
impl PrettyDuration {
    #[must_use]
    pub fn new(d: Duration) -> Self {
        Self(TimeDelta::from_std(d).unwrap_or(TimeDelta::MAX))
    }
}
impl Display for PrettyDuration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let weeks = self.0.num_weeks();
        let days = self.0.num_days() % 7;
        let hours = self.0.num_hours() % 24;
        let minutes = self.0.num_minutes() % 60;
        let seconds = self.0.num_seconds() % 60;

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

#[cfg(test)]
mod test {
    use super::{Frame, Heading};
    #[test]
    fn test_heading() {
        println!("{}", Heading("Hi there!"));
        println!("{}", Heading("Hey ho!".to_string()));
        println!("{}", Heading(format!("I have {} cents", 5)));
        println!("{}", Frame("This is a box, not a Box<T> though"));
        println!("{}", Frame("smaller"));
    }
}
