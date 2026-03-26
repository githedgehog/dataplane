// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! A trait for a type that can provide CLI data

use arc_swap::{ArcSwap, ArcSwapOption};
use left_right::ReadHandle;
use std::fmt::Display;
use std::sync::Arc;

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

impl<T> CliDataProvider for ArcSwap<T>
where
    T: CliDataProvider,
{
    fn provide(&self) -> String {
        self.load().provide()
    }
}

impl<T> CliDataProvider for ArcSwapOption<T>
where
    T: CliDataProvider,
{
    fn provide(&self) -> String {
        self.load()
            .as_ref()
            .map(|p: &Arc<T>| p.provide())
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
