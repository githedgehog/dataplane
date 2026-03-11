// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! A trait for a type that can provide CLI data

use left_right::ReadHandle;
use std::sync::Arc;

pub enum CliData {}

/// A trait for types that can produce contents for the cli
pub trait CliDataProvider: Send {
    fn provide(&self, what: Option<CliData>) -> String;
}

impl<T> CliDataProvider for Arc<T>
where
    T: Send + Sync + CliDataProvider,
{
    fn provide(&self, what: Option<CliData>) -> String {
        self.as_ref().provide(what)
    }
}

impl<T> CliDataProvider for ReadHandle<T>
where
    T: Send + Sync + CliDataProvider,
{
    fn provide(&self, what: Option<CliData>) -> String {
        if let Some(data) = &self.enter() {
            data.provide(what)
        } else {
            "inaccessible".to_string()
        }
    }
}
