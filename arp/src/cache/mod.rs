// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! ARP/ND cache, populated by netlink events

#![deny(clippy::all, clippy::pedantic)]
#![allow(clippy::collapsible_if)]

#[allow(clippy::module_inception)]
mod cache;
mod cacherw;
mod display;
mod listener;

pub use cache::{NeighCache, NeighEntry, NeighState};
pub(crate) use cacherw::NeighCacheWriter;
pub use cacherw::{NeighCacheError, NeighCacheReader, NeighCacheReaderFactory};
pub(crate) use listener::NeighListener;
