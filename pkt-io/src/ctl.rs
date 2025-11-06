// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Pkt IO controller management.
//! This module defines the public interface to control the IO packet manager.
//! The control is exerted over a channel via which the IO packet manager is told
//! the taps it should be moving packets for.

use net::interface::InterfaceName;
use std::collections::HashSet;
use std::fmt::Display;
use tokio::sync::mpsc::Sender;
use tokio::sync::mpsc::error::SendError;

#[derive(Debug, Clone)]
pub struct TapSet(pub(crate) HashSet<InterfaceName>);
impl TapSet {
    #[must_use]
    pub(crate) fn new() -> Self {
        Self(HashSet::new())
    }
    fn add(&mut self, tapname: InterfaceName) {
        self.0.insert(tapname);
    }
    fn del(&mut self, tapname: &InterfaceName) {
        self.0.remove(tapname);
    }
    pub(crate) fn iter(&self) -> impl Iterator<Item = &InterfaceName> {
        self.0.iter()
    }
    pub(crate) fn contains(&self, tapname: &InterfaceName) -> bool {
        self.0.contains(tapname)
    }
    pub(crate) fn clear(&mut self) {
        self.0.clear();
    }
}

/// The internal messages to control an [`crate::io::IoManager`].
pub enum IoManagerMsg {
    Enable(TapSet),
    Stop,
}

/// The object used to drive an [`IoManager`].
/// This object:
///    - can keep a set of tap specifications internally.
///    - calling commit on it issues a config request.
///    - can be cloned.
pub struct IoManagerCtl {
    tapset: TapSet,
    sender: Sender<IoManagerMsg>,
}
impl Clone for IoManagerCtl {
    fn clone(&self) -> Self {
        Self {
            tapset: TapSet::new(), // we don't clone the internal set for convenience
            sender: self.sender.clone(),
        }
    }
}
impl IoManagerCtl {
    #[must_use]
    pub(crate) fn new(sender: Sender<IoManagerMsg>) -> Self {
        Self {
            tapset: TapSet::new(),
            sender,
        }
    }
    pub fn add(&mut self, tapname: InterfaceName) {
        self.tapset.add(tapname);
    }
    pub fn del(&mut self, tapname: &InterfaceName) {
        self.tapset.del(tapname);
    }
    pub fn clear(&mut self) {
        self.tapset.clear();
    }
    /// Send a request to the IO manager with the taps in the local [`TapSet`].
    ///
    /// # Errors
    ///
    /// May fail if the channel has been closed
    pub async fn commit(&mut self) -> Result<(), SendError<IoManagerMsg>> {
        self.sender
            .send(IoManagerMsg::Enable(self.tapset.clone()))
            .await
    }

    /// Request the IO manager to stop. This stops the IO manager service.
    ///
    /// # Errors
    ///
    /// May fail if the channel has been closed
    pub async fn stop(&mut self) -> Result<(), SendError<IoManagerMsg>> {
        self.sender.send(IoManagerMsg::Stop).await
    }
}

impl Display for TapSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "━━━━ Interfaces to be active ━━━━")?;
        for spec in &self.0 {
            writeln!(f, "{spec}")?;
        }
        Ok(())
    }
}
