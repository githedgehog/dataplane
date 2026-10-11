// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Where a port's frames go.

use tokio::sync::mpsc;

/// Why a [`FrameSink`] did not take a frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Refused {
    /// The port's transmit queue is full; the frame is lost, but the port is still there.
    #[error("the port's transmit queue is full")]
    Full,
    /// The port is gone.
    #[error("the port is gone")]
    Closed,
}

/// The transmit side of one port.
///
/// It must not block: a full queue refuses the frame, and the next advertisement replaces it.
pub trait FrameSink: Send {
    /// Queue `frame` for transmission out of the port.
    ///
    /// # Errors
    ///
    /// Refuses the frame if the queue is full or the port is gone.
    fn send(&mut self, frame: Vec<u8>) -> Result<(), Refused>;
}

impl FrameSink for mpsc::Sender<Vec<u8>> {
    fn send(&mut self, frame: Vec<u8>) -> Result<(), Refused> {
        self.try_send(frame).map_err(|error| match error {
            mpsc::error::TrySendError::Full(_) => Refused::Full,
            mpsc::error::TrySendError::Closed(_) => Refused::Closed,
        })
    }
}
