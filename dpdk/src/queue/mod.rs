//! DPDK queue abstractions.
pub mod rx;
pub mod tx;
pub mod hairpin;

/// The possible states of a DPDK queue
#[derive(Debug)]
pub enum QueueState {
    /// An unconfigured queue
    Unconfigured,
    /// A stopped queue
    Stopped,
    /// A started queue
    Started,
}

