//! DPDK queue abstractions.
pub mod rx;
pub mod tx;
pub mod hairpin;

#[derive(Debug)]
pub enum QueueState {
    Unconfigured,
    Stopped,
    Started,
}

