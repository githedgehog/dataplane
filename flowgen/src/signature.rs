// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! What every generated packet carries, so that whatever comes back can be traced to what was sent.
//!
//! The signature leads the innermost UDP payload. Nothing a dataplane does to headers -- NAT,
//! encapsulation, decapsulation -- touches it, so a returning packet names its flow and its place
//! in that flow however its headers were rewritten.

/// Marks a payload as carrying a [`Signature`].
pub const MAGIC: [u8; 4] = *b"fgen";

/// Bytes a signature takes.
pub const LEN: usize = 32;

/// A packet's identity, as its payload carries it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Signature {
    /// The run that sent it, so that a stray packet from another run is not mistaken for ours.
    pub run: u32,
    /// Its flow's number in its stream's flow space.
    pub flow: u64,
    /// Its place in its flow, from zero.
    pub seq: u64,
    /// When it was sent, in nanoseconds on the sender's clock.
    pub tx_ns: u64,
}

impl Signature {
    /// Write the signature into the first [`LEN`] bytes of `out`.
    ///
    /// # Panics
    ///
    /// If `out` is shorter than [`LEN`]; templates are built with room for it.
    pub fn write(&self, out: &mut [u8]) {
        let out = &mut out[..LEN];
        out[0..4].copy_from_slice(&MAGIC);
        out[4..8].copy_from_slice(&self.run.to_be_bytes());
        out[8..16].copy_from_slice(&self.flow.to_be_bytes());
        out[16..24].copy_from_slice(&self.seq.to_be_bytes());
        out[24..32].copy_from_slice(&self.tx_ns.to_be_bytes());
    }

    /// The signature leading `payload`, if it carries one.
    #[must_use]
    pub fn read(payload: &[u8]) -> Option<Signature> {
        let bytes = payload.get(..LEN)?;
        if bytes[0..4] != MAGIC {
            return None;
        }
        let word = |at: usize| {
            let mut w = [0; 8];
            w.copy_from_slice(&bytes[at..at + 8]);
            u64::from_be_bytes(w)
        };
        Some(Signature {
            run: u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
            flow: word(8),
            seq: word(16),
            tx_ns: word(24),
        })
    }
}
