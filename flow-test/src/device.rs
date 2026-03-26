// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

// All items in this module are pub(crate) for consumption by the harness
// (Phase 2+). Suppress dead-code warnings until those consumers land.
#![allow(dead_code)]

//! In-process capture device implementing smoltcp's [`Device`] trait.
//!
//! [`CaptureDevice`] backs both its receive and transmit paths with
//! [`VecDeque<Vec<u8>>`] queues, making it possible to inject frames into
//! the smoltcp stack and drain frames that the stack transmits — all without
//! touching the OS network stack.
//!
//! This module is `pub(crate)`: nothing here is part of the public API.
//! Downstream consumers interact with the harness through `net` crate types.
//!
//! [`Device`]: smoltcp::phy::Device

use std::collections::VecDeque;

use smoltcp::phy::{self, Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::time::Instant;
use tracing::trace;

/// Maximum Ethernet frame size (header + payload, excluding FCS).
const ETHERNET_MTU: usize = 1514;

// ---------------------------------------------------------------------------
// CaptureDevice
// ---------------------------------------------------------------------------

/// A virtual network device backed by in-memory queues.
///
/// Frames pushed into the RX queue via [`inject_rx`](Self::inject_rx) will be
/// delivered to the smoltcp stack on the next [`Interface::poll`] call.
/// Frames that the stack transmits are collected in the TX queue and can be
/// retrieved with [`drain_tx`](Self::drain_tx).
pub(crate) struct CaptureDevice {
    /// Frames waiting to be received by the smoltcp stack.
    rx_queue: VecDeque<Vec<u8>>,
    /// Frames transmitted by the smoltcp stack.
    tx_queue: VecDeque<Vec<u8>>,
}

impl CaptureDevice {
    /// Create a new `CaptureDevice` with empty queues.
    pub(crate) fn new() -> Self {
        Self {
            rx_queue: VecDeque::new(),
            tx_queue: VecDeque::new(),
        }
    }

    /// Enqueue a raw Ethernet frame for the smoltcp stack to receive on its
    /// next poll.
    pub(crate) fn inject_rx(&mut self, frame: Vec<u8>) {
        trace!(len = frame.len(), "injecting frame into RX queue");
        self.rx_queue.push_back(frame);
    }

    /// Drain all frames transmitted by the smoltcp stack since the last drain.
    pub(crate) fn drain_tx(&mut self) -> impl Iterator<Item = Vec<u8>> + '_ {
        self.tx_queue.drain(..)
    }

    /// Number of frames waiting in the TX queue.
    pub(crate) fn tx_pending(&self) -> usize {
        self.tx_queue.len()
    }

    /// Number of frames waiting in the RX queue.
    pub(crate) fn rx_pending(&self) -> usize {
        self.rx_queue.len()
    }
}

// ---------------------------------------------------------------------------
// smoltcp Device impl
// ---------------------------------------------------------------------------

impl Device for CaptureDevice {
    type RxToken<'a> = CaptureRxToken;
    type TxToken<'a> = CaptureTxToken<'a>;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let frame = self.rx_queue.pop_front()?;
        trace!(len = frame.len(), "device: handing frame to smoltcp");
        Some((
            CaptureRxToken { frame },
            CaptureTxToken {
                tx_queue: &mut self.tx_queue,
            },
        ))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(CaptureTxToken {
            tx_queue: &mut self.tx_queue,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ethernet;
        caps.max_transmission_unit = ETHERNET_MTU;
        caps.max_burst_size = Some(1);
        // Disable all checksum offloading.
        // The dataplane computes its own checksums, and smoltcp's expectations
        // would otherwise conflict with the values the pipeline produces.
        caps.checksum = phy::ChecksumCapabilities::ignored();
        caps
    }
}

// ---------------------------------------------------------------------------
// Tokens
// ---------------------------------------------------------------------------

/// Receive token that yields a single captured frame.
pub(crate) struct CaptureRxToken {
    frame: Vec<u8>,
}

impl RxToken for CaptureRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.frame)
    }
}

/// Transmit token that appends the written frame to the device's TX queue.
pub(crate) struct CaptureTxToken<'a> {
    tx_queue: &'a mut VecDeque<Vec<u8>>,
}

impl TxToken for CaptureTxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buf = vec![0u8; len];
        let result = f(&mut buf);
        trace!(len, "device: captured transmitted frame");
        self.tx_queue.push_back(buf);
        result
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_device_has_empty_queues() {
        let dev = CaptureDevice::new();
        assert_eq!(dev.tx_pending(), 0);
        assert_eq!(dev.rx_pending(), 0);
    }

    #[test]
    fn inject_rx_increases_pending_count() {
        let mut dev = CaptureDevice::new();
        dev.inject_rx(vec![0xAA; 64]);
        assert_eq!(dev.rx_pending(), 1);
        dev.inject_rx(vec![0xBB; 64]);
        assert_eq!(dev.rx_pending(), 2);
    }

    #[test]
    fn receive_yields_injected_frame() {
        let mut dev = CaptureDevice::new();
        let frame = vec![0xDE, 0xAD, 0xBE, 0xEF];
        dev.inject_rx(frame.clone());

        let (rx, _tx) = dev.receive(Instant::ZERO).unwrap_or_else(|| {
            panic!("expected a receive token after injecting a frame")
        });

        let received = rx.consume(<[u8]>::to_vec);
        assert_eq!(received, frame);
        assert_eq!(dev.rx_pending(), 0);
    }

    #[test]
    fn receive_returns_none_when_rx_empty() {
        let mut dev = CaptureDevice::new();
        assert!(dev.receive(Instant::ZERO).is_none());
    }

    #[test]
    fn transmit_token_captures_frame() {
        let mut dev = CaptureDevice::new();

        let tx = dev
            .transmit(Instant::ZERO)
            .unwrap_or_else(|| panic!("expected a transmit token"));

        let payload = [0x01, 0x02, 0x03, 0x04];
        tx.consume(payload.len(), |buf| {
            buf.copy_from_slice(&payload);
        });

        assert_eq!(dev.tx_pending(), 1);
        let frames: Vec<_> = dev.drain_tx().collect();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0], payload);
        assert_eq!(dev.tx_pending(), 0);
    }

    #[test]
    fn drain_tx_yields_all_frames_in_order() {
        let mut dev = CaptureDevice::new();

        for i in 0u8..5 {
            let tx = dev
                .transmit(Instant::ZERO)
                .unwrap_or_else(|| panic!("expected a transmit token"));
            tx.consume(1, |buf| {
                buf[0] = i;
            });
        }

        assert_eq!(dev.tx_pending(), 5);
        let frames: Vec<_> = dev.drain_tx().collect();
        for (i, frame) in frames.iter().enumerate() {
            assert_eq!(frame.len(), 1);
            #[allow(clippy::cast_possible_truncation)]
            let expected = i as u8;
            assert_eq!(frame[0], expected);
        }
        assert_eq!(dev.tx_pending(), 0);
    }

    #[test]
    fn capabilities_are_ethernet() {
        let dev = CaptureDevice::new();
        let caps = dev.capabilities();
        assert_eq!(caps.medium, Medium::Ethernet);
        assert_eq!(caps.max_transmission_unit, ETHERNET_MTU);
        assert_eq!(caps.max_burst_size, Some(1));
    }
}
