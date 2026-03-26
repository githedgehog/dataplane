// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Pcap capture for recording harness frame exchanges.
//!
//! [`PcapCapture`] collects raw Ethernet frames as they transit the
//! harness's forward and reverse pipes.  Each frame is tagged with the
//! simulated timestamp, transit direction, and processing stage
//! (pre-pipe, post-pipe, or passthrough).  The captured frames can
//! then be written to a standard [pcap file] for analysis in
//! Wireshark, tcpdump, or any other pcap-compatible tool.
//!
//! Capture happens at the **harness level** (not the smoltcp device
//! level).  This means the output shows frames exactly as they appear
//! at the pipe boundary — before and after NAT translation, for
//! example — which is the most useful vantage point for debugging
//! dataplane processing logic.
//!
//! # Usage
//!
//! ```ignore
//! use dataplane_flow_test::pcap::{Direction, PcapCapture, Stage};
//!
//! let mut capture = PcapCapture::new();
//!
//! // Record frames as they pass through the harness.
//! capture.record(elapsed, Direction::Forward, Stage::PrePipe, &frame);
//! capture.record(elapsed, Direction::Forward, Stage::PostPipe, &translated);
//!
//! // Write to disk for offline analysis.
//! capture.write_pcap("debug.pcap").expect("write pcap");
//! ```
//!
//! [pcap file]: https://wiki.wireshark.org/Development/LibpcapFileFormat

use std::borrow::Cow;
use std::fmt;
use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::Path;
use std::time::Duration;

use pcap_file::pcap::{PcapPacket, PcapWriter};

// ---------------------------------------------------------------------------
// Direction
// ---------------------------------------------------------------------------

/// Which direction a frame was travelling when captured.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Direction {
    /// Client → server (the "forward" path).
    Forward,
    /// Server → client (the "reverse" path).
    Reverse,
}

impl fmt::Display for Direction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Forward => write!(f, "forward"),
            Self::Reverse => write!(f, "reverse"),
        }
    }
}

// ---------------------------------------------------------------------------
// Stage
// ---------------------------------------------------------------------------

/// At which processing stage the frame was captured.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Stage {
    /// Before the pipe closure processed the frame.
    ///
    /// For IP packets, this is the raw frame as emitted by the sending
    /// endpoint's smoltcp stack — prior to NAT, filtering, or any other
    /// transformation the pipe applies.
    PrePipe,

    /// After the pipe closure processed the frame.
    ///
    /// This is the frame as it will be injected into the receiving
    /// endpoint.  Comparing `PrePipe` and `PostPipe` captures for the
    /// same frame reveals exactly what the pipe changed (e.g. source
    /// port rewrite by NAT).
    PostPipe,

    /// The frame bypassed the pipe entirely.
    ///
    /// Non-IP frames (e.g. ARP) are forwarded as raw bytes without
    /// going through the pipe closure.  They appear once with this
    /// stage rather than as a `PrePipe` / `PostPipe` pair.
    Passthrough,
}

impl fmt::Display for Stage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PrePipe => write!(f, "pre-pipe"),
            Self::PostPipe => write!(f, "post-pipe"),
            Self::Passthrough => write!(f, "passthrough"),
        }
    }
}

// ---------------------------------------------------------------------------
// CapturedFrame
// ---------------------------------------------------------------------------

/// A single Ethernet frame captured by [`PcapCapture`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturedFrame {
    /// Simulated timestamp at the moment of capture (elapsed time
    /// since the harness clock started at zero).
    pub timestamp: Duration,
    /// Direction the frame was travelling.
    pub direction: Direction,
    /// Processing stage at which the frame was recorded.
    pub stage: Stage,
    /// Raw Ethernet frame bytes.
    pub data: Vec<u8>,
}

impl fmt::Display for CapturedFrame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{:>8.3}ms] {:<7} {:<11} {} bytes",
            self.timestamp.as_secs_f64() * 1_000.0,
            self.direction,
            self.stage,
            self.data.len(),
        )
    }
}

// ---------------------------------------------------------------------------
// PcapCapture
// ---------------------------------------------------------------------------

/// In-memory buffer of captured Ethernet frames.
///
/// Frames are accumulated via [`record`](Self::record) and can later be
/// written out as a pcap file with
/// [`write_pcap`](Self::write_pcap) or
/// [`write_to_writer`](Self::write_to_writer).
///
/// The pcap output is a single stream of Ethernet frames ordered by
/// insertion time.  Pre-pipe and post-pipe captures for the same
/// original frame appear as consecutive entries at the same timestamp,
/// which makes it straightforward to correlate them in Wireshark's
/// packet list.
#[derive(Debug, Clone)]
pub struct PcapCapture {
    frames: Vec<CapturedFrame>,
}

impl PcapCapture {
    /// Create an empty capture buffer.
    #[must_use]
    pub fn new() -> Self {
        Self { frames: Vec::new() }
    }

    /// Record a single frame.
    ///
    /// Frames are stored in insertion order.  The `timestamp` should
    /// come from [`FlowHarness::elapsed`] at the time of capture so
    /// that the resulting pcap file has meaningful relative timestamps.
    ///
    /// [`FlowHarness::elapsed`]: crate::harness::FlowHarness::elapsed
    pub fn record(
        &mut self,
        timestamp: Duration,
        direction: Direction,
        stage: Stage,
        data: &[u8],
    ) {
        self.frames.push(CapturedFrame {
            timestamp,
            direction,
            stage,
            data: data.to_vec(),
        });
    }

    /// Number of captured frames.
    #[must_use]
    pub fn len(&self) -> usize {
        self.frames.len()
    }

    /// Returns `true` if no frames have been captured.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.frames.is_empty()
    }

    /// Discard all captured frames, resetting the buffer.
    pub fn clear(&mut self) {
        self.frames.clear();
    }

    /// Borrowed slice of all captured frames in insertion order.
    #[must_use]
    pub fn frames(&self) -> &[CapturedFrame] {
        &self.frames
    }

    /// Write all captured frames to a pcap file at `path`.
    ///
    /// The file is created (or truncated if it already exists) and a
    /// standard pcap global header with `DataLink::ETHERNET` is written
    /// first, followed by every captured frame in insertion order.
    ///
    /// Returns the number of packets written.
    ///
    /// # Errors
    ///
    /// Returns [`io::Error`] if the file cannot be created or written.
    pub fn write_pcap(&self, path: impl AsRef<Path>) -> io::Result<usize> {
        let file = File::create(path)?;
        let writer = BufWriter::new(file);
        self.write_to_writer(writer)
    }

    /// Write all captured frames to an arbitrary [`Write`] sink.
    ///
    /// This is the general-purpose form of [`write_pcap`](Self::write_pcap)
    /// — useful for writing to an in-memory buffer in tests.
    ///
    /// Returns the number of packets written.
    ///
    /// # Errors
    ///
    /// Returns [`io::Error`] if the writer encounters an I/O failure or
    /// if the pcap header/packet serialisation fails.
    pub fn write_to_writer<W: Write>(&self, writer: W) -> io::Result<usize> {
        let mut pcap_writer = PcapWriter::new(writer).map_err(map_pcap_err)?;

        for frame in &self.frames {
            #[allow(clippy::cast_possible_truncation)] // frame sizes ≤ 65 535
            let orig_len = frame.data.len() as u32;

            let packet = PcapPacket {
                timestamp: frame.timestamp,
                orig_len,
                data: Cow::Borrowed(&frame.data),
            };

            pcap_writer.write_packet(&packet).map_err(map_pcap_err)?;
        }

        Ok(self.frames.len())
    }
}

impl Default for PcapCapture {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for PcapCapture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "PcapCapture ({} frames)", self.frames.len())?;
        for (i, frame) in self.frames.iter().enumerate() {
            writeln!(f, "  [{i:>4}] {frame}")?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Error mapping
// ---------------------------------------------------------------------------

/// Map a [`pcap_file::PcapError`] into a standard [`io::Error`].
fn map_pcap_err(e: pcap_file::PcapError) -> io::Error {
    match e {
        pcap_file::PcapError::IoError(io_err) => io_err,
        other => io::Error::new(io::ErrorKind::Other, other.to_string()),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::Cursor;

    use pcap_file::pcap::PcapReader;

    // -- construction -------------------------------------------------------

    #[test]
    fn new_capture_is_empty() {
        let capture = PcapCapture::new();
        assert!(capture.is_empty());
        assert_eq!(capture.len(), 0);
        assert!(capture.frames().is_empty());
    }

    #[test]
    fn default_is_empty() {
        let capture = PcapCapture::default();
        assert!(capture.is_empty());
    }

    // -- record -------------------------------------------------------------

    #[test]
    fn record_accumulates_frames() {
        let mut capture = PcapCapture::new();
        let frame = vec![0xAAu8; 64];

        capture.record(Duration::from_millis(1), Direction::Forward, Stage::PrePipe, &frame);
        capture.record(Duration::from_millis(1), Direction::Forward, Stage::PostPipe, &frame);
        capture.record(Duration::from_millis(2), Direction::Reverse, Stage::PrePipe, &frame);

        assert_eq!(capture.len(), 3);
        assert!(!capture.is_empty());
    }

    #[test]
    fn record_preserves_insertion_order() {
        let mut capture = PcapCapture::new();

        capture.record(
            Duration::from_millis(10),
            Direction::Forward,
            Stage::PrePipe,
            &[1],
        );
        capture.record(
            Duration::from_millis(20),
            Direction::Reverse,
            Stage::PostPipe,
            &[2],
        );
        capture.record(
            Duration::from_millis(30),
            Direction::Forward,
            Stage::Passthrough,
            &[3],
        );

        let frames = capture.frames();
        assert_eq!(frames[0].data, vec![1]);
        assert_eq!(frames[1].data, vec![2]);
        assert_eq!(frames[2].data, vec![3]);
    }

    #[test]
    fn record_stores_correct_metadata() {
        let mut capture = PcapCapture::new();
        let ts = Duration::from_micros(42_000);
        let data = vec![0xDE, 0xAD, 0xBE, 0xEF];

        capture.record(ts, Direction::Reverse, Stage::PostPipe, &data);

        let frame = &capture.frames()[0];
        assert_eq!(frame.timestamp, ts);
        assert_eq!(frame.direction, Direction::Reverse);
        assert_eq!(frame.stage, Stage::PostPipe);
        assert_eq!(frame.data, data);
    }

    // -- clear --------------------------------------------------------------

    #[test]
    fn clear_removes_all_frames() {
        let mut capture = PcapCapture::new();
        capture.record(Duration::ZERO, Direction::Forward, Stage::PrePipe, &[0; 14]);
        capture.record(Duration::ZERO, Direction::Reverse, Stage::PrePipe, &[0; 14]);
        assert_eq!(capture.len(), 2);

        capture.clear();
        assert!(capture.is_empty());
        assert_eq!(capture.len(), 0);
    }

    // -- Display ------------------------------------------------------------

    #[test]
    fn direction_display() {
        assert_eq!(Direction::Forward.to_string(), "forward");
        assert_eq!(Direction::Reverse.to_string(), "reverse");
    }

    #[test]
    fn stage_display() {
        assert_eq!(Stage::PrePipe.to_string(), "pre-pipe");
        assert_eq!(Stage::PostPipe.to_string(), "post-pipe");
        assert_eq!(Stage::Passthrough.to_string(), "passthrough");
    }

    #[test]
    fn captured_frame_display_includes_key_fields() {
        let frame = CapturedFrame {
            timestamp: Duration::from_millis(42),
            direction: Direction::Forward,
            stage: Stage::PrePipe,
            data: vec![0u8; 100],
        };
        let display = frame.to_string();
        assert!(display.contains("forward"), "should mention direction");
        assert!(display.contains("pre-pipe"), "should mention stage");
        assert!(display.contains("100"), "should mention byte count");
    }

    #[test]
    fn pcap_capture_display_includes_frame_count() {
        let mut capture = PcapCapture::new();
        capture.record(Duration::ZERO, Direction::Forward, Stage::PrePipe, &[0; 14]);
        let display = capture.to_string();
        assert!(display.contains("1 frames"), "should show frame count");
    }

    // -- pcap writing -------------------------------------------------------

    /// Build a minimal valid Ethernet frame (14-byte header + 46-byte
    /// minimum payload padding).
    fn minimal_ethernet_frame() -> Vec<u8> {
        let mut frame = vec![0u8; 60]; // 14 header + 46 min payload
        // Destination MAC
        frame[0..6].copy_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
        // Source MAC
        frame[6..12].copy_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
        // EtherType: IPv4 (0x0800)
        frame[12] = 0x08;
        frame[13] = 0x00;
        frame
    }

    #[test]
    fn write_to_writer_empty_capture_produces_valid_pcap() {
        let capture = PcapCapture::new();
        let mut buf = Vec::new();
        let count = capture
            .write_to_writer(&mut buf)
            .expect("writing empty capture should succeed");

        assert_eq!(count, 0, "no packets written");

        // The buffer should still contain a valid pcap header.
        let mut reader = PcapReader::new(Cursor::new(&buf))
            .expect("empty pcap should have a valid header");

        // No packets to read.
        assert!(
            reader.next_packet().is_none(),
            "empty capture should produce no packets",
        );
    }

    #[test]
    fn write_to_writer_round_trips_single_frame() {
        let mut capture = PcapCapture::new();
        let frame = minimal_ethernet_frame();
        let ts = Duration::from_millis(42);

        capture.record(ts, Direction::Forward, Stage::PrePipe, &frame);

        let mut buf = Vec::new();
        let count = capture
            .write_to_writer(&mut buf)
            .expect("write should succeed");
        assert_eq!(count, 1);

        // Read it back.
        let mut reader = PcapReader::new(Cursor::new(&buf)).expect("valid pcap");
        let packet = reader
            .next_packet()
            .expect("should have one packet")
            .expect("packet should parse");

        assert_eq!(packet.data.as_ref(), frame.as_slice());
        assert_eq!(packet.orig_len, frame.len() as u32);

        // No more packets.
        assert!(reader.next_packet().is_none(), "only one packet expected");
    }

    #[test]
    fn write_to_writer_round_trips_multiple_frames() {
        let mut capture = PcapCapture::new();
        let frame_a = minimal_ethernet_frame();
        let mut frame_b = minimal_ethernet_frame();
        frame_b[14] = 0x45; // tweak a byte so payloads differ

        capture.record(
            Duration::from_millis(1),
            Direction::Forward,
            Stage::PrePipe,
            &frame_a,
        );
        capture.record(
            Duration::from_millis(1),
            Direction::Forward,
            Stage::PostPipe,
            &frame_b,
        );
        capture.record(
            Duration::from_millis(2),
            Direction::Reverse,
            Stage::Passthrough,
            &frame_a,
        );

        let mut buf = Vec::new();
        let count = capture
            .write_to_writer(&mut buf)
            .expect("write should succeed");
        assert_eq!(count, 3);

        let mut reader = PcapReader::new(Cursor::new(&buf)).expect("valid pcap");
        let mut packets = Vec::new();
        while let Some(pkt) = reader.next_packet() {
            packets.push(pkt.expect("packet should parse").into_owned());
        }

        assert_eq!(packets.len(), 3, "should round-trip all three frames");
        assert_eq!(packets[0].data.as_ref(), frame_a.as_slice());
        assert_eq!(packets[1].data.as_ref(), frame_b.as_slice());
        assert_eq!(packets[2].data.as_ref(), frame_a.as_slice());
    }

    #[test]
    fn write_to_writer_preserves_timestamps() {
        let mut capture = PcapCapture::new();
        let frame = minimal_ethernet_frame();

        let ts1 = Duration::from_millis(100);
        let ts2 = Duration::from_secs(1) + Duration::from_micros(500);

        capture.record(ts1, Direction::Forward, Stage::PrePipe, &frame);
        capture.record(ts2, Direction::Reverse, Stage::PrePipe, &frame);

        let mut buf = Vec::new();
        capture
            .write_to_writer(&mut buf)
            .expect("write should succeed");

        let mut reader = PcapReader::new(Cursor::new(&buf)).expect("valid pcap");
        let mut packets = Vec::new();
        while let Some(pkt) = reader.next_packet() {
            packets.push(pkt.expect("packet should parse").into_owned());
        }

        assert_eq!(packets.len(), 2);
        assert_eq!(packets[0].timestamp, ts1);
        assert_eq!(packets[1].timestamp, ts2);
    }
}
