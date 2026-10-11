// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::{
    CaptureController, CaptureEnd, CaptureNames, CaptureRequest, CaptureStage, CaptureStartError,
    Direction, Directions,
};
use concurrency::sync::{Arc, Mutex};
use concurrency::thread;
use net::buffer::TestBuffer;
use net::packet::Packet;
use net::packet::test_utils::build_test_ipv4_packet;
use pcap_file::pcapng::{Block, PcapNgReader};
use pipeline::NetworkFunction;
use std::io::Write;
use std::num::{NonZeroU32, NonZeroU64, NonZeroUsize};
use std::time::Duration;

/// A capture file shared between the test and the writer thread.
#[derive(Clone, Default)]
struct SharedFile(Arc<Mutex<Vec<u8>>>);

impl Write for SharedFile {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl SharedFile {
    /// How many packets the file holds.
    fn packets(&self) -> u64 {
        let bytes = self.0.lock().clone();
        let mut reader = PcapNgReader::new(bytes.as_slice()).unwrap();
        let mut packets = 0;
        while let Some(block) = reader.next_block() {
            if let Block::EnhancedPacket(_) = block.unwrap().0 {
                packets += 1;
            }
        }
        packets
    }
}

fn request(
    directions: Directions,
    sample_one_in: u32,
    packets: u64,
    queue_depth: usize,
) -> CaptureRequest {
    CaptureRequest {
        directions,
        sample_one_in: NonZeroU32::new(sample_one_in).unwrap(),
        packets: NonZeroU64::new(packets).unwrap(),
        duration: Duration::from_hours(1),
        queue_depth: NonZeroUsize::new(queue_depth).unwrap(),
    }
}

fn burst(len: usize) -> Vec<Packet<TestBuffer>> {
    (0..len)
        .map(|_| build_test_ipv4_packet(64).unwrap())
        .collect()
}

/// Run one burst of `len` packets through a capture stage on its own thread.
fn worker(
    controller: &CaptureController,
    direction: Direction,
    len: usize,
) -> thread::JoinHandle<()> {
    let sink = controller.sink(direction);
    thread::spawn(move || {
        let mut stage = CaptureStage::new(direction, sink);
        stage.process_burst(&mut burst(len));
    })
}

#[concurrency::test]
fn stopping_while_workers_capture_loses_no_record() {
    let controller = CaptureController::new();
    let file = SharedFile::default();
    // A one-slot queue, so that records are dropped as well as written.
    controller
        .start(
            request(Directions::Both, 1, 4, 1),
            file.clone(),
            CaptureNames::default(),
        )
        .unwrap();
    let workers = [
        worker(&controller, Direction::Ingress, 3),
        worker(&controller, Direction::Egress, 3),
    ];
    let report = controller.stop().unwrap();
    for worker in workers {
        worker.join().unwrap();
    }

    assert!(report.admitted <= 4, "admitted beyond the budget: {report}");
    assert_eq!(report.written + report.dropped, report.admitted, "{report}");
    assert!(
        matches!(report.end, CaptureEnd::Stopped | CaptureEnd::Budget),
        "{report}"
    );
    assert_eq!(file.packets(), report.written);
}

#[concurrency::test]
fn a_capture_ends_on_its_budget_and_another_can_follow() {
    let controller = CaptureController::new();
    let file = SharedFile::default();
    controller
        .start(
            request(Directions::Both, 1, 2, 8),
            file.clone(),
            CaptureNames::default(),
        )
        .unwrap();
    worker(&controller, Direction::Ingress, 5).join().unwrap();

    let report = controller.stop().unwrap();
    assert!(matches!(report.end, CaptureEnd::Budget), "{report}");
    assert_eq!((report.admitted, report.written, report.dropped), (2, 2, 0));
    assert_eq!(file.packets(), 2);

    controller
        .start(
            request(Directions::Both, 1, 2, 8),
            SharedFile::default(),
            CaptureNames::default(),
        )
        .unwrap();
    assert!(matches!(
        controller.start(
            request(Directions::Both, 1, 2, 8),
            SharedFile::default(),
            CaptureNames::default()
        ),
        Err(CaptureStartError::AlreadyRunning)
    ));
    let report = controller.stop().unwrap();
    assert_eq!(report.admitted, 0, "{report}");
}

#[concurrency::test]
fn a_capture_ignores_directions_it_was_not_asked_for() {
    let controller = CaptureController::new();
    controller
        .start(
            request(Directions::Egress, 1, 10, 8),
            SharedFile::default(),
            CaptureNames::default(),
        )
        .unwrap();
    worker(&controller, Direction::Ingress, 3).join().unwrap();
    worker(&controller, Direction::Egress, 2).join().unwrap();
    assert_eq!(controller.stop().unwrap().admitted, 2);
}

#[cfg(not(feature = "shuttle"))]
mod real_time {
    use super::*;
    use crate::CaptureStatus;

    #[test]
    fn sampling_keeps_one_packet_in_n() {
        let controller = CaptureController::new();
        controller
            .start(
                request(Directions::Both, 3, 100, 64),
                SharedFile::default(),
                CaptureNames::default(),
            )
            .unwrap();
        let mut stage = CaptureStage::new(Direction::Ingress, controller.sink(Direction::Ingress));
        stage.process_burst(&mut burst(10));
        // Packets 0, 3, 6 and 9.
        assert_eq!(controller.stop().unwrap().admitted, 4);
    }

    #[test]
    fn a_capture_ends_at_its_deadline() {
        let controller = CaptureController::new();
        let mut request = request(Directions::Both, 1, 100, 8);
        request.duration = Duration::from_millis(20);
        controller
            .start(request, SharedFile::default(), CaptureNames::default())
            .unwrap();
        let give_up = clock::deadline(Duration::from_secs(10));
        loop {
            if let CaptureStatus::Finished(report) = controller.status() {
                assert!(matches!(report.end, CaptureEnd::Deadline), "{report}");
                break;
            }
            assert!(clock::now() < give_up, "the capture outlived its deadline");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn an_idle_controller_admits_nothing() {
        let controller = CaptureController::new();
        let mut stage = CaptureStage::new(Direction::Ingress, controller.sink(Direction::Ingress));
        stage.process_burst(&mut burst(3));
        assert!(matches!(controller.status(), CaptureStatus::Idle));
        assert!(controller.stop().is_none());
    }

    #[test]
    fn a_directory_capture_leaves_one_readable_file() {
        let dir = std::env::temp_dir().join(format!("capture-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let controller = CaptureController::new();
        let captures = crate::CaptureDirectory::new(controller.clone(), &dir);

        let path = captures
            .start(
                request(Directions::Both, 1, 10, 64),
                CaptureNames::default(),
            )
            .unwrap();
        assert!(matches!(
            captures.start(
                request(Directions::Both, 1, 10, 64),
                CaptureNames::default()
            ),
            Err(crate::CaptureFileError::Start(
                CaptureStartError::AlreadyRunning
            ))
        ));
        let mut stage = CaptureStage::new(Direction::Ingress, controller.sink(Direction::Ingress));
        stage.process_burst(&mut burst(3));
        let (report, stopped) = captures.stop().unwrap();
        assert_eq!(stopped, path);
        assert_eq!(report.written, 3, "{report}");

        let files: Vec<_> = std::fs::read_dir(&dir).unwrap().collect();
        assert_eq!(files.len(), 1, "a refused start left a file behind");
        let file = SharedFile(Arc::new(Mutex::new(std::fs::read(&path).unwrap())));
        assert_eq!(file.packets(), 3);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
