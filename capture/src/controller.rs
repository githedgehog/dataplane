// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Starting, feeding, and stopping a capture.
//!
//! One [`CaptureController`] is shared by the control plane and every worker.
//! Each worker's [`CaptureStage`]s hold a [`ControlledSink`], which admits packets into the running
//! capture (if any) and queues their records for a single writer thread.
//! Workers never block: a full queue drops the record and counts it.
//!
//! # Accounting
//!
//! A capture has a packet budget, and a packet is *admitted* once it takes a unit of that budget.
//! Every admitted packet is eventually either received by the writer or counted as dropped.
//! Ending a capture swaps the remaining budget to zero, which closes admission atomically:
//! after the swap the number admitted is final, and the writer drains the queue until
//! `received + dropped == admitted`.
//! That condition, not a timeout or the queue disconnecting, is what lets the writer finish without losing
//! a record some worker was still sending.
//!
//! [`CaptureStage`]: crate::CaptureStage

use crate::filter::CaptureFilter;
use crate::names::CaptureNames;
use crate::record::{CaptureRecord, Direction};
use crate::stage::CaptureSink;
use crate::writer::{CaptureWriteError, CaptureWriter};
use concurrency::slot::SlotOption;
use concurrency::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use concurrency::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TryRecvError};
use concurrency::sync::{Arc, Mutex};
use concurrency::thread::{self, JoinHandle};
use net::buffer::PacketBufferMut;
use net::packet::Packet;
use std::fmt::{Display, Formatter};
use std::io::Write;
use std::num::{NonZeroU32, NonZeroU64, NonZeroUsize};
use std::time::{Duration, Instant};

/// How often an idle writer wakes to check the deadline.
const WRITER_TICK: Duration = Duration::from_millis(100);

/// What to capture, and when to stop.
#[derive(Debug, Clone, Copy)]
pub struct CaptureRequest {
    /// Which packets to record.
    pub filter: CaptureFilter,
    /// Keep one matching packet in this many.
    ///
    /// Each capture stage samples on its own (one count per worker and direction), so workers share
    /// nothing to sample.
    pub sample_one_in: NonZeroU32,
    /// Stop once this many packets have been admitted.
    pub packets: NonZeroU64,
    /// Stop after this long, whatever has been admitted.
    pub duration: Duration,
    /// How many records may wait for the writer before further records are dropped.
    pub queue_depth: NonZeroUsize,
}

/// Why a capture ended.
#[derive(Debug)]
pub enum CaptureEnd {
    /// The packet budget was used up.
    Budget,
    /// The requested duration elapsed.
    Deadline,
    /// [`CaptureController::stop`] was called.
    Stopped,
    /// Writing the file failed; records received after the failure were discarded.
    WriteFailed(CaptureWriteError),
}

impl Display for CaptureEnd {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            CaptureEnd::Budget => f.write_str("packet budget used"),
            CaptureEnd::Deadline => f.write_str("duration elapsed"),
            CaptureEnd::Stopped => f.write_str("stopped"),
            CaptureEnd::WriteFailed(error) => write!(f, "write failed: {error}"),
        }
    }
}

/// The outcome of a finished capture.
#[derive(Debug)]
pub struct CaptureReport {
    /// Packets which took a unit of the budget.
    pub admitted: u64,
    /// Admitted packets whose records were written to the file.
    pub written: u64,
    /// Admitted packets whose records were dropped because the writer's queue was full.
    pub dropped: u64,
    /// Why the capture ended.
    pub end: CaptureEnd,
}

impl Display for CaptureReport {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "capture ended ({end}): admitted={admitted} written={written} dropped={dropped}",
            end = self.end,
            admitted = self.admitted,
            written = self.written,
            dropped = self.dropped,
        )
    }
}

/// What the controller is doing.
#[derive(Debug)]
pub enum CaptureStatus {
    /// No capture has run yet.
    Idle,
    /// A capture is running.
    Running {
        /// Packets admitted so far.
        admitted: u64,
        /// Records dropped so far.
        dropped: u64,
    },
    /// The last capture finished.
    Finished(Arc<CaptureReport>),
}

/// Errors from [`CaptureController::start`].
#[derive(Debug, thiserror::Error)]
pub enum CaptureStartError {
    /// Only one capture runs at a time.
    #[error("a capture is already running")]
    AlreadyRunning,
    /// The pcapng stream could not be started.
    #[error(transparent)]
    Write(#[from] CaptureWriteError),
    /// The writer thread could not be spawned.
    #[error("failed to spawn the capture writer thread: {0}")]
    Spawn(std::io::Error),
}

// A bounded channel stores messages inline in its preallocated slots; boxing the record to shrink `Wake`
// would add an allocation per captured packet instead.
#[allow(clippy::large_enum_variant)]
enum Message {
    Record(CaptureRecord),
    /// Sent by [`CaptureController::stop`] so that a writer waiting for records notices the stop.
    Wake,
}

/// The state of one capture, shared by the writer and every worker.
struct Session {
    id: u64,
    filter: CaptureFilter,
    sample_one_in: NonZeroU32,
    budget: u64,
    remaining: AtomicU64,
    dropped: AtomicU64,
    stop: AtomicBool,
    /// Set by the writer as its last act, once the controller no longer advertises this session.
    finished: AtomicBool,
    queue: SyncSender<Message>,
}

impl Session {
    /// Take one unit of budget, or fail if it is used up or the capture has ended.
    fn admit(&self) -> bool {
        let mut remaining = self.remaining.load(Ordering::Relaxed);
        while remaining > 0 {
            match self.remaining.compare_exchange_weak(
                remaining,
                remaining - 1,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(actual) => remaining = actual,
            }
        }
        false
    }

    /// Queue the record of an admitted packet, counting it as dropped if the queue is full.
    fn send(&self, record: CaptureRecord) {
        if self.queue.try_send(Message::Record(record)).is_err() {
            self.dropped.fetch_add(1, Ordering::AcqRel);
        }
    }

    fn admitted(&self) -> u64 {
        self.budget - self.remaining.load(Ordering::Acquire)
    }
}

struct Inner {
    /// Whether a session is advertised; lets an idle worker skip a burst with one relaxed load.
    active: AtomicBool,
    session: SlotOption<Session>,
    control: Mutex<Control>,
}

#[derive(Default)]
struct Control {
    next_id: u64,
    running: Option<Running>,
    last: Option<Arc<CaptureReport>>,
}

struct Running {
    session: Arc<Session>,
    writer: JoinHandle<CaptureReport>,
}

impl Control {
    /// Collect a writer which has finished on its own (budget, deadline, or write failure).
    fn reap(&mut self) {
        let finished = self
            .running
            .as_ref()
            .is_some_and(|running| running.session.finished.load(Ordering::Acquire));
        if finished {
            self.join();
        }
    }

    /// Wait for the running writer, if any, and keep its report.
    fn join(&mut self) {
        if let Some(running) = self.running.take() {
            let report = running
                .writer
                .join()
                .unwrap_or_else(|panic| std::panic::resume_unwind(panic));
            self.last = Some(Arc::new(report));
        }
    }
}

/// Starts and stops captures, and hands out the sinks workers feed them through.
#[derive(Clone)]
pub struct CaptureController {
    inner: Arc<Inner>,
}

impl Default for CaptureController {
    fn default() -> Self {
        Self::new()
    }
}

impl CaptureController {
    /// A controller with no capture running.
    #[must_use]
    pub fn new() -> Self {
        CaptureController {
            inner: Arc::new(Inner {
                active: AtomicBool::new(false),
                session: SlotOption::empty(),
                control: Mutex::new(Control::default()),
            }),
        }
    }

    /// A sink for a [`CaptureStage`] recording packets going in `direction`.
    ///
    /// [`CaptureStage`]: crate::CaptureStage
    #[must_use]
    pub fn sink(&self, direction: Direction) -> ControlledSink {
        ControlledSink {
            inner: self.inner.clone(),
            direction,
            session: None,
            skip: 0,
        }
    }

    /// Start a capture writing to `out`, showing interfaces and VPCs by `names`.
    ///
    /// # Errors
    ///
    /// Fails if a capture is already running, or if the stream or its writer thread cannot be started.
    pub fn start<W: Write + Send + 'static>(
        &self,
        request: CaptureRequest,
        out: W,
        names: CaptureNames,
    ) -> Result<(), CaptureStartError> {
        let mut control = self.inner.control.lock();
        control.reap();
        if control.running.is_some() {
            return Err(CaptureStartError::AlreadyRunning);
        }
        let writer = CaptureWriter::new(out, names)?;
        let (queue, records) = mpsc::sync_channel(request.queue_depth.get());
        let session = Arc::new(Session {
            id: control.next_id,
            filter: request.filter,
            sample_one_in: request.sample_one_in,
            budget: request.packets.get(),
            remaining: AtomicU64::new(request.packets.get()),
            dropped: AtomicU64::new(0),
            stop: AtomicBool::new(false),
            finished: AtomicBool::new(false),
            queue,
        });
        control.next_id += 1;

        let deadline = clock::saturating_add(clock::now(), request.duration);
        let inner = self.inner.clone();
        let writing = session.clone();
        let handle = thread::Builder::new()
            .name("capture-writer".to_owned())
            .spawn(move || write_capture(&inner, &writing, &records, writer, deadline))
            .map_err(CaptureStartError::Spawn)?;

        self.inner.session.store(Some(session.clone()));
        self.inner.active.store(true, Ordering::Release);
        control.running = Some(Running {
            session,
            writer: handle,
        });
        Ok(())
    }

    /// Stop the running capture and wait until its file is complete.
    ///
    /// Returns the report of the capture which was running, or `None` if none was.
    #[must_use]
    pub fn stop(&self) -> Option<Arc<CaptureReport>> {
        let mut control = self.inner.control.lock();
        let running = control.running.as_ref()?;
        running.session.stop.store(true, Ordering::Release);
        // The writer may be waiting for a record; this wakes it. If it has already exited the send fails,
        // which is fine: it has nothing left to notice.
        let _ = running.session.queue.send(Message::Wake);
        control.join();
        control.last.clone()
    }

    /// What the controller is doing.
    #[must_use]
    pub fn status(&self) -> CaptureStatus {
        let mut control = self.inner.control.lock();
        control.reap();
        if let Some(running) = &control.running {
            return CaptureStatus::Running {
                admitted: running.session.admitted(),
                dropped: running.session.dropped.load(Ordering::Acquire),
            };
        }
        match &control.last {
            Some(report) => CaptureStatus::Finished(report.clone()),
            None => CaptureStatus::Idle,
        }
    }
}

/// The writer thread's tally of what it has taken off the queue.
struct Tally<W: Write> {
    writer: CaptureWriter<W>,
    received: u64,
    written: u64,
    failure: Option<CaptureWriteError>,
}

impl<W: Write> Tally<W> {
    /// Write a received record, or discard it if an earlier write already failed.
    fn take(&mut self, record: &CaptureRecord) {
        self.received += 1;
        if self.failure.is_some() {
            return;
        }
        match self.writer.write(record) {
            Ok(()) => self.written += 1,
            Err(error) => self.failure = Some(error),
        }
    }
}

/// The body of the writer thread.
///
/// It wakes at least every [`WRITER_TICK`] to check the deadline.
/// (Under shuttle, `recv_timeout` never times out, so a model-checked capture must end by budget or
/// [`CaptureController::stop`].)
fn write_capture<W: Write>(
    inner: &Inner,
    session: &Session,
    records: &Receiver<Message>,
    writer: CaptureWriter<W>,
    deadline: Instant,
) -> CaptureReport {
    let mut tally = Tally {
        writer,
        received: 0,
        written: 0,
        failure: None,
    };

    let end = loop {
        if tally.failure.is_some() {
            break CaptureEnd::Stopped; // replaced by the failure below
        }
        // Budget before stop: a capture which used its whole budget says so even if a stop raced it.
        if session.remaining.load(Ordering::Acquire) == 0 {
            break CaptureEnd::Budget;
        }
        if session.stop.load(Ordering::Acquire) {
            break CaptureEnd::Stopped;
        }
        let now = clock::now();
        if now >= deadline {
            break CaptureEnd::Deadline;
        }
        match records.recv_timeout(WRITER_TICK.min(deadline - now)) {
            Ok(Message::Record(record)) => tally.take(&record),
            Ok(Message::Wake) | Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => {
                unreachable!("the session holds the sender for as long as the writer runs")
            }
        }
    };

    // Close admission; from here the number admitted is final.
    let admitted = session.budget - session.remaining.swap(0, Ordering::AcqRel);
    while tally.received + session.dropped.load(Ordering::Acquire) < admitted {
        match records.try_recv() {
            Ok(Message::Record(record)) => tally.take(&record),
            Ok(Message::Wake) => {}
            Err(TryRecvError::Empty) => thread::yield_now(),
            Err(TryRecvError::Disconnected) => {
                unreachable!("the session holds the sender for as long as the writer runs")
            }
        }
    }

    let Tally {
        writer,
        written,
        failure,
        ..
    } = tally;
    let mut report = CaptureReport {
        admitted,
        written,
        dropped: session.dropped.load(Ordering::Acquire),
        end,
    };
    if let Some(error) = failure {
        report.end = CaptureEnd::WriteFailed(error);
    } else {
        let ended = clock::system_now()
            .duration_since(clock::SystemTime::UNIX_EPOCH)
            .unwrap_or_default();
        if let Err(error) = writer.finish(&report, ended) {
            report.end = CaptureEnd::WriteFailed(error);
        }
    }

    // Withdraw the session before declaring it finished, so that a capture started next is never
    // clobbered by this one's cleanup.
    inner.active.store(false, Ordering::Release);
    inner.session.store(None);
    session.finished.store(true, Ordering::Release);
    report
}

/// A [`CaptureSink`] feeding whichever capture a [`CaptureController`] is running.
pub struct ControlledSink {
    inner: Arc<Inner>,
    direction: Direction,
    session: Option<Arc<Session>>,
    /// Packets to pass over before the next one is sampled.
    skip: u32,
}

impl CaptureSink for ControlledSink {
    fn begin_burst(&mut self) -> bool {
        if !self.inner.active.load(Ordering::Relaxed) {
            self.session = None;
            return false;
        }
        let Some(session) = self.inner.session.load_full() else {
            self.session = None;
            return false;
        };
        if !session.filter.includes(self.direction) {
            self.session = None;
            return false;
        }
        if self.session.as_ref().map(|current| current.id) != Some(session.id) {
            self.skip = 0;
        }
        self.session = Some(session);
        true
    }

    fn admits<Buf: PacketBufferMut>(&mut self, packet: &Packet<Buf>) -> bool {
        let Some(session) = &self.session else {
            return false;
        };
        // Filter before sampling, so that sampling picks among the packets asked for.
        if !session.filter.matches(packet) {
            return false;
        }
        if self.skip > 0 {
            self.skip -= 1;
            return false;
        }
        if !session.admit() {
            return false;
        }
        self.skip = session.sample_one_in.get() - 1;
        true
    }

    fn submit(&mut self, record: CaptureRecord) {
        match &self.session {
            Some(session) => session.send(record),
            None => unreachable!("records are only submitted for packets admitted into a session"),
        }
    }
}
