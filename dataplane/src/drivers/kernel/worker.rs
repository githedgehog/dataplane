// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

// We want to avoid Packet moves, so allow Vec<Box<_>> to be sure
#![allow(clippy::vec_box)]

use std::collections::HashMap;
use std::io;
use std::os::fd::AsRawFd;

use afpacket::tokio::RawPacketStream;
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncWriteExt, Interest};
use tokio::sync::Mutex;
use tokio::time::{Duration, interval};

use concurrency::sync::Arc;
use concurrency::thread;
#[allow(unused_imports)] // used under loom/shuttle backends
use concurrency::thread::BuilderExt;
use lifecycle::{CancellationToken, Subsystem};
use net::buffer::test_buffer::TestBuffer;
use net::interface::InterfaceIndex;
use net::packet::{DoneReason, Packet};
use pipeline::{DynPipeline, NetworkFunction};

use crate::drivers::kernel::DriverKernel;
use crate::drivers::kernel::fanout::{PacketFanoutType, set_packet_fanout};
use crate::drivers::kernel::kif::Kif;
use crate::drivers::kernel::sockstats;
use crate::drivers::kernel::{WorkerIfaceMonitor, WorkerMonitor};
use crate::drivers::status::WorkerId;
use crate::drivers::watchdog::{RxCounters, Watchdog};

use tracing::{debug, error, info, trace, warn};

struct WorkerInterfaceWriter {
    if_name: String,
    #[allow(unused)]
    if_index: InterfaceIndex,
    sock: RawPacketStream,
}

struct WorkerInterfaceReader {
    if_name: String,
    if_index: InterfaceIndex,
    read_fd: AsyncFd<std::os::unix::io::OwnedFd>,
    watchdog: Watchdog,
}

type WorkerInterfaceReaders = Vec<WorkerInterfaceReader>;
type WorkerIfTable = HashMap<InterfaceIndex, Arc<Mutex<WorkerInterfaceWriter>>>;

#[allow(unsafe_code)]
/// This function must be called from a tokio context
fn create_worker_interface(
    id: WorkerId,
    total_workers: usize,
    if_name: &str,
    if_index: InterfaceIndex,
    watchdog: Watchdog,
) -> io::Result<(WorkerInterfaceWriter, WorkerInterfaceReader)> {
    let mut sock = RawPacketStream::new()?;
    sock.bind(if_name)
        .inspect_err(|e| error!("Failed to open raw sock for interface {if_name}: {e}"))?;

    let fd = sock.as_raw_fd();
    let buf_size = 4 * 1024 * 1024;

    let bfd = unsafe { std::os::unix::io::BorrowedFd::borrow_raw(fd) };
    nix::sys::socket::setsockopt(&bfd, nix::sys::socket::sockopt::RcvBuf, &buf_size).inspect_err(
        |e| {
            error!("Failed to set SO_RCVBUF for interface {if_name}: {e}");
        },
    )?;
    nix::sys::socket::setsockopt(&bfd, nix::sys::socket::sockopt::SndBuf, &buf_size).inspect_err(
        |e| {
            error!("Failed to set SO_SNDBUF for interface {if_name}: {e}");
        },
    )?;

    let read_fd_owned = nix::unistd::dup(bfd).map_err(io::Error::from)?;
    let read_fd = AsyncFd::with_interest(read_fd_owned, Interest::READABLE)?;
    let fanout_type = set_packet_fanout(if_index, &read_fd);
    if total_workers > 1 {
        match fanout_type {
            Ok(fanout_type) => match fanout_type {
                PacketFanoutType::Cpu => {
                    warn!(
                        worker = id,
                        "Using {fanout_type} for interface {if_name}, which may result in poor performance"
                    );
                }
                _ => {
                    info!(worker = id, "Using {fanout_type} for interface {if_name}");
                }
            },
            Err(e) => {
                error!(
                    worker = id,
                    "Failed to set packet fanout with more than 1 worker ({total_workers} workers) for interface {if_name}: {e}"
                );
                return Err(e.into());
            }
        }
    } else {
        match fanout_type {
            Ok(fanout_type) => {
                info!(worker = id, "Using {fanout_type} for interface {if_name}");
            }
            Err(e) => {
                warn!(
                    worker = id,
                    "Unable to set packet fanout for interface {if_name}: {e}"
                );
            }
        }
    }

    Ok((
        WorkerInterfaceWriter {
            if_name: String::from(if_name),
            if_index,
            sock,
        },
        WorkerInterfaceReader {
            if_name: String::from(if_name),
            if_index,
            read_fd,
            watchdog,
        },
    ))
}

pub struct Worker {
    id: WorkerId,
    total_workers: usize,
    setup_pipeline: Arc<dyn Send + Sync + Fn() -> DynPipeline<TestBuffer>>,
    subsystem: Subsystem,
}

impl Worker {
    pub fn new(
        id: WorkerId,
        total_workers: usize,
        setup_pipeline: &Arc<dyn Send + Sync + Fn() -> DynPipeline<TestBuffer>>,
        subsystem: Subsystem,
    ) -> Self {
        Worker {
            id,
            total_workers,
            setup_pipeline: setup_pipeline.clone(),
            subsystem,
        }
    }

    /// Spawn a task for a given worker `WorkerId` in the given `JoinSet` to read packets
    /// from a single interface (`WorkerInterfaceReader`) and process them with a pipeline
    /// built from `setup`. The task can be cancelled with the provided `CancellationToken`.
    /// The interface table is used to send packets successfully processed over the right
    /// interface (`WorkerInterfaceWriter`).
    fn spawn_worker_interface_reader(
        id: WorkerId,
        intf: WorkerInterfaceReader,
        reader_handles: &mut tokio::task::JoinSet<()>,
        setup: Arc<dyn Fn() -> DynPipeline<TestBuffer> + Send + Sync>,
        if_table: Arc<HashMap<InterfaceIndex, Arc<Mutex<WorkerInterfaceWriter>>>>,
        cancel: CancellationToken,
    ) {
        // the interval at which we'll pat the watchdog if there is no activity on the socket
        let pat_period = Duration::from_secs(u64::from(DriverKernel::TASK_PAT_PERIOD));

        reader_handles.spawn_local(async move {
            let intf = intf;
            let mut pipeline = setup();
            let mut ticker = interval(pat_period);
            loop {
                debug!(worker = id, "awaiting packets");

                let mut counters = RxCounters::default();

                let packets_vec = tokio::select! {
                    () = cancel.cancelled() => {
                        info!(
                            worker = id,
                            rx_intf_name = intf.if_name,
                            "cancellation observed; exiting reader"
                        );
                        break;
                    },
                    result = read_packets_from_interface(id, &intf, &mut counters) => match result {
                        Ok(packets) => packets,
                        Err(e) => {
                            error!(
                                worker = id,
                                rx_intf_name = intf.if_name,
                                "Error reading packets from interface: {e}"
                            );
                            Vec::new()
                        }
                    },
                    // N.B. read_packets_from_interface() MUST be cancel-safe for this wake-up not to
                    // cause packet loss, nor loss of the counters it fills. It currently is: it only
                    // awaits before reading anything from the socket.
                    // The pipeline gets an empty batch rather than being skipped. Nothing in it
                    // moves a packet, but a stage whose work is timed -- the stats stage closes a
                    // batch on a schedule -- can only notice the schedule when `process` is
                    // called. An interface that went quiet used to hold its last batch, and so
                    // its last packets, until traffic resumed: for ever, if it did not.
                    _ = ticker.tick() => {
                        intf.watchdog.pat();
                        Vec::new()
                    }
                };

                debug!(
                    worker = id,
                    rx_intf_name = intf.if_name,
                    "Read {} packets from interface {}",
                    packets_vec.len(),
                    intf.if_name
                );

                let mut to_tx: u64 = 0; // number of packets to send
                let mut tx_pkts: u64 = 0; // number of packets successfully sent
                let mut tx_drops: u64 = 0; // number of packets dropped on tx
                let rx_pkts = packets_vec.len() as u64; // number of packets received
                counters.rx = rx_pkts;

                let packets = packets_vec.into_iter();
                let out_pkts = pipeline
                    .process(packets.map(|pkt| *pkt))
                    .collect::<Vec<_>>();

                // number of packets output by pipeline: includes delivered and local (which should not be
                // accounted as pipeline drops)
                let num_out_pkts: u64 = out_pkts.len() as u64;

                // send each of the packets output by the pipeline, except those to be locally delivered
                for out_pkt in out_pkts {
                    let done = out_pkt.get_done();
                    debug_assert!(done.is_some());
                    if done == Some(DoneReason::Delivered) {
                        to_tx += 1;
                        if tx_packet(id, &intf.if_name, &if_table, out_pkt).await {
                            tx_pkts += 1;
                        } else {
                            tx_drops += 1;
                        }
                    }
                }

                tracing::debug!(
                    worker = id,
                    rx_intf_name = intf.if_name,
                    "Sent {tx_pkts} packets out of {to_tx}, dropped {tx_drops}",
                );

                // update rx task stats
                counters.ppline_drops = rx_pkts.saturating_sub(num_out_pkts);
                counters.tx = tx_pkts;
                counters.tx_drops = tx_drops;
                intf.watchdog.record(&counters);
            }
        });
    }

    pub fn start<'scope>(
        self,
        scope: &'scope thread::Scope<'scope, '_>,
        interfaces: &[Kif],
    ) -> Result<WorkerMonitor<'scope>, io::Error> {
        let id = self.id;
        let total_workers = self.total_workers;
        let setup = self.setup_pipeline;
        let subsystem = self.subsystem;
        let cancel = subsystem.cancel_token();
        let interfaces = interfaces.to_vec();

        // Create vector of `WorkerIfaceMonitor` with the watchdogs. We'll hand a watchdog to each
        // interface reader and pass this vector along with the `WorkerMonitor` returned for this `Worker`
        // for the supervisor to check. Ideally we'd create the watchdogs in the interface readers and
        // collect them. However build_interface_table() needs to be called from the worker's tokio runtime
        let ifmonitors: Vec<_> = interfaces
            .iter()
            .map(|kif| WorkerIfaceMonitor::new(&kif.name))
            .collect();

        let worker_ifmonitors = ifmonitors.clone();

        let thread_builder = thread::Builder::new().name(format!("dp-worker-{id}"));
        let handle_res = thread_builder.spawn_scoped(scope, move || {
            info!(worker = id, "Worker started");

            // create exit guard for this worker
            let mut guard = subsystem.new_exit_guard(format!("worker {id}"), true);

            // each worker has its own tokio runtime
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build_local(tokio::runtime::LocalOptions::default())?;

            // block on a single task to create and supervise all of this worker's interface readers
            let result = rt.block_on(async {
                // Build readers for interfaces and this worker's interface table
                let (readers, if_table) = match build_interface_table(
                    id,
                    total_workers,
                    interfaces.as_slice(),
                    &worker_ifmonitors,
                ) {
                    Ok(table) => table,
                    Err(e) => {
                        error!(worker = id, "Error building interface table: {}", e);
                        return Err(e);
                    }
                };

                // spawn tasks to read from each interface
                let mut reader_handles = tokio::task::JoinSet::new();
                for intf in readers {
                    Self::spawn_worker_interface_reader(
                        id,
                        intf,
                        &mut reader_handles,
                        setup.clone(),
                        if_table.clone(),
                        cancel.clone(),
                    );
                }

                // Wait for all reader handles to complete
                while let Some(res) = reader_handles.join_next().await {
                    match res {
                        Ok(()) => {}
                        Err(e) => {
                            error!(worker = id, "Reader handle failed: {e}");
                            return Err(e.into());
                        }
                    }
                }

                Ok::<(), io::Error>(())
            });

            if subsystem.is_cancelled() {
                guard.disarm();
            }
            info!(worker = id, "worker exited");
            result?;
            Ok::<(), io::Error>(())
        })?;
        let monitor = WorkerMonitor::new(id, handle_res, ifmonitors);
        Ok(monitor)
    }
}

fn build_interface_table(
    id: WorkerId,
    total_workers: usize,
    interfaces: &[Kif],
    ifmonitors: &[WorkerIfaceMonitor],
) -> Result<(WorkerInterfaceReaders, Arc<WorkerIfTable>), io::Error> {
    let mut if_table = HashMap::new();
    let mut readers = Vec::new();
    for kif in interfaces {
        // find the watchdog for this interface
        let watchdog = ifmonitors
            .iter()
            .find(|ifm| ifm.ifname.as_ref() == kif.name.as_str())
            .map(|ifm| ifm.watchdog.clone())
            .ok_or(io::Error::other("Failed to find interface watchdog"))?;

        let (writer, reader) =
            create_worker_interface(id, total_workers, &kif.name, kif.ifindex, watchdog)?;

        if_table.insert(kif.ifindex, Arc::new(Mutex::new(writer)));
        readers.push(reader);
    }
    Ok((readers, Arc::new(if_table)))
}

/// Build a [`Packet`] out of a frame just read from a socket. `bytes` is the length the
/// kernel reported for the frame, which may be more than what we read into `raw`.
/// Returns `None` if the frame could not be used, and counts why.
fn build_packet(
    id: WorkerId,
    if_name: &str,
    raw: &[u8],
    bytes: usize,
    if_index: InterfaceIndex,
    counters: &mut RxCounters,
) -> Option<Box<Packet<TestBuffer>>> {
    if raw.len() < bytes {
        counters.truncated += 1;
        error!(
            worker = id,
            rx_intf_name = if_name,
            "Received packet with {bytes} bytes on {if_name} but raw buffer is only {} bytes, truncating",
            raw.len()
        );
    }
    let buf = TestBuffer::from_raw_data(&raw[..std::cmp::min(raw.len(), bytes)]);
    match Packet::new(buf) {
        Ok(mut incoming) => {
            incoming.meta_mut().iif = Some(if_index);
            Some(Box::new(incoming))
        }
        Err(e) => {
            // Parsing errors happen; avoid logspam for loopback
            counters.parse_errors += 1;
            if if_name != "lo" {
                error!(
                    worker = id,
                    rx_intf_name = if_name,
                    "Failed to parse packet on '{}': {e}",
                    if_name
                );
            }
            None
        }
    }
}

/// Tries to receive frames from the indicated interface and builds `Packet`s
/// out of them. Returns a vector of [`Packet`]s.
fn packet_recv(
    id: WorkerId,
    if_name: &str,
    if_fd: i32,
    if_index: InterfaceIndex,
    max_to_read: usize,
    pkts: &mut Vec<Box<Packet<TestBuffer>>>,
    counters: &mut RxCounters,
) -> Result<(), nix::Error> {
    let mut raw = [0u8; 9600];
    let mut ret = Ok(());
    pkts.clear();
    while pkts.len() < max_to_read {
        match nix::sys::socket::recv(
            if_fd,
            &mut raw,
            nix::sys::socket::MsgFlags::MSG_DONTWAIT | nix::sys::socket::MsgFlags::MSG_TRUNC,
        ) {
            Ok(0) => {
                // Treated as "no more to read".
                counters.zero_len += 1;
                break;
            }
            Ok(bytes) => {
                trace!("Received packet with {} bytes on {}", bytes, if_name);
                if let Some(pkt) = build_packet(id, if_name, &raw, bytes, if_index, counters) {
                    pkts.push(pkt);
                }
            }
            Err(e) if e == nix::errno::Errno::EWOULDBLOCK => {
                ret = Err(e);
                break;
            }
            Err(e) => {
                ret = Err(e);
                break;
            }
        }
    }
    ret
}

async fn read_packets_from_interface(
    id: WorkerId,
    intf: &WorkerInterfaceReader,
    counters: &mut RxCounters,
) -> Result<Vec<Box<Packet<TestBuffer>>>, io::Error> {
    let fd = &intf.read_fd;
    let mut guard = match fd.readable().await {
        Ok(guard) => guard,
        Err(e) => {
            error!(
                worker = id,
                rx_intf_name = intf.if_name,
                "Unable to wait for readability on interface {}: {e}",
                intf.if_name
            );
            return Err(e);
        }
    };
    // pat the watchdog
    intf.watchdog.pat();

    if !guard.ready().is_readable() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::WouldBlock,
            "Would block",
        ));
    }
    let mut pkts = Vec::with_capacity(DriverKernel::MAX_RX_PKT_BATCH);
    match guard.try_io(|fd| {
        packet_recv(
            id,
            intf.if_name.as_str(),
            fd.as_raw_fd(),
            intf.if_index,
            DriverKernel::MAX_RX_PKT_BATCH,
            &mut pkts,
            counters,
        )
        .map_err(std::convert::Into::into)
    }) {
        Ok(result) => match result {
            Ok(()) => (),
            Err(e) => {
                error!(
                    worker = id,
                    rx_intf_name = intf.if_name,
                    "Unable to receive packet on interface {}, index: {}: {e}",
                    intf.if_name,
                    intf.if_index
                );
            }
        },
        Err(_wouldblock) => (),
    }

    // Ask the kernel what it dropped on the socket while we were away. This is
    // read-and-clear, so it must be polled on each pass or the counts pile up.
    match sockstats::get_kernel_drops(fd.get_ref()) {
        Ok(drops) => counters.kernel_drops += drops,
        Err(e) => {
            debug!(
                worker = id,
                rx_intf_name = intf.if_name,
                "Unable to read socket statistics on interface {}: {e}",
                intf.if_name
            );
        }
    }

    trace!(
        worker = id,
        rx_intf_name = intf.if_name,
        "Received {} packets from interface {}, index: {}",
        pkts.len(),
        intf.if_name,
        intf.if_index,
    );
    Ok(pkts)
}

async fn tx_packet(
    id: WorkerId,
    rx_if_name: &str,
    if_table: &WorkerIfTable,
    pkt: Packet<TestBuffer>,
) -> bool {
    debug_assert_eq!(pkt.get_done(), Some(DoneReason::Delivered));
    // get outgoing interface marking. Should always have one. Otherwise the egress stage is buggy
    let Some(oif) = pkt.meta().oif else {
        error!(
            worker = id,
            rx_intf_name = rx_if_name,
            "Missing oif in packet metadata. Will drop packet (pipeline bug)"
        );
        return false;
    };

    // lookup interface
    let Some(outgoing_unlocked) = if_table.get(&oif) else {
        warn!(
            worker = id,
            rx_intf_name = rx_if_name,
            "TX drop: unknown oif {} (driver bug)",
            oif
        );
        return false;
    };

    // serialize and xmit
    match pkt.serialize() {
        Ok(out) => {
            let mut outgoing = outgoing_unlocked.lock().await;
            let len = out.as_ref().len();
            trace!(
                worker = id,
                rx_intf_name = rx_if_name,
                "TXing {len} bytes on interface {}",
                &outgoing.if_name
            );
            match outgoing.sock.write(out.as_ref()).await {
                Ok(written) if written == len => {}
                Ok(written) => {
                    // One write is one frame on a packet socket, so we can't complete a partial
                    // write with a second one: the remainder would go out as its own frame.
                    warn!(
                        worker = id,
                        rx_intf_name = rx_if_name,
                        "TX wrote {written} of {len} octets on interface '{}'. Dropping packet",
                        &outgoing.if_name
                    );
                    return false;
                }
                Err(e) => {
                    warn!(
                        worker = id,
                        rx_intf_name = rx_if_name,
                        "TX failed for pkt ({len} octets) on interface '{}': {e}",
                        &outgoing.if_name
                    );
                    return false;
                }
            }
            trace!(
                worker = id,
                rx_intf_name = rx_if_name,
                "TX {len} bytes on interface {}",
                &outgoing.if_name
            );
            true
        }
        Err(e) => {
            warn!(
                worker = id,
                rx_intf_name = rx_if_name,
                "Serialize failed: {e:?}"
            );
            false
        }
    }
}

#[cfg(test)]
mod test {
    use super::{RxCounters, build_packet};
    use net::buffer::test_buffer::TestBuffer;
    use net::interface::InterfaceIndex;
    use net::packet::Packet;
    use net::packet::test_utils::build_test_ipv4_packet;

    const IF_INDEX: u32 = 1;
    const IF_NAME: &str = "test0";

    fn if_index() -> InterfaceIndex {
        InterfaceIndex::try_new(IF_INDEX).expect("bad interface index")
    }

    fn build_test_frame() -> Packet<TestBuffer> {
        build_test_ipv4_packet(64).expect("failed to build test packet")
    }

    /// A frame we can parse is returned, and tagged with the interface it came from.
    #[test]
    fn good_frame_is_not_counted_as_an_error() {
        let packet = build_test_frame();
        let buf = packet.serialize().expect("failed to serialize test packet");
        let raw = buf.as_ref();

        let mut counters = RxCounters::default();
        let built = build_packet(0, IF_NAME, raw, raw.len(), if_index(), &mut counters)
            .expect("valid frame should be built");

        assert_eq!(built.meta().iif, Some(if_index()));
        assert_eq!(counters.parse_errors, 0);
        assert_eq!(counters.truncated, 0);
    }

    /// A frame we cannot parse is dropped, and counted.
    #[test]
    fn unparseable_frame_is_counted() {
        let raw = [0xffu8; 4];

        let mut counters = RxCounters::default();
        let built = build_packet(0, IF_NAME, &raw, raw.len(), if_index(), &mut counters);

        assert!(built.is_none());
        assert_eq!(counters.parse_errors, 1);
        assert_eq!(counters.truncated, 0);
    }

    /// A frame longer than what we read is counted, whether or not we can parse it.
    #[test]
    fn oversize_frame_is_counted() {
        let packet = build_test_frame();
        let buf = packet.serialize().expect("failed to serialize test packet");
        let raw = buf.as_ref();

        let mut counters = RxCounters::default();
        // the kernel tells us the frame was longer than what it copied for us
        let built = build_packet(0, IF_NAME, raw, raw.len() + 1, if_index(), &mut counters);

        assert!(built.is_some());
        assert_eq!(counters.truncated, 1);
        assert_eq!(counters.parse_errors, 0);
    }
}
