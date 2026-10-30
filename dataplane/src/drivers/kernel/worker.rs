// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

// We want to avoid Packet moves, so allow Vec<Box<_>> to be sure
#![allow(clippy::vec_box)]

use std::collections::HashMap;
use std::io;
use std::io::IoSliceMut;
use std::os::fd::AsRawFd;

use afpacket::tokio::RawPacketStream;
use nix::libc;
use nix::sys::socket::MsgFlags;
use nix::{setsockopt_impl, sockopt_impl};
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncWriteExt, Interest};
use tokio::sync::Mutex;
use tokio::time::{Duration, interval};

/// How often a quiet interface's reader still expires flows: the flow wheel's tick.
const EXPIRY_PERIOD: Duration = Duration::from_millis(10);

use concurrency::sync::Arc;
use concurrency::thread;
#[allow(unused_imports)] // used under loom/shuttle backends
use concurrency::thread::BuilderExt;
use lifecycle::{CancellationToken, Subsystem};
use net::buffer::test_buffer::TestBuffer;
use net::interface::InterfaceIndex;
use net::packet::{DoneReason, Packet};
use pipeline::NetworkFunction;

use crate::drivers::cpbridge::Frame;
use crate::drivers::disposition::Disposition;
use crate::drivers::kernel::DriverKernel;
use crate::drivers::kernel::fanout::{PacketFanoutType, set_packet_fanout};
use crate::drivers::kernel::kif::Kif;
use crate::drivers::kernel::multicast::receive_all_multicast;
use crate::drivers::kernel::sockstats;
use crate::drivers::status::WorkerId;
use crate::drivers::supervisor::{RxTaskMonitor, TASK_PAT_PERIOD, WorkerMonitor};
use crate::drivers::watchdog::{RxCounters, Watchdog};
use crate::packet_processor::{EXPIRY_BUDGET, PipelineFactory, WorkerPipeline};

use tracing::{debug, error, info, trace, warn};

/// One port's share of the control-plane bridge, as a single worker sees it.
///
/// The parts are split differently on purpose. `index` and `punt` are given to **every** worker:
/// any worker can receive a frame the kernel should see, and every worker has to stamp received
/// packets with the index the rest of the dataplane knows this interface by. `inject` is given to
/// exactly one, because two workers draining the same queue would interleave a peering session's
/// frames across two sockets and reorder them.
pub(crate) struct BridgedPort {
    /// The interface this stands in for, which is also the tap's name.
    pub(crate) name: String,
    /// The tap's interface index -- see [`crate::drivers::cpbridge::PortCpQueues::index`].
    pub(crate) index: InterfaceIndex,
    /// Where a punted frame goes.
    pub(crate) punt: tokio::sync::mpsc::Sender<Frame>,
    /// Frames the kernel wants transmitted. `None` on every worker but the drainer.
    pub(crate) inject: Option<crate::drivers::cpbridge::InjectReceiver>,
}

struct WorkerInterfaceWriter {
    if_name: String,
    #[allow(unused)]
    if_index: InterfaceIndex,
    sock: RawPacketStream,
}

struct WorkerInterfaceReader {
    if_name: String,
    /// The index the rest of the dataplane knows this interface by.
    ///
    /// The tap's, when a bridge stands in for this interface, and the kernel interface's own
    /// otherwise. Stamped onto every received packet as `iif`, because the ingress stage looks the
    /// interface up in a table built from the *control plane's* view. See
    /// [`PortCpQueues::index`](crate::drivers::cpbridge::PortCpQueues::index).
    if_index: InterfaceIndex,
    read_fd: AsyncFd<std::os::unix::io::OwnedFd>,
    watchdog: Watchdog,
    /// Where a punted frame goes, when this interface has a tap standing in for it.
    punt: Option<tokio::sync::mpsc::Sender<Frame>>,
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
    punt: Option<tokio::sync::mpsc::Sender<Frame>>,
) -> io::Result<(WorkerInterfaceWriter, WorkerInterfaceReader)> {
    // `if_index` is the dataplane-wide identity; the socket is bound by *name*, which resolves in
    // this thread's namespace to the real interface. The two are deliberately different things.
    let mut sock = RawPacketStream::new()?;
    sock.bind(if_name)
        .inspect_err(|e| error!("Failed to open raw sock for interface {if_name}: {e}"))?;

    let fd = sock.as_raw_fd();
    let buf_size = 4 * 1024 * 1024;

    let bfd = unsafe { std::os::unix::io::BorrowedFd::borrow_raw(fd) };
    // With a tap standing in for this interface, the control plane's multicast arrives here or
    // nowhere. Not fatal: forwarding does not need it.
    if punt.is_some()
        && let Err(e) = receive_all_multicast(bfd, if_name)
    {
        error!(
            "Could not have {if_name} accept all multicast ({e}); LLDP and IPv6 neighbour \
             discovery from its peers will not reach the control plane"
        );
    }
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
    nix::sys::socket::setsockopt(&bfd, PacketAuxdata, &true).inspect_err(|e| {
        error!("Failed to set PACKET_AUXDATA for interface {if_name}: {e}");
    })?;

    let read_fd_owned = nix::unistd::dup(bfd).map_err(io::Error::from)?;
    // SAFETY: The AsyncFd takes ownership of the duplicated OwnedFd, so the fd stays open for its
    // whole lifetime and as_raw_fd() always returns the same value.
    let read_fd = unsafe { AsyncFd::register_with_interest(read_fd_owned, Interest::READABLE) }?;
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
            punt,
        },
    ))
}

pub struct Worker {
    id: WorkerId,
    total_workers: usize,
    setup_pipeline: PipelineFactory<'static, TestBuffer>,
    subsystem: Subsystem,
}

impl Worker {
    pub fn new(
        id: WorkerId,
        total_workers: usize,
        setup_pipeline: &PipelineFactory<'static, TestBuffer>,
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
    #[allow(clippy::too_many_lines)] // the punt/transmit decision belongs beside the rx loop
    fn spawn_worker_interface_reader(
        id: WorkerId,
        intf: WorkerInterfaceReader,
        reader_handles: &mut tokio::task::JoinSet<()>,
        setup: PipelineFactory<'static, TestBuffer>,
        if_table: Arc<HashMap<InterfaceIndex, Arc<Mutex<WorkerInterfaceWriter>>>>,
        cancel: CancellationToken,
    ) {
        // the interval at which we'll pat the watchdog if there is no activity on the socket
        let pat_period = Duration::from_secs(u64::from(TASK_PAT_PERIOD));

        reader_handles.spawn_local(async move {
            let intf = intf;
            let WorkerPipeline {
                mut pipeline,
                flows,
            } = setup();
            let mut ticker = interval(pat_period);
            // Flows created by this pipeline expire on its handle's wheel, driven from here: after
            // every burst, and on this tick while the interface is quiet.
            let mut expiry = interval(EXPIRY_PERIOD);
            expiry.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
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
                    _ = ticker.tick() => {
                        intf.watchdog.pat();
                        Vec::new()
                    }
                    _ = expiry.tick() => {
                        flows.expire(clock::now(), EXPIRY_BUDGET);
                        continue;
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
                if rx_pkts > 0 {
                    flows.expire(clock::now(), EXPIRY_BUDGET);
                }

                // What becomes of each packet is [`Disposition::of`]'s decision, the same one the
                // DPDK driver asks. When this interface has a tap standing in for it, the kernel
                // is on the far side of that tap and has seen nothing: the interface was moved
                // into the datapath's namespace, so the host stack no longer has it. Anything the
                // pipeline marked `Local` has to be carried across, or the control plane never
                // learns a peer's MAC and BGP never forms an adjacency.
                //
                // Init moves the interfaces out of the host stack, so a tap is the kernel's only
                // view of them. `punt` is `None` only without a bridge (its creation failed,
                // which is fatal, or a test), and a frame for the kernel is then lost: a punt drop,
                // as in the DPDK driver.
                let mut ppline_drops: u64 = 0;
                let mut punted: u64 = 0;
                let mut punt_drops: u64 = 0;
                for out_pkt in out_pkts {
                    match Disposition::of(&out_pkt) {
                        Disposition::Transmit => {
                            to_tx += 1;
                            if tx_packet(id, &intf.if_name, &if_table, out_pkt).await {
                                tx_pkts += 1;
                            } else {
                                tx_drops += 1;
                            }
                        }
                        Disposition::Punt => match &intf.punt {
                            Some(punt) if punt_packet(id, &intf.if_name, punt, out_pkt) => {
                                punted += 1;
                            }
                            _ => punt_drops += 1,
                        },
                        Disposition::Drop => ppline_drops += 1,
                    }
                }
                if punted > 0 {
                    trace!(
                        worker = id,
                        rx_intf_name = intf.if_name,
                        "Punted {punted} frames to the control plane",
                    );
                }

                tracing::debug!(
                    worker = id,
                    rx_intf_name = intf.if_name,
                    "Sent {tx_pkts} packets out of {to_tx}, dropped {tx_drops}",
                );

                // Update RX task stats.
                counters.ppline_drops = ppline_drops;
                counters.tx = tx_pkts;
                counters.tx_drops = tx_drops;
                counters.punt_drops = punt_drops;
                intf.watchdog.record(&counters);
            }
        });
    }

    pub fn start<'scope>(
        self,
        scope: &'scope thread::Scope<'scope, '_>,
        interfaces: &[Kif],
        bridge: Vec<BridgedPort>,
    ) -> Result<WorkerMonitor<'scope, io::Error>, io::Error> {
        let id = self.id;
        let total_workers = self.total_workers;
        let setup = self.setup_pipeline;
        let subsystem = self.subsystem;
        let cancel = subsystem.cancel_token();
        let interfaces = interfaces.to_vec();

        // Create vector of `RxTaskMonitor` with the watchdogs. We'll hand a watchdog to each
        // interface reader and pass this vector along with the `WorkerMonitor` returned for this `Worker`
        // for the supervisor to check. Ideally we'd create the watchdogs in the interface readers and
        // collect them. However build_interface_table() needs to be called from the worker's tokio runtime
        let ifmonitors: Vec<_> = interfaces
            .iter()
            .map(|kif| RxTaskMonitor::new(&kif.name))
            .collect();

        let worker_ifmonitors = ifmonitors.clone();

        let mut bridge: HashMap<String, BridgedPort> = bridge
            .into_iter()
            .map(|port| (port.name.clone(), port))
            .collect();

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
                    &mut bridge,
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

                // And one task per interface whose queues this worker took, carrying what the
                // control plane wants sent. Only this worker has them -- see
                // `DriverKernel::spawn_workers_scoped` for why that is not merely tidiness.
                for (if_name, port) in bridge.drain() {
                    let Some(inject) = port.inject else {
                        continue;
                    };
                    let Some(writer) = if_table.get(&port.index).cloned() else {
                        warn!(
                            worker = id,
                            "the bridge has an injection queue for {if_name}, which this worker \
                             has no socket for; the control plane cannot transmit on it"
                        );
                        continue;
                    };
                    reader_handles.spawn_local(inject_frames(
                        id,
                        if_name,
                        inject,
                        writer,
                        cancel.clone(),
                    ));
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
    ifmonitors: &[RxTaskMonitor],
    bridge: &mut HashMap<String, BridgedPort>,
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

        // Keyed by name, because the two indices in play mean different things and only the name
        // is common to both namespaces.
        let bridged = bridge.get(kif.name.as_str());
        let punt = bridged.map(|port| port.punt.clone());

        // The tap's index when there is a bridge, this interface's own when there is not. This is
        // the number the pipeline will use for both `iif` and `oif`, so the table is keyed by it.
        let if_index = bridged.map_or(kif.ifindex, |port| port.index);

        let (writer, reader) =
            create_worker_interface(id, total_workers, &kif.name, if_index, watchdog, punt)?;

        if_table.insert(if_index, Arc::new(Mutex::new(writer)));
        readers.push(reader);
    }
    Ok((readers, Arc::new(if_table)))
}

sockopt_impl!(
    /// Request per-frame metadata, including checksum status, from the packet socket.
    ///
    /// TCP and UDP frames from a local stack over veth, or a guest using virtio checksum offload,
    /// may arrive with `CHECKSUM_PARTIAL`. Their checksum field contains the pseudo-header sum;
    /// the remaining checksum computation must be completed before transmission.
    PacketAuxdata,
    SetOnly,
    libc::SOL_PACKET,
    libc::PACKET_AUXDATA,
    bool
);

/// Space for one `tpacket_auxdata` message, including its control-message header and padding.
const CONTROL_LEN: usize = 64;

/// Read `TP_STATUS_CSUMNOTREADY` from a control buffer zeroed before `recvmsg`.
/// Returns `None` if control messages were truncated (`MSG_CTRUNC`), or `Some(false)` if no
/// message reports an unfinished checksum.
fn checksum_unfinished(control: &[u8], flags: MsgFlags) -> Option<bool> {
    const HEADER: usize = size_of::<libc::cmsghdr>();
    // `CMSG_ALIGN`, in glibc and musl alike.
    let align = |len: usize| len.next_multiple_of(size_of::<usize>());
    if flags.contains(MsgFlags::MSG_CTRUNC) {
        return None;
    }
    let mut at = 0;
    while let Some(bytes) = control.get(at..at + HEADER) {
        #[allow(unsafe_code)]
        // SAFETY: `bytes` holds a whole `cmsghdr`, which is plain integers: any octets are one.
        let header: libc::cmsghdr = unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast()) };
        #[allow(clippy::unnecessary_cast, clippy::useless_conversion)] // usize or u32, by libc
        let len = usize::try_from(header.cmsg_len).unwrap_or(0);
        if len < HEADER {
            break; // the zeroes after the last message
        }
        if header.cmsg_level == libc::SOL_PACKET && header.cmsg_type == libc::PACKET_AUXDATA {
            // `tp_status` leads `struct tpacket_auxdata`.
            let data = at + align(HEADER);
            return Some(
                control
                    .get(data..)
                    .and_then(<[u8]>::first_chunk::<4>)
                    .is_some_and(|status| {
                        u32::from_ne_bytes(*status) & libc::TP_STATUS_CSUMNOTREADY != 0
                    }),
            );
        }
        at += align(len);
    }
    Some(false)
}

/// Build a [`Packet`] from a received frame. `bytes` is the reported frame length, which may
/// exceed `raw`. `checksum_unfinished` requests a refresh for partial or unknown checksum status.
/// Returns `None` if the frame could not be used, and counts why.
fn build_packet(
    id: WorkerId,
    if_name: &str,
    raw: &[u8],
    bytes: usize,
    checksum_unfinished: bool,
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
            if checksum_unfinished {
                // Request a transport checksum refresh for partial or unknown checksum status.
                incoming.meta_mut().set_checksum_refresh(true);
            }
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
        let mut control = [0u8; CONTROL_LEN];
        let received = nix::sys::socket::recvmsg::<()>(
            if_fd,
            &mut [IoSliceMut::new(&mut raw)],
            Some(&mut control),
            MsgFlags::MSG_DONTWAIT | MsgFlags::MSG_TRUNC,
        )
        .map(|message| (message.bytes, message.flags));
        let received = received.map(|(bytes, flags)| {
            // Refresh unknown status too, to avoid forwarding a partial checksum. This can
            // overwrite an already computed checksum and mask corruption.
            let unfinished = checksum_unfinished(&control, flags).unwrap_or_else(|| {
                counters.csum_unknown += 1;
                true
            });
            (bytes, unfinished)
        });
        match received {
            Ok((0, _)) => {
                // Treated as "no more to read".
                counters.zero_len += 1;
                break;
            }
            Ok((bytes, checksum_unfinished)) => {
                trace!("Received packet with {} bytes on {}", bytes, if_name);
                if let Some(pkt) = build_packet(
                    id,
                    if_name,
                    &raw,
                    bytes,
                    checksum_unfinished,
                    if_index,
                    counters,
                ) {
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

/// Hand a frame to the kernel through the tap standing in for the interface it arrived on.
///
/// Returns whether it was handed over. A `false` here is counted as a punt drop: the packet was
/// meant for the kernel, and the kernel did not get it.
///
/// The frame is copied. It has to be: the far end of this channel is a task on the management
/// runtime, and the packet's buffer belongs to this worker. `serialize` first, so what the kernel
/// sees is the frame as the pipeline left it -- the same bytes a transmit would have put on the
/// wire -- rather than a payload stripped of its headers.
fn punt_packet(
    id: WorkerId,
    rx_if_name: &str,
    punt: &tokio::sync::mpsc::Sender<Frame>,
    pkt: Packet<TestBuffer>,
) -> bool {
    let serialized = match pkt.serialize() {
        Ok(out) => out,
        Err(e) => {
            trace!(
                worker = id,
                rx_intf_name = rx_if_name,
                "failed to serialize a frame to punt: {e:?}"
            );
            return false;
        }
    };

    // `try_send`, never a blocking send. This is the packet path and there is nothing here it may
    // wait for; a full queue means the tap's pump has fallen behind, which is a control-plane
    // problem and not a reason to stop forwarding.
    if punt.try_send(serialized.as_ref().to_vec()).is_err() {
        trace!(
            worker = id,
            rx_intf_name = rx_if_name,
            "punt queue is full; dropping a frame for the kernel"
        );
        return false;
    }
    true
}

/// Carry whatever the kernel has queued for an interface onto the wire.
///
/// # Why this bypasses the pipeline
///
/// FRR has already made the forwarding decision. These frames come off a tap standing in for this
/// exact interface, carrying the headers the kernel built; running them through the pipeline would
/// route them a second time, using tables derived from the kernel's own decision.
///
/// # Why one worker
///
/// Only the worker that took this interface's queues runs this. Draining from two would interleave
/// a peering session's frames across two sockets and reorder them.
async fn inject_frames(
    id: WorkerId,
    if_name: String,
    mut inject: crate::drivers::cpbridge::InjectReceiver,
    writer: Arc<Mutex<WorkerInterfaceWriter>>,
    cancel: CancellationToken,
) {
    loop {
        let frame = tokio::select! {
            () = cancel.cancelled() => break,
            frame = inject.recv() => match frame {
                Some(frame) => frame,
                // The bridge is gone, which happens on shutdown and means there is nothing left
                // to carry.
                None => break,
            },
        };

        let mut outgoing = writer.lock().await;
        match outgoing.sock.write(frame.as_slice()).await {
            Ok(written) if written == frame.len() => {
                trace!(
                    worker = id,
                    "injected {written} bytes from the control plane on {if_name}"
                );
            }
            Ok(written) => warn!(
                worker = id,
                "short write injecting on {if_name}: {written} of {} bytes; one write is one \
                 frame on a packet socket, so this frame is lost",
                frame.len()
            ),
            Err(e) => warn!(
                worker = id,
                "failed to inject a control-plane frame on {if_name}: {e}"
            ),
        }
    }
    debug!(worker = id, "injection for {if_name} stopped");
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
    use super::{CONTROL_LEN, Disposition, RxCounters, build_packet, checksum_unfinished};
    use net::buffer::test_buffer::TestBuffer;
    use net::interface::InterfaceIndex;
    use net::packet::test_utils::{build_test_ipv4_packet, build_test_ipv6_packet};
    use net::packet::{DoneReason, Packet};
    use nix::libc;
    use nix::sys::socket::MsgFlags;
    use pipeline::{NetworkFunction, sample_nfs::DecrementTtl};

    const IF_INDEX: u32 = 1;
    const IF_NAME: &str = "test0";

    fn if_index() -> InterfaceIndex {
        InterfaceIndex::try_new(IF_INDEX).expect("bad interface index")
    }

    fn build_test_frame() -> Packet<TestBuffer> {
        build_test_ipv4_packet(64).expect("failed to build test packet")
    }

    #[test]
    fn only_delivered_verdicts_are_transmitted() {
        let packets: Vec<_> = (0..=u8::MAX)
            .filter_map(DoneReason::from_repr)
            .map(|reason| {
                let mut packet = build_test_frame();
                packet.done(reason);
                packet
            })
            .collect();
        let expected_drops = packets.len() - 2;
        let drops = packets
            .iter()
            .filter(|packet| Disposition::of(packet) == Disposition::Drop)
            .count();
        let transmitted: Vec<_> = packets
            .into_iter()
            .filter(|packet| Disposition::of(packet) == Disposition::Transmit)
            .collect();

        assert_eq!(transmitted.len(), 1);
        assert_eq!(transmitted[0].get_done(), Some(DoneReason::Delivered));
        assert_eq!(drops, expected_drops);
    }

    #[test]
    fn ttl_drops_and_missing_verdicts_are_accounted() {
        let mut burst = vec![
            build_test_ipv4_packet(0).unwrap(),
            build_test_ipv6_packet(0).unwrap(),
            build_test_frame(),
        ];
        DecrementTtl.process_burst(&mut burst);
        let drops = burst
            .iter()
            .filter(|packet| Disposition::of(packet) == Disposition::Drop)
            .count();
        let transmitted = burst
            .iter()
            .filter(|packet| Disposition::of(packet) == Disposition::Transmit)
            .count();

        assert_eq!(transmitted, 0);
        assert_eq!(drops, 3);
    }

    /// A frame we can parse is returned, and tagged with the interface it came from.
    #[test]
    fn good_frame_is_not_counted_as_an_error() {
        let packet = build_test_frame();
        let buf = packet.serialize().expect("failed to serialize test packet");
        let raw = buf.as_ref();

        let mut counters = RxCounters::default();
        let built = build_packet(0, IF_NAME, raw, raw.len(), false, if_index(), &mut counters)
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
        let built = build_packet(
            0,
            IF_NAME,
            &raw,
            raw.len(),
            false,
            if_index(),
            &mut counters,
        );

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
        let built = build_packet(
            0,
            IF_NAME,
            raw,
            raw.len() + 1,
            false,
            if_index(),
            &mut counters,
        );

        assert!(built.is_some());
        assert_eq!(counters.truncated, 1);
        assert_eq!(counters.parse_errors, 0);
    }

    /// A `PACKET_AUXDATA` control message with `status`, at the start of a zeroed buffer, as
    /// `recvmsg` leaves it.
    fn auxdata(status: u32) -> [u8; CONTROL_LEN] {
        let header = size_of::<libc::cmsghdr>();
        let data = header.next_multiple_of(size_of::<usize>());
        let len = data + size_of::<libc::tpacket_auxdata>();
        let mut control = [0u8; CONTROL_LEN];
        // `cmsg_len` is the leading field, a size_t in glibc and a socklen_t in musl, either way
        // native-endian; the rest of it is zero.
        control[..size_of::<u32>()].copy_from_slice(&u32::try_from(len).unwrap().to_ne_bytes());
        let level = std::mem::offset_of!(libc::cmsghdr, cmsg_level);
        control[level..level + 4].copy_from_slice(&libc::SOL_PACKET.to_ne_bytes());
        let kind = std::mem::offset_of!(libc::cmsghdr, cmsg_type);
        control[kind..kind + 4].copy_from_slice(&libc::PACKET_AUXDATA.to_ne_bytes());
        control[data..data + 4].copy_from_slice(&status.to_ne_bytes());
        control
    }

    #[test]
    fn the_checksum_status_is_read_from_the_control_messages() {
        let partial = auxdata(libc::TP_STATUS_CSUMNOTREADY | libc::TP_STATUS_USER);
        let finished = auxdata(libc::TP_STATUS_USER);
        assert_eq!(checksum_unfinished(&partial, MsgFlags::empty()), Some(true));
        assert_eq!(
            checksum_unfinished(&finished, MsgFlags::empty()),
            Some(false)
        );
        assert_eq!(
            checksum_unfinished(&[0; CONTROL_LEN], MsgFlags::empty()),
            Some(false),
            "no control message, no partial checksum"
        );
        assert_eq!(
            checksum_unfinished(&finished, MsgFlags::MSG_CTRUNC),
            None,
            "truncated control messages leave the status unknown"
        );
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod vm_tests {
    use super::{PacketAuxdata, packet_recv};
    use crate::drivers::watchdog::RxCounters;
    use caps::Capability;
    use fixin::wrap;
    use hardware::netns::NetworkNamespace;
    use net::buffer::test_buffer::TestBuffer;
    use net::checksum::{Checksum, ones_complement_sum as sum};
    use net::headers::{TryHeaders, TryIp, TryUdp};
    use net::interface::InterfaceIndex;
    use net::packet::Packet;
    use net::udp::UdpChecksumPayload;
    use nix::libc;
    use nix::sys::socket::setsockopt;
    use nix::{setsockopt_impl, sockopt_impl};
    use rtnetlink::{LinkUnspec, LinkVeth};
    use std::io::Write;
    use std::os::fd::{AsRawFd, BorrowedFd};
    use test_utils::with_caps;

    const SOURCE_PORT: u16 = 4000;
    /// The UDP checksum's offset in [`frame`]: Ethernet, IPv4, then 6 octets into UDP.
    const UDP_CHECKSUM: usize = 14 + 20 + 6;

    sockopt_impl!(
        /// `PACKET_VNET_HDR`: a `virtio_net_hdr` leads every frame sent on the socket.
        PacketVnetHdr,
        SetOnly,
        libc::SOL_PACKET,
        libc::PACKET_VNET_HDR,
        bool
    );

    /// `stream`'s socket, borrowed for as long as `stream` lives.
    fn fd(stream: &afpacket::sync::RawPacketStream) -> BorrowedFd<'_> {
        #[allow(unsafe_code)]
        // SAFETY: `stream` owns the socket and keeps it open for the borrow's lifetime.
        unsafe {
            BorrowedFd::borrow_raw(stream.as_raw_fd())
        }
    }

    /// A broadcast UDP datagram from 10.0.0.1 to 10.0.0.2, carrying `checksum`.
    fn frame(destination_port: u16, checksum: u16) -> Vec<u8> {
        let payload = [0x5a_u8; 32];
        let udp_len = u16::try_from(8 + payload.len()).unwrap();
        let mut ipv4 = vec![
            0x45, 0, 0, 0, 0, 1, 0, 0, 64, 17, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2,
        ];
        ipv4[2..4].copy_from_slice(&(20 + udp_len).to_be_bytes());
        let ipv4_checksum = !sum(&ipv4);
        ipv4[10..12].copy_from_slice(&ipv4_checksum.to_be_bytes());
        let mut out = vec![0xff; 6];
        out.extend_from_slice(&[2, 0, 0, 0, 0, 1, 0x08, 0x00]);
        out.extend_from_slice(&ipv4);
        out.extend_from_slice(&SOURCE_PORT.to_be_bytes());
        out.extend_from_slice(&destination_port.to_be_bytes());
        out.extend_from_slice(&udp_len.to_be_bytes());
        out.extend_from_slice(&checksum.to_be_bytes());
        out.extend_from_slice(&payload);
        out
    }

    /// The sum of [`frame`]'s pseudo-header, which is what a stack leaves in the checksum field
    /// for the device to finish.
    fn pseudo_header_sum(frame: &[u8]) -> u16 {
        let udp_len = u16::try_from(frame.len() - 34).unwrap();
        let mut pseudo = frame[26..34].to_vec(); // source and destination
        pseudo.extend_from_slice(&[0, 17]);
        pseudo.extend_from_slice(&udp_len.to_be_bytes());
        sum(&pseudo)
    }

    /// A `virtio_net_hdr`: with `needs_checksum`, the kernel takes the frame as `CHECKSUM_PARTIAL`,
    /// the UDP checksum left for the device to finish, as a guest's virtio driver hands it over.
    fn virtio_net_hdr(needs_checksum: bool) -> [u8; 10] {
        const VIRTIO_NET_HDR_F_NEEDS_CSUM: u8 = 1;
        let mut header = [0u8; 10];
        if needs_checksum {
            header[0] = VIRTIO_NET_HDR_F_NEEDS_CSUM;
            header[6..8].copy_from_slice(&34_u16.to_ne_bytes()); // csum_start: the UDP header
            header[8..10].copy_from_slice(&6_u16.to_ne_bytes()); // csum_offset: its checksum
        }
        header
    }

    /// A frame the kernel delivers with its transport checksum unfinished is marked for serialize
    /// to finish, and leaves with a valid checksum. A finished one is left alone.
    #[n_vm::test]
    #[wrap(with_caps([Capability::CAP_NET_ADMIN, Capability::CAP_SYS_ADMIN, Capability::CAP_NET_RAW]))]
    fn a_checksum_the_kernel_left_unfinished_is_finished_on_the_way_out() {
        std::thread::spawn(|| {
            let netns = NetworkNamespace::create().unwrap();
            netns.enter_with_sysfs().unwrap();
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    let (connection, handle, _) = rtnetlink::new_connection().unwrap();
                    let connection = tokio::spawn(connection);
                    handle
                        .link()
                        .add(LinkVeth::new("ck0", "ck1").build())
                        .execute()
                        .await
                        .unwrap();
                    for name in ["ck0", "ck1"] {
                        let index = nix::net::if_::if_nametoindex(name).unwrap();
                        handle
                            .link()
                            .set(LinkUnspec::new_with_index(index).up().build())
                            .execute()
                            .await
                            .unwrap();
                    }
                    connection.abort();
                });

            let mut receiver = afpacket::sync::RawPacketStream::new().unwrap();
            receiver.bind("ck0").unwrap();
            setsockopt(&fd(&receiver), PacketAuxdata, &true).unwrap();

            let mut sender = afpacket::sync::RawPacketStream::new().unwrap();
            sender.bind("ck1").unwrap();
            setsockopt(&fd(&sender), PacketVnetHdr, &true).unwrap();

            let mut unfinished = frame(4001, 0);
            let seed = pseudo_header_sum(&unfinished);
            unfinished[UDP_CHECKSUM..UDP_CHECKSUM + 2].copy_from_slice(&seed.to_be_bytes());
            let mut finished = frame(4002, 0);
            let checksum = match !sum(&[
                &finished[26..34],
                &[0, 17],
                &finished[38..40],
                &finished[34..],
            ]
            .concat())
            {
                0 => 0xffff,
                checksum => checksum,
            };
            finished[UDP_CHECKSUM..UDP_CHECKSUM + 2].copy_from_slice(&checksum.to_be_bytes());
            for (needs_checksum, frame) in [(true, &unfinished), (false, &finished)] {
                sender
                    .write_all(&[&virtio_net_hdr(needs_checksum)[..], frame].concat())
                    .unwrap();
            }

            // Both frames, keyed by destination port, as the driver's worker would build them.
            let mut received = std::collections::HashMap::new();
            let mut counters = RxCounters::default();
            for _ in 0..100 {
                let mut packets = Vec::new();
                let _ = packet_recv(
                    0,
                    "ck0",
                    receiver.as_raw_fd(),
                    InterfaceIndex::try_new(1).unwrap(),
                    16,
                    &mut packets,
                    &mut counters,
                );
                for packet in packets {
                    if let Some(udp) = packet.headers().try_udp()
                        && udp.source().as_u16() == SOURCE_PORT
                    {
                        received.insert(udp.destination().as_u16(), packet);
                    }
                }
                if received.len() == 2 {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            let unfinished = received
                .remove(&4001)
                .expect("the unfinished frame never arrived");
            let finished = received
                .remove(&4002)
                .expect("the finished frame never arrived");
            assert!(
                unfinished.meta().checksum_refresh(),
                "a frame whose checksum the kernel left unfinished was not marked to finish it"
            );
            assert!(
                !finished.meta().checksum_refresh(),
                "a frame with a finished checksum was marked for a recompute"
            );

            let out = unfinished.serialize().unwrap().as_ref().to_vec();
            let out = Packet::new(TestBuffer::from_raw_data(&out)).unwrap();
            let net = out.headers().try_ip().unwrap().clone();
            out.headers()
                .try_udp()
                .unwrap()
                .validate_checksum(&UdpChecksumPayload::new(&net, &[0x5a_u8; 32]))
                .expect("the unfinished checksum left unfinished");
        })
        .join()
        .unwrap();
    }
}
