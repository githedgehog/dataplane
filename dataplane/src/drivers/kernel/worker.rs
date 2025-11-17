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

use concurrency::sync::Arc;
use concurrency::thread;
use net::buffer::test_buffer::TestBuffer;
use net::interface::InterfaceIndex;
use net::packet::Packet;
use pipeline::{DynPipeline, NetworkFunction};

use crate::drivers::kernel::fanout::{PacketFanoutType, set_packet_fanout};
use crate::drivers::kernel::kif::Kif;
use crate::drivers::tokio_util::{force_send, run_in_local_tokio_runtime};

use tracing::{debug, error, info, trace, warn};

type WorkerId = usize;

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
}

type WorkerInterfaceReaders = Vec<WorkerInterfaceReader>;
type WorkerIfTable = HashMap<InterfaceIndex, Arc<Mutex<WorkerInterfaceWriter>>>;

#[allow(unsafe_code)]
fn create_worker_interface(
    id: WorkerId,
    total_workers: usize,
    if_name: &str,
    if_index: InterfaceIndex,
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

    // FIXME(mvachhar) Insert RSS setsockopt here

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
        },
    ))
}

pub struct Worker {
    id: WorkerId,
    total_workers: usize,
    setup_pipeline: Arc<dyn Send + Sync + Fn() -> DynPipeline<TestBuffer>>,
}

impl Worker {
    pub fn new(
        id: WorkerId,
        total_workers: usize,
        setup_pipeline: &Arc<dyn Send + Sync + Fn() -> DynPipeline<TestBuffer>>,
    ) -> Self {
        Worker {
            id,
            total_workers,
            setup_pipeline: setup_pipeline.clone(),
        }
    }

    pub fn start(
        &mut self,
        thread_builder: thread::Builder,
        interfaces: &[Kif],
    ) -> Result<thread::JoinHandle<Result<(), io::Error>>, io::Error> {
        let id = self.id;
        let total_workers = self.total_workers;
        let setup = self.setup_pipeline.clone();
        let interfaces = interfaces.iter().map(Kif::clone).collect::<Vec<_>>();

        let handle_res = thread_builder.spawn(move || {
            info!(worker = id, "Worker started");

            run_in_local_tokio_runtime(async || {
                let (readers, if_table) =
                    match build_interface_table(id, total_workers, interfaces.as_slice()) {
                        Ok(table) => table,
                        Err(e) => {
                            error!(worker = id, "Error building interface table: {}", e);
                            return Err(e);
                        }
                    };

                let setup = setup.clone();
                let if_table = if_table.clone();

                let mut reader_handles = tokio::task::JoinSet::new();

                for intf in readers {
                    let setup = setup.clone();
                    let if_table = if_table.clone();
                    reader_handles.spawn(async move {
                        let intf = intf;
                        // Pipeline isn't Send because it isn't safe to Send, but we know that we are
                        // using it inside of a tokio current_thread runtime which will not send it
                        // to another thread as long as we don't use it in a spawn_blocking, which we don't, so force it to be send here.
                        #[allow(unsafe_code)]
                        let mut pipeline = unsafe { force_send(setup()) };
                        loop {
                            tracing::debug!(worker = id, "awaiting packets");

                            let packets_vec = match read_packets_from_interface(id, &intf).await {
                                Ok(packets) => packets,
                                Err(e) => {
                                    error!(
                                        worker = id,
                                        rx_intf_name = intf.if_name,
                                        "Error reading packets from interface: {e}"
                                    );
                                    vec![]
                                }
                            };

                            debug!(
                                worker = id,
                                rx_intf_name = intf.if_name,
                                "Read {} packets from interface {}",
                                packets_vec.len(),
                                intf.if_name
                            );

                            // Try to receive everything else that is in the buffer
                            let packets = packets_vec.into_iter();

                            let mut count = 0;
                            let out_pkts = pipeline
                                .process(packets.map(|pkt| *pkt))
                                .collect::<Vec<_>>();
                            for out_pkt in out_pkts {
                                trace!(
                                    worker = id,
                                    rx_intf_name = intf.if_name,
                                    "Tx packet after pipeline for interface {}",
                                    intf.if_name
                                );
                                tx_packet(id, &intf.if_name, &if_table, out_pkt).await;
                                count += 1;
                            }

                            tracing::debug!(
                                worker = id,
                                rx_intf_name = intf.if_name,
                                "processed {count} packets from interface {}",
                                intf.if_name
                            );
                        }
                    });
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
            })?;
            info!(worker = id, "Worker exited");
            Ok::<(), io::Error>(())
        })?;
        Ok(handle_res)
    }
}

fn build_interface_table(
    id: WorkerId,
    total_workers: usize,
    interfaces: &[Kif],
) -> Result<(WorkerInterfaceReaders, Arc<WorkerIfTable>), io::Error> {
    let mut if_table = HashMap::new();
    let mut readers = Vec::new();
    for kif in interfaces {
        let (writer, reader) = create_worker_interface(id, total_workers, &kif.name, kif.ifindex)?;
        if_table.insert(kif.ifindex, Arc::new(Mutex::new(writer)));
        readers.push(reader);
    }
    Ok((readers, Arc::new(if_table)))
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
) -> Result<(), nix::Error> {
    let mut raw = [0u8; 9100];
    let mut ret = Ok(());
    pkts.clear();
    while pkts.len() < max_to_read {
        match nix::sys::socket::recv(
            if_fd,
            &mut raw,
            nix::sys::socket::MsgFlags::MSG_DONTWAIT | nix::sys::socket::MsgFlags::MSG_TRUNC,
        ) {
            Ok(0) => break, // no more
            Ok(bytes) => {
                trace!("Received packet with {} bytes on {}", bytes, if_name);
                // build TestBuffer and parse
                if raw.len() < bytes {
                    error!(
                        worker = id,
                        rx_intf_name = if_name,
                        "Received packet with {bytes} bytes on {if_name} but raw buffer is only {} bytes, trunctating",
                        raw.len()
                    );
                }
                let buf = TestBuffer::from_raw_data(&raw[..std::cmp::min(raw.len(), bytes)]);
                match Packet::new(buf) {
                    Ok(mut incoming) => {
                        incoming.get_meta_mut().iif = Some(if_index);
                        pkts.push(Box::new(incoming));
                    }
                    Err(e) => {
                        // Parsing errors happen; avoid logspam for loopback
                        if if_name != "lo" {
                            error!(
                                worker = id,
                                rx_intf_name = if_name,
                                "Failed to parse packet on '{}': {e}",
                                if_name
                            );
                        }
                    }
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
    if !guard.ready().is_readable() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::WouldBlock,
            "Would block",
        ));
    }
    let mut pkts = Vec::with_capacity(128);
    match guard.try_io(|fd| {
        packet_recv(
            id,
            intf.if_name.as_str(),
            fd.as_raw_fd(),
            intf.if_index,
            128,
            &mut pkts,
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

    trace!(
        worker = id,
        rx_intf_name = intf.if_name,
        "Received {} packets from interface {}, index: {}",
        intf.if_name,
        intf.if_index,
        pkts.len()
    );
    Ok(pkts)
}

async fn tx_packet(
    id: WorkerId,
    rx_if_name: &str,
    if_table: &WorkerIfTable,
    pkt: Packet<TestBuffer>,
) {
    let oif_id_opt = pkt.get_meta().oif;
    if let Some(oif_id) = oif_id_opt {
        if let Some(outgoing_unlocked) = if_table.get(&oif_id) {
            trace!(
                worker = id,
                rx_intf_name = rx_if_name,
                "Locking interface index {} for transmit from rx interface {}",
                oif_id,
                rx_if_name
            );
            let mut outgoing = outgoing_unlocked.lock().await;
            match pkt.serialize() {
                Ok(out) => {
                    let len = out.as_ref().len();
                    trace!(
                        worker = id,
                        rx_intf_name = rx_if_name,
                        "TXing {len} bytes on interface {}",
                        &outgoing.if_name
                    );
                    if let Err(e) = outgoing.sock.write(out.as_ref()).await {
                        warn!(
                            worker = id,
                            rx_intf_name = rx_if_name,
                            "TX failed for pkt ({len} octets) on '{}': {e}",
                            &outgoing.if_name
                        );
                    } else {
                        trace!(
                            worker = id,
                            rx_intf_name = rx_if_name,
                            "TX {len} bytes on interface {}",
                            &outgoing.if_name
                        );
                    }
                    trace!(
                        worker = id,
                        rx_intf_name = rx_if_name,
                        "Finished TXing {len} bytes on interface {}",
                        &outgoing.if_name
                    );
                }
                Err(e) => error!(
                    worker = id,
                    rx_intf_name = rx_if_name,
                    "Serialize failed: {e:?}"
                ),
            }
        } else {
            warn!(
                worker = id,
                rx_intf_name = rx_if_name,
                "TX drop: unknown oif {}",
                oif_id
            );
        }
    } else {
        // No oif set -> inspect DoneReason via enforce()
        match pkt.enforce() {
            Some(_keep) => {
                // Packet is not marked for drop by the pipeline (Delivered/None/keep=true),
                // but we still can't TX without an oif; drop here.
                error!(
                    worker = id,
                    rx_intf_name = rx_if_name,
                    "No oif in packet meta; enforce() => keep/Delivered; dropping here"
                );
            }
            None => {
                // Pipeline explicitly marked it to be dropped
                debug!(
                    worker = id,
                    rx_intf_name = rx_if_name,
                    "Packet marked for drop by pipeline (enforce() => None)"
                );
            }
        }
    }
}
