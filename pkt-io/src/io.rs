// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Local Pkt IO controller

use ahash::RandomState;
use futures::StreamExt;
use futures::stream::FuturesUnordered;
use tokio::join;
use tokio::spawn;
use tokio::sync::Mutex;
use tokio::sync::mpsc::{Receiver, Sender, channel};
use tokio::task;

use crate::PktQueue;
use interface_manager::interface::TapDevice;
use net::buffer::PacketBufferMut;
use net::buffer::PacketBufferPool;
use net::interface::{InterfaceIndex, InterfaceName};
use net::packet::Packet;

use std::collections::HashMap;
use std::sync::Arc;

use tracectl::trace_target;
#[allow(unused)]
use tracing::{debug, error, info, trace, warn};

const PKT_IO_MGR: &str = "pkt-io-manager";
trace_target!(PKT_IO_MGR, LevelFilter::INFO, &[]);

use crate::ctl::{IoManagerCtl, IoManagerMsg};

#[derive(Debug)]

struct Tap {
    tapid: InterfaceIndex,
    device: TapDevice,
    rx_task: Mutex<Option<task::JoinHandle<()>>>,
}

impl Tap {
    const fn new(tapid: InterfaceIndex, device: TapDevice) -> Self {
        Self {
            tapid,
            device,
            rx_task: Mutex::const_new(None),
        }
    }
    async fn disable_rx(&self) {
        let tapname = self.device.name();
        let mut g = self.rx_task.lock().await;
        if let Some(handle) = g.take() {
            debug!("Stopping rx from tap {tapname}");
            handle.abort();
        }
    }
}

#[derive(Debug)]
#[allow(unused)]
struct TapTable(HashMap<InterfaceIndex, Arc<Tap>, RandomState>);
impl TapTable {
    fn new() -> Self {
        Self(HashMap::with_hasher(RandomState::with_seed(0)))
    }
    async fn add_tap(&mut self, spec: &InterfaceName) -> Result<(), std::io::Error> {
        let device = TapDevice::open(spec).await?;
        let tap = Tap::new(device.ifindex(), device);
        self.0.insert(tap.tapid, Arc::new(tap));
        Ok(())
    }
    async fn del_tap(&mut self, tapid: InterfaceIndex) {
        debug!("Deleting tap entry for tap with id {tapid}...");
        if let Some(tap) = self.0.remove(&tapid) {
            let tapname = tap.device.name();
            debug!("Tap for interface {tapid} found: {tapname}");
            tap.disable_rx().await;
            debug!("Deleted tap entry for device {tapname}");
        }
    }
    fn get_tap(&self, id: InterfaceIndex) -> Option<&TapDevice> {
        self.0.get(&id).map(|m| &m.device)
    }
    fn values(&self) -> impl Iterator<Item = &Arc<Tap>> {
        self.0.values()
    }
    fn contains(&self, tapname: &InterfaceName) -> bool {
        self.0.values().any(|tap| tap.device.name() == tapname)
    }
}
impl Clone for TapTable {
    fn clone(&self) -> Self {
        let mut new = TapTable::new();
        for m in self.values() {
            new.0.insert(m.tapid, Arc::clone(m));
        }
        new
    }
}

#[derive(Debug)]
enum TapOp {
    Add(Arc<Tap>),
    Del(InterfaceIndex),
}

struct IoManager<Buf: PacketBufferMut, P: PacketBufferPool> {
    puntq: PktQueue<Buf>,
    injectq: PktQueue<Buf>,
    pool: Arc<P>,
    receiver: Receiver<IoManagerMsg>,
}
impl<Buf: PacketBufferMut, P: PacketBufferPool<Buffer = Buf> + 'static> IoManager<Buf, P> {
    fn new(
        puntq: PktQueue<Buf>,
        injectq: PktQueue<Buf>,
        receiver: Receiver<IoManagerMsg>,
        pool: P,
    ) -> Self {
        Self {
            puntq,
            injectq,
            pool: Arc::new(pool),
            receiver,
        }
    }

    // handle incoming packets: fetch packets punted by pipeline and write them to the corresponding tap
    async fn punt_packets(puntq: PktQueue<Buf>, taptable: TapTable) {
        let taps = taptable
            .values()
            .map(|m| format!("{}", m.device.name()))
            .collect::<Vec<_>>()
            .as_slice()
            .join(" ");

        debug!("Started task to punt packets. Taps to service: {taps}");
        drop(taps);

        // allow concurrent packet writes on distinct taps, because we don't want writing on a
        // tap to block writes to another one. With this, multiple writes to the same tap could
        // happen. In principle, this should not be an issue since writes should conclude
        // in a single io operation with tap devices.
        let mut multi_write = FuturesUnordered::new();

        loop {
            while let Some(packet) = puntq.pop() {
                let Some(ifindex) = packet.get_meta().iif else {
                    warn!("Packet has no incoming interface annotation. Dropping it...");
                    continue;
                };
                trace!("Rx punted packet. iif={ifindex}:\n{packet}");

                // lookup tap device from the id of the interface it was received
                let Some(device) = taptable.get_tap(ifindex) else {
                    warn!("Could not find tap with ifindex {ifindex}. Dropping packet...");
                    continue;
                };

                // ideally, here we would not need to call serialize again but some
                // method that would extract the underlying buffer from the packet.
                // This is not possible at the moment since we'd get wrong offsets (headroom)
                let Ok(buf) = packet.serialize() else {
                    error!("Failed to (re)serialize local incoming packet");
                    continue;
                };

                multi_write.push(device.write(buf));

                // One write at a time
                //match device.write(buf).await {
                //    Err(e) => error!("Failed to write buffer to tap {}: {e}", device.name()),
                //    Ok(()) => debug!("Wrote packet from if {ifindex} to tap {}!", device.name()),
                //}
            }

            // write packets concurrently over distinct taps
            while let Some(result) = multi_write.next().await {
                match result {
                    Err(e) => error!("Failed to write buffer to tap: {e}"),
                    Ok(()) => trace!("Wrote packet to tap!"),
                }
            }

            if puntq.is_empty() {
                puntq.notified().await;
                tokio::task::yield_now().await;
            }
        }
    }

    // continuously read from the given tap and push to injection queue.
    async fn tap_out_loop(pool: Arc<P>, injectq: PktQueue<Buf>, map: Arc<Tap>) {
        let tapid = map.tapid;
        let tapname = map.device.name();
        let device = &map.device;

        debug!("Running Rx task for tap '{tapname}' ({tapid})");
        loop {
            let Ok(mut buffer) = pool.new_buffer() else {
                warn!("Packet buffer allocation failed!");
                continue;
            };
            match device.read(&mut buffer).await {
                Ok(size) => match Packet::new(buffer) {
                    Err(e) => error!("Failed to build packet from buffer: {e}"),
                    Ok(mut packet) => {
                        packet.get_meta_mut().oif = Some(tapid);
                        packet.get_meta_mut().set_sourced(true);
                        trace!("Read {size} octets from tap {tapname}. Packet is:\n{packet}");
                        if let Err(_drop) = injectq.push(Box::new(packet)) {
                            warn!("Could not inject packet (queue len:{})", injectq.len());
                        }
                    }
                },
                Err(e) => {
                    error!("Failure reading packet from tap {tapname}: {e}");
                    break;
                }
            }
        }
    }

    async fn punt_pkt_control(puntq: PktQueue<Buf>, mut receiver: Receiver<TapOp>) {
        let mut taptable = TapTable::new();
        let mut tx = spawn(async {});

        debug!("Punt packet control started ...");
        while let Some(action) = receiver.recv().await {
            match action {
                TapOp::Add(m) => taptable.0.insert(m.tapid, m),
                TapOp::Del(id) => taptable.0.remove(&id),
            };
            tx.abort();
            tx = spawn(Self::punt_packets(puntq.clone(), taptable.clone()));
        }
        warn!("Channel closed for packet punt control");
    }

    fn start_punt_pkt_control(puntq: PktQueue<Buf>) -> (task::JoinHandle<()>, Sender<TapOp>) {
        let (sender, receiver) = channel::<TapOp>(100);
        let handle = tokio::spawn(Self::punt_pkt_control(puntq.clone(), receiver));
        (handle, sender)
    }

    async fn run(self) {
        info!("Running IO-manager");

        let puntq = self.puntq;
        let injectq = self.injectq;
        let pool = self.pool;
        let mut receiver = self.receiver;

        let mut taptable = TapTable::new();

        // spawn packet punt controller. A single task is used to punt packets to all taps from a queue
        let (puntctl_handle, puntctl) = Self::start_punt_pkt_control(puntq.clone());

        let h = tokio::spawn(async move {
            while let Some(msg) = receiver.recv().await {
                match msg {
                    IoManagerMsg::Stop => {
                        info!("Got request to stop...");
                        puntctl_handle.abort();
                        for m in taptable.values() {
                            let mut g = m.rx_task.lock().await;
                            if let Some(task) = g.take() {
                                task.abort();
                            }
                        }
                        return;
                    }
                    IoManagerMsg::Enable(spec) => {
                        info!("Received request to activate interfaces:\n{spec}");

                        // add tap entries that we don't have
                        for spec in spec.iter() {
                            if !taptable.contains(spec) {
                                if let Err(e) = taptable.add_tap(spec).await {
                                    error!("Fatal, could not open tap {}: {e}", spec);
                                }
                            }
                        }
                        // remove tap entries we no longer need, cancelling the corresponding rx/tx tasks.
                        // Taps will continue to exist but will be operationally down.
                        let to_remove: Vec<InterfaceIndex> = taptable
                            .values()
                            .filter(|m| !spec.contains(m.device.name()))
                            .map(|m| m.tapid)
                            .collect();

                        for id in &to_remove {
                            taptable.del_tap(*id).await;
                            if let Err(e) = puntctl.send(TapOp::Del(*id)).await {
                                warn!("Failed to send del for tap {id}: {e}");
                            }
                        }

                        // start the required rx/tx tasks. The existing ones are left as is.
                        for m in taptable.values() {
                            let mut g = m.rx_task.lock().await;
                            if g.is_none() {
                                let tapname = m.device.name();

                                debug!("Spawning rx task for tap {tapname}");
                                let rx_task =
                                    Self::tap_out_loop(pool.clone(), injectq.clone(), m.clone());

                                *g = Some(spawn(rx_task));

                                match puntctl.send(TapOp::Add(m.clone())).await {
                                    Ok(()) => debug!("Asked controller to punt to {tapname}"),
                                    Err(e) => warn!("Failed to request punting to {tapname}: {e}"),
                                }
                            }
                        }
                    }
                }
            }
            warn!("IO manager control channel closed!");
        });
        let _ = join!(h);
        info!("IO manager loop stopped.");
    }
}

pub fn start_io<Buf: PacketBufferMut, P: PacketBufferPool<Buffer = Buf> + 'static>(
    puntq: PktQueue<Buf>,
    injectq: PktQueue<Buf>,
    pool: P,
) -> Result<(std::thread::JoinHandle<()>, IoManagerCtl), String> {
    info!("Starting pkt-io-manager");

    let (sender, receiver) = channel::<IoManagerMsg>(100);
    let handle = std::thread::Builder::new()
        .name("pkt-io-mgr".to_string())
        .spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_io()
                .enable_time()
                .build()
                .expect("Tokio runtime creation failed");

            let iom = IoManager::new(puntq, injectq, receiver, pool);
            rt.block_on(iom.run());
            info!("IO manager stopped!");
        })
        .map_err(|e| format!("Failed to start io manager: {e}"))?;

    let iom_ctl = IoManagerCtl::new(sender);
    Ok((handle, iom_ctl))
}

#[cfg(test)]
mod io_tests {
    use caps::Capability::CAP_NET_ADMIN;
    use interface_manager::interface::TapDevice;
    use net::buffer::{PacketBufferMut, TestBuffer, TestBufferPool};
    use net::interface::{InterfaceIndex, InterfaceName};
    use net::packet::Packet;
    use rtnetlink::LinkUnspec;
    use test_utils::with_caps;

    use crate::PktIo;
    use crate::{IoManagerCtl, PktQueue};

    use crate::io::start_io;
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::thread::{JoinHandle, sleep};

    use net::packet::test_utils::build_test_ipv4_packet;
    use tracing_test::traced_test;

    use rand::rng;
    use rand::seq::IteratorRandom;

    // this is not a test
    #[allow(unused)]
    async fn tap_read() {
        const TAPNAME: &str = "tapme";
        let tapname = InterfaceName::try_from(TAPNAME).unwrap();
        println!("Creating tap {tapname}...");
        let tap = TapDevice::open(&tapname).await.unwrap();
        loop {
            let mut buf = TestBuffer::new();
            match tap.read(&mut buf).await {
                Ok(len) => {
                    let packet = Packet::new(buf).unwrap();
                    println!("got pkt w/ len {}:\n{packet}", len.get());
                }
                Err(e) => println!("error: {e}"),
            }
        }
    }

    #[traced_test]
    #[tokio::test]
    #[fixin::wrap(with_caps([CAP_NET_ADMIN]))]
    async fn test_tap_reuse() {
        let tapname = InterfaceName::try_from("tap-test-2").unwrap();
        let tap1 = TapDevice::open(&tapname).await.unwrap();
        drop(tap1);
        let _tap2 = TapDevice::open(&tapname).await.unwrap();
    }

    // a thread that just pops packets from the injectq
    fn sink_thread<Buf: PacketBufferMut>(
        sink_queue: PktQueue<Buf>,
        run: Arc<AtomicBool>,
    ) -> JoinHandle<()> {
        let sink = std::thread::Builder::new()
            .name("pkt-sink".to_string())
            .spawn(move || {
                while run.load(Ordering::Relaxed) {
                    while let Some(_packet) = sink_queue.pop() {
                        //println!("Outgoing pkt:\n{packet}");
                    }
                    sleep(std::time::Duration::from_millis(500));
                }
            })
            .unwrap();
        sink
    }

    // a thread that punts packets after annotating them with the incoming interface
    fn punt_thread(
        puntq: PktQueue<TestBuffer>,
        run: Arc<AtomicBool>,
        pace: std::time::Duration,
    ) -> JoinHandle<()> {
        let punt = std::thread::Builder::new()
            .name("pkt-punt".to_string())
            .spawn(move || {
                // learn taps from kernel
                let taps = Arc::new(learn_taps());
                println!("Available taps:{taps:#?}");

                let mut rng = rng();
                while run.load(Ordering::Relaxed) {
                    sleep(pace);
                    let mut packet = build_test_ipv4_packet(64).unwrap();

                    if let Some((tapid, _tapname)) = taps.iter().choose(&mut rng) {
                        packet.get_meta_mut().iif = Some(InterfaceIndex::try_new(*tapid).unwrap());
                    }
                    if let Err(_dropped) = puntq.push(Box::new(packet)) {
                        println!("Queue is full!, dropping...");
                    } else {
                        puntq.notify();
                    }
                }
            })
            .unwrap();
        punt
    }

    fn learn_taps() -> HashMap<u32, String> {
        let mut taps = HashMap::new();
        let interfaces = netdev::get_interfaces();
        for interface in &interfaces {
            if interface.name.contains("tap") {
                taps.insert(interface.index, interface.name.clone());
            }
        }
        taps
    }

    fn register_tap(iom_ctl: &mut IoManagerCtl, tapname: &str) {
        let tapname = InterfaceName::try_from(tapname).unwrap();
        iom_ctl.add(tapname);
    }

    async fn bring_tap_up(ifindex: u32) {
        let (connection, handle, _) = rtnetlink::new_connection().unwrap();
        tokio::spawn(connection);
        handle
            .link()
            .set(LinkUnspec::new_with_index(ifindex).up().build())
            .execute()
            .await
            .expect("Failed to bring up tap");
        println!("Brought tap up");
    }

    async fn create_test_taps() {
        const NUM_TAPS: usize = 5;
        for n in 0..NUM_TAPS {
            let tapname = format!("tap{n}");
            let tapname = InterfaceName::try_from(tapname).unwrap();
            let tap = TapDevice::open(&tapname).await.unwrap();
            bring_tap_up(tap.ifindex().to_u32()).await;
        }
    }

    #[traced_test]
    #[tokio::test]
    #[fixin::wrap(with_caps([CAP_NET_ADMIN]))]
    async fn test_io_manager() {
        // create queues
        let puntq = PktIo::<TestBuffer>::create_queue(1000).unwrap();
        let injectq = PktIo::<TestBuffer>::create_queue(100).unwrap();

        // create test taps
        create_test_taps().await;

        // atomic to stop auxiliary threads
        let thread_run = Arc::new(AtomicBool::new(true));

        // a thread that just pops packets from the injectq
        let sink_handle = sink_thread(injectq.clone(), thread_run.clone());

        // a thread that punts packets to taps at a certain pace. This thread punts packets to all of the
        // taps, but some of those may not be handled by the IO manager
        let pace = std::time::Duration::from_millis(1000);
        let punt_handle = punt_thread(puntq.clone(), thread_run.clone(), pace);

        // start IO manager
        let (io_handle, mut iom_ctl) =
            start_io::<TestBuffer, TestBufferPool>(puntq.clone(), injectq.clone(), TestBufferPool)
                .unwrap();

        // here we control the IO manager
        let wait_time = std::time::Duration::from_secs(2);

        tokio::time::sleep(wait_time).await;
        println!("================ Registering tap0 =============================");
        register_tap(&mut iom_ctl, "tap0");
        iom_ctl.commit().await.unwrap();

        tokio::time::sleep(wait_time).await;
        println!("================ Registering tap1 & tap2 ======================");
        register_tap(&mut iom_ctl, "tap1");
        register_tap(&mut iom_ctl, "tap2");
        iom_ctl.commit().await.unwrap();

        tokio::time::sleep(wait_time).await;
        println!("================ Unregistering tap0 ==========================");
        iom_ctl.del(&InterfaceName::try_from("tap0").unwrap());
        iom_ctl.commit().await.unwrap();

        tokio::time::sleep(wait_time).await;
        println!("================ Flushing all ==========================");
        iom_ctl.clear();
        iom_ctl.commit().await.unwrap();

        tokio::time::sleep(wait_time).await;
        println!("================ Adding tap0 back ==========================");
        register_tap(&mut iom_ctl, "tap0");
        iom_ctl.commit().await.unwrap();

        tokio::time::sleep(wait_time).await;
        println!("================ Stop IO ==========================");
        iom_ctl.stop().await.unwrap();
        io_handle.join().unwrap();

        // stop punt thread and sink thread
        println!("================ Stop Test threads ==========================");
        tokio::time::sleep(wait_time).await;
        thread_run.store(false, Ordering::Relaxed);
        punt_handle.join().unwrap();
        sink_handle.join().unwrap();
    }
}
