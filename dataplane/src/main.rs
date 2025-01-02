mod message;
mod manager;
mod worker;

use crate::message::{Message, Tag};
use dpdk::eal;
use dpdk::eal::Eal;
use dpdk::lcore::{LCoreId, LCoreIndex, RteThreadId, WorkerThread};
use dpdk::mem::RteAllocator;
use std::ffi::{c_int, c_void};
use std::num::NonZero;
use std::time::Duration;
use tracing::info;

#[global_allocator]
static GLOBAL_ALLOCATOR: RteAllocator = RteAllocator;

fn init(args: impl IntoIterator<Item = impl AsRef<str>>) -> Eal {
    let rte = eal::init(args);
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_target(false)
        .with_thread_ids(true)
        .with_line_number(true)
        .with_thread_names(true)
        .init();
    rte
}

fn main() {
    let eal = init([
        "--main-lcore",
        "2",
        "--lcores",
        "2-4",
        "--in-memory",
        "--allow",
        "0000:c1:00.0,dv_flow_en=1",
        "--huge-worker-stack=8192",
        "--socket-mem=16384,0,0,0",
        "--no-telemetry",
    ]);
    assert!(RteAllocator::is_initialized());
    LCoreId::list().for_each(|lcore_id| {
        WorkerThread::launch_on(lcore_id, move || {
            info!("Starting RTE Worker");
        })
    })
}

struct Registration {
    system_thread_id: std::thread::ThreadId,
    tx: crossbeam::channel::Sender<WorkerMessage>,
}

enum ManagerMessage {}

enum WorkerMessage {
    Registration(Message<Registration>),
}

struct ManagerQueue {
    manager_rx: crossbeam::channel::Receiver<WorkerMessage>,
    manager_tx: crossbeam::channel::Sender<WorkerMessage>,
}

