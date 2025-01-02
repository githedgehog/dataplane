use std::num::NonZero;
use std::time::Duration;
use dpdk::eal::Eal;
use dpdk::lcore::{LCoreId, RteThreadId};
use crate::{message, Registration, WorkerMessage};
use crate::message::{Message, Tag};

#[derive(Debug)]
pub(crate) struct WorkerHandle<'eal> {
    eal: &'eal Eal,
    id: LCoreId,
    rte_thread_id: RteThreadId,
    system_thread_id: std::thread::ThreadId,
    manager_rx: crossbeam::channel::Receiver<WorkerMessage>,
    worker_tx: crossbeam::channel::Sender<WorkerMessage>,
}



impl WorkerHandle<'_> {
    const CHANNEL_BOUND: usize = 512;

    #[tracing::instrument(level = "info")]
    fn new(eal: &Eal, worker_tx: crossbeam::channel::Sender<WorkerMessage>) -> WorkerHandle<'_> {
        let (tx, rx) = crossbeam::channel::bounded(WorkerHandle::CHANNEL_BOUND);
        let sender = LCoreId::current();
        let system_thread_id = std::thread::current().id();
        let message = Message::<Registration> {
            tag: Tag {
                id: message::Id(NonZero::new(1).unwrap_or_else(|| unreachable!())),
                sender,
                regarding: None,
            },
            data: Registration {
                system_thread_id,
                tx,
            },
        };
        worker_tx
            .send_timeout(WorkerMessage::Registration(message), Duration::from_secs(2))
            .unwrap_or_else(|e| {
                Eal::fatal_error(format!("failed to send worker registration: {e}"))
            });
        WorkerHandle {
            eal,
            id: sender,
            manager_rx: rx,
            rte_thread_id: RteThreadId::current(),
            system_thread_id,
            worker_tx,
        }
    }
}
