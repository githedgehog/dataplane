// use tokio::sync::mpsc::Receiver;
use crossbeam::channel::Receiver;
use priority_queue::PriorityQueue;
use std::marker::PhantomData;

#[repr(transparent)]
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct TypedId<T> {
    inner: u64,
    _marker: PhantomData<T>,
}

pub type Id<T> = TypedId<*const T>;

impl<T> Id<T> {
    pub fn new(inner: u64) -> Self {
        Self {
            inner,
            _marker: PhantomData,
        }
    }

    pub fn get(&self) -> u64 {
        self.inner
    }
}

pub enum Task {
    // PacketIn(Id<Vpc>),
    PacketOut,
    Flows,
}

pub struct Task2 {
    queue: PriorityQueue<WorkQueue, f64>,
}

pub struct WorkQueue {
    incoming: Receiver<Task>,
    buffer: Vec<Task>,
    scheduled: Vec<Task>,
}
