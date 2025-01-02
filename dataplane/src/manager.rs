use crate::worker::WorkerHandle;

#[derive(Debug)]
pub(crate) struct Manager<'eal> {
    eal: &'eal dpdk::eal::Eal,
    workers: Vec<WorkerHandle<'eal>>,
    // agents: Vec<AgentHandle<'eal>>,
}


