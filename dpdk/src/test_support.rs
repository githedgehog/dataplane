// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use concurrency::sync::OnceLock;

use crate::eal::{Eal, EalShared};

/// Shared access to the process-wide test EAL, which is deliberately never dropped.
static EAL: OnceLock<EalShared<'static>> = OnceLock::new();

/// Initialize the process-wide test EAL and return a shared handle.
/// Teardown is tested separately because this fixture keeps the EAL alive until exit.
#[must_use]
pub fn start_eal() -> EalShared<'static> {
    *EAL.get_or_init(|| {
        let core_pinning = crate::eal::main_lcore_arg();
        let eal_id = format!("{}", id::Id::<Eal>::new());
        let args: &[&str] = &[
            "--no-huge",
            "--no-pci",
            "--in-memory",
            "--no-telemetry",
            "--no-shconf",
            "--no-hpet",
            "--iova-mode=va",
            "--file-prefix",
            &eal_id,
            "--lcores",
            &core_pinning,
        ];
        // Leaked on purpose: `Eal` is `!Send`, so it has to stay on whichever thread reached
        // here first, and the leak is what lets the projection be `'static`.
        let eal: &'static Eal = Box::leak(Box::new(crate::eal::init(args.iter().copied())));
        eal.shared()
    })
}

#[cfg(test)]
pub(crate) fn packet_pool(size: u32) -> crate::mem::Pool {
    packet_pool_with_data_size(size, 2048)
}

#[cfg(test)]
pub(crate) fn packet_pool_with_data_size(size: u32, data_size: u16) -> crate::mem::Pool {
    use crate::mem::{Pool, PoolConfig, PoolParams};
    use crate::socket::SocketId;
    use concurrency::process_global::atomic::{AtomicU32, Ordering};

    static NEXT_POOL: AtomicU32 = AtomicU32::new(0);
    let _eal = start_eal();
    let name = format!("batch_{}", NEXT_POOL.fetch_add(1, Ordering::Relaxed));
    let params = PoolParams {
        size,
        cache_size: 0,
        private_size: 0,
        data_size,
        socket_id: SocketId::ANY,
    };
    Pool::new_pkt_pool(PoolConfig::new(name, params).unwrap()).unwrap()
}

#[cfg(test)]
pub(crate) fn available(pool: &crate::mem::Pool) -> usize {
    // SAFETY: the pool is live and its per-core cache is disabled.
    unsafe { dpdk_sys::rte_mempool_avail_count(pool.inner().as_mut_ptr()) as usize }
}
