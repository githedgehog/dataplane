// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use concurrency::sync::OnceLock;

use crate::eal::{Eal, EalShared};

/// The shared projection of the process-wide test EAL.
///
/// The projection rather than the [`Eal`] itself: `Eal` is `!Send + !Sync` (it stays on the
/// thread that initialised it), and a `static` requires both. The owning handle is leaked below,
/// which is what makes the `'static` projection sound.
static EAL: OnceLock<EalShared<'static>> = OnceLock::new();

/// Initialise the process-wide test EAL, once, and return a shared handle to it.
///
/// Every `#[with_eal]` test funnels through here. Note this deliberately never tears the EAL
/// down: the owning [`Eal`] is leaked, so neither the mempool registry nor `rte_eal_cleanup` runs
/// at the end of a test binary. That was already true when this held the `Eal` in a `OnceLock`
/// (which never drops its contents either) and is fine for a process about to exit -- but it does
/// mean the teardown path is not exercised by unit tests.
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
        data_size: 2048,
        socket_id: SocketId::ANY,
    };
    Pool::new_pkt_pool(PoolConfig::new(name, params).unwrap()).unwrap()
}

#[cfg(test)]
pub(crate) fn available(pool: &crate::mem::Pool) -> usize {
    // SAFETY: the pool is live and its per-core cache is disabled.
    unsafe { dpdk_sys::rte_mempool_avail_count(pool.as_mut_ptr()) as usize }
}
