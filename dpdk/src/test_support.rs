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
pub(crate) fn packet_pool(size: u32) -> crate::mem::Pool<'static> {
    use crate::mem::{PoolConfig, PoolParams};
    use crate::socket::SocketId;
    use concurrency::process_global::atomic::{AtomicU32, Ordering};

    static NEXT_POOL: AtomicU32 = AtomicU32::new(0);
    let shared = start_eal();
    let name = format!("batch_{}", NEXT_POOL.fetch_add(1, Ordering::Relaxed));
    let params = PoolParams {
        size,
        cache_size: 0,
        private_size: 0,
        data_size: 2048,
        socket_id: SocketId::ANY,
    };
    shared
        .mem()
        .new_pkt_pool(PoolConfig::new(name, params).unwrap())
        .unwrap()
}

#[cfg(test)]
pub(crate) fn available(pool: &crate::mem::Pool<'_>) -> usize {
    // SAFETY: the pool is live and its per-core cache is disabled.
    unsafe { dpdk_sys::rte_mempool_avail_count(pool.as_mut_ptr()) as usize }
}

/// Serializes ring-port creation and teardown, which DPDK does not make thread-safe.
#[cfg(test)]
#[allow(
    clippy::disallowed_types,
    reason = "the DPDK port registry is process-wide"
)]
pub(crate) static PORT_LOCK: concurrency::process_global::Mutex<()> =
    concurrency::process_global::Mutex::new(());

// The ring PMD is used only by tests. Signature from rte_eth_ring.h.
#[cfg(test)]
#[link(name = "rte_net_ring", kind = "static")]
unsafe extern "C" {
    fn rte_eth_from_ring(ring: *mut dpdk_sys::rte_ring) -> core::ffi::c_int;
}

/// An unconfigured ring-PMD port, removed again on drop.
#[cfg(test)]
#[allow(
    clippy::disallowed_types,
    reason = "the DPDK port registry is process-wide"
)]
pub(crate) struct RingPort {
    pub(crate) index: crate::dev::DevIndex,
    ring: core::ptr::NonNull<dpdk_sys::rte_ring>,
    name: std::ffi::CString,
    _guard: concurrency::process_global::MutexGuard<'static, ()>,
}

#[cfg(test)]
#[allow(
    clippy::disallowed_types,
    reason = "the DPDK port registry is process-wide"
)]
impl RingPort {
    pub(crate) fn new() -> RingPort {
        let _eal = start_eal();
        #[allow(clippy::unwrap_used)]
        let guard = PORT_LOCK.lock().unwrap();
        // SAFETY: the EAL is initialized; the ring outlives the port using it.
        let ring = core::ptr::NonNull::new(unsafe {
            dpdk_sys::rte_ring_create(c"claim_ring".as_ptr(), 8, -1, 0)
        })
        .expect("create ring");
        // SAFETY: `ring` is a live ring.
        let port = unsafe { rte_eth_from_ring(ring.as_ptr()) };
        assert!(port >= 0, "create ring port: {port}");
        let index = crate::dev::DevIndex(u16::try_from(port).expect("port id fits u16"));
        let mut name = [0; dpdk_sys::RTE_ETH_NAME_MAX_LEN as usize];
        // SAFETY: `name` is large enough for any port name.
        assert_eq!(
            unsafe { dpdk_sys::rte_eth_dev_get_name_by_port(index.0, name.as_mut_ptr()) },
            0
        );
        RingPort {
            index,
            ring,
            // SAFETY: the successful lookup wrote a NUL-terminated name.
            name: unsafe { core::ffi::CStr::from_ptr(name.as_ptr()) }.to_owned(),
            _guard: guard,
        }
    }
}

#[cfg(test)]
impl Drop for RingPort {
    fn drop(&mut self) {
        // SAFETY: the port was never started; remove it before freeing its ring.
        unsafe {
            assert_eq!(dpdk_sys::rte_vdev_uninit(self.name.as_ptr()), 0);
            dpdk_sys::rte_ring_free(self.ring.as_ptr());
        }
    }
}
