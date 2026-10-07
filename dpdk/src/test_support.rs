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
    _guard: std::rc::Rc<concurrency::process_global::MutexGuard<'static, ()>>,
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
        Self::with_guard(std::rc::Rc::new(guard))
    }

    pub(crate) fn another(&self) -> RingPort {
        Self::with_guard(self._guard.clone())
    }

    fn with_guard(
        guard: std::rc::Rc<concurrency::process_global::MutexGuard<'static, ()>>,
    ) -> RingPort {
        use concurrency::process_global::atomic::{AtomicU32, Ordering};

        static NEXT_RING: AtomicU32 = AtomicU32::new(0);
        let name = std::ffi::CString::new(format!(
            "claim_ring_{}",
            NEXT_RING.fetch_add(1, Ordering::Relaxed)
        ))
        .unwrap();
        // SAFETY: the EAL is initialized; the ring outlives the port using it.
        let ring =
            core::ptr::NonNull::new(unsafe { dpdk_sys::rte_ring_create(name.as_ptr(), 8, -1, 0) })
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
