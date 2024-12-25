use crate::eal::{Eal, EalErrno};
use std::ffi::{c_int, c_uint, c_void, CStr, CString};
use std::ptr::null_mut;
use tracing::info;
use dpdk_sys::{rte_thread_attr_init, rte_thread_attr_t, rte_thread_create, rte_thread_join, rte_thread_t};

#[repr(u32)]
pub enum LCorePriority {
    Normal = dpdk_sys::rte_thread_priority::RTE_THREAD_PRIORITY_NORMAL as c_uint,
    RealTime = dpdk_sys::rte_thread_priority::RTE_THREAD_PRIORITY_REALTIME_CRITICAL as c_uint,
}

struct LCoreAttributes {
    priority: LCorePriority,
    name: String,
    stack_size: usize,
}

pub struct ServiceThread<'scope> {
    thread_id: dpdk_sys::rte_thread_t,
    priority: LCorePriority,
    handle: std::thread::ScopedJoinHandle<'scope, ()>,
}

// TODO: take stack size as an EAL argument instead of hard coding it
const STACK_SIZE: usize = 8 * 1024 * 1024;

impl ServiceThread<'_> {
    #[cold]
    #[allow(clippy::expect_used)]
    pub fn new<'scope>(
        scope: &'scope std::thread::Scope<'scope, '_>,
        name: impl AsRef<str>,
        run: impl FnOnce() + 'scope + Send,
    ) -> ServiceThread<'scope> {
        let (send, recv) = std::sync::mpsc::sync_channel(1);
        let handle = std::thread::Builder::new()
            .name(name.as_ref().to_string())
            .stack_size(STACK_SIZE)
            .spawn_scoped(scope, move || {
                info!("Initializing RTE Lcore");
                let ret = unsafe { dpdk_sys::rte_thread_register() };
                if ret != 0 {
                    let errno = unsafe { dpdk_sys::wrte_errno() };
                    let msg = format!("rte thread exited with code {ret}, errno: {errno}");
                    Eal::fatal_error(msg)
                }
                let thread_id = unsafe { dpdk_sys::rte_thread_self() };
                send.send(thread_id).expect("could not send thread id");
                run();
                unsafe { dpdk_sys::rte_thread_unregister() };
            })
            .expect("could not create EalThread");
        let thread_id = recv.recv().expect("could not receive thread id");
        ServiceThread {
            thread_id,
            priority: LCorePriority::RealTime,
            handle,
        }
    }
    
    pub fn new_eal(
        run: extern "C" fn(*mut c_void) -> u32,
        arg: *mut c_void,
    ) {
        let mut thread_id = rte_thread_t::default();
        let mut attr = rte_thread_attr_t {
            priority: LCorePriority::Normal as u32,
        };
        let mut val: u32 = 0;
        unsafe {
            EalErrno::check(rte_thread_attr_init(&mut attr));
            EalErrno::check(rte_thread_create(&mut thread_id, &attr, Some(run), arg));
            rte_thread_join(thread_id, &mut val);
        }
    }

    #[allow(clippy::expect_used)]
    fn join(self) {
        self.handle.join().expect("failed to join LCore");
    }
}



struct LCoreParams {
    priority: LCorePriority,
    name: String,
    thunk: extern "C" fn(*mut c_void) -> u32,
}

trait LCoreParameters {
    fn priority(&self) -> &LCorePriority;
    fn name(&self) -> &String;
}

struct LCore {
    params: LCoreParams,
    id: LcoreId,
}

impl LCoreParameters for LCoreParams {
    fn priority(&self) -> &LCorePriority {
        &self.priority
    }

    fn name(&self) -> &String {
        &self.name
    }
}

impl LCoreParameters for LCore {
    fn priority(&self) -> &LCorePriority {
        &self.params.priority
    }

    fn name(&self) -> &String {
        &self.params.name
    }
}

#[derive(Debug, Copy, Clone)]
pub struct LcoreId(dpdk_sys::rte_thread_t);

impl PartialEq for LcoreId {
    fn eq(&self, other: &Self) -> bool {
        unsafe { dpdk_sys::rte_thread_equal(self.0, other.0) != 0 }
    }
}

impl Eq for LcoreId {}

trait AllocatedLCore {
    fn id(&self) -> LcoreId;
}

impl LCore {
    fn allocate(params: LCoreParams) -> LCore {
        let mut thread = dpdk_sys::rte_thread_t::default();
        let mut attr = dpdk_sys::rte_thread_attr_t {
            priority: LCorePriority::RealTime as u32,
        };
        EalErrno::check(unsafe { dpdk_sys::rte_thread_attr_init(&mut attr) });
        EalErrno::check(unsafe {
            dpdk_sys::rte_thread_create(&mut thread, &attr, Some(params.thunk), null_mut())
        });

        #[allow(clippy::panic)]
        if !params.name.is_ascii() {
            panic!("invalid thread name: not ascii");
        }
        #[allow(clippy::expect_used)]
        unsafe {
            dpdk_sys::rte_thread_set_name(
                thread,
                CString::new(params.name.as_bytes().to_vec())
                    .expect("could not allocate thread name")
                    .as_ptr(),
            )
        };
        EalErrno::check(unsafe {
            dpdk_sys::rte_thread_set_priority(thread, LCorePriority::RealTime as c_uint)
        });
        LCore {
            params,
            id: LcoreId(thread),
        }
    }
}

impl AllocatedLCore for LCore {
    fn id(&self) -> LcoreId {
        self.id
    }
}