// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Sleeping until a receive queue has a packet.
//!
//! [`RxWaiter`] lets an idle lcore block in `epoll_wait` on receive queues across ports and
//! drivers, plus other descriptors such as injection eventfds.
//! Devices must be configured with [`DevConfig::rx_interrupts`].
//!
//! To avoid missed wakeups, [arm](RxWaiter::arm), poll every queue again, then
//! [wait](RxWaiter::wait) only if all are empty: packets received before arming may not interrupt.
//! [Disarm](RxWaiter::disarm) on wake to avoid interrupt overhead while polling.
//!
//! [`DevConfig::rx_interrupts`]: crate::dev::DevConfig::rx_interrupts

use core::marker::PhantomData;
use core::ptr::NonNull;
use core::time::Duration;
use std::os::fd::{AsRawFd, BorrowedFd, OwnedFd, RawFd};

use errno::Errno;
use nix::libc::{EPOLL_CTL_ADD, EPOLL_CTL_DEL, EPOLLET, EPOLLIN};
use nix::sys::epoll::{Epoll, EpollCreateFlags};

use crate::dev::{DevIndex, DevInfo};
use crate::queue::rx::{RxQueue, RxQueueIndex};

/// The most events one wait reports; any beyond are reported by the next.
const MAX_EVENTS: usize = 32;

/// Drivers that arm or disarm another queue's receive interrupt than the one asked for.
///
/// The pinned ixgbe PF driver maps queue `q` to MSI-X vector `q + 1` under VFIO, but its
/// `rx_queue_intr_enable` and `rx_queue_intr_disable` set and clear the mask bit for vector `q`.
/// Disarming one queue masks another's interrupt, and arming a queue reports success while its own
/// vector can stay masked, so a waiter would sleep through its packets until the timeout. The port
/// lock below cannot correct that.
const ARMS_ANOTHER_QUEUE: &[&str] = &["net_ixgbe"];

/// Whether the driver passes the check for known queue-to-vector mapping bugs.
/// This does not establish interrupt support; configuration and registration can still fail.
/// [`RxWaiter::watch`] rejects drivers listed in `ARMS_ANOTHER_QUEUE`.
#[must_use]
pub fn arms_each_queue(info: &DevInfo<'_>) -> bool {
    arms_each_queue_of(info.driver_name())
}

fn arms_each_queue_of(driver: &str) -> bool {
    !ARMS_ANOTHER_QUEUE.contains(&driver)
}

/// One lock per port around arming and disarming its queues' interrupts.
///
/// Some drivers update a shared interrupt mask with read-modify-write operations.
/// Serialize those updates so workers cannot overwrite each other's queue masks.
#[allow(
    clippy::disallowed_types,
    reason = "guards calls into the EAL's process-wide ports, which outlive model executions"
)]
static PORT_LOCKS: [concurrency::process_global::Mutex<()>; DevIndex::MAX as usize] =
    [const { concurrency::process_global::Mutex::new(()) }; DevIndex::MAX as usize];

/// Which epoll set holds each queue interrupt's descriptor, by port and descriptor.
///
/// Queues sharing a vector also share a descriptor. The EAL stores one registration per vector:
/// adding it to a second set reports success without registering, and either set can remove it.
/// Reject cross-waiter sharing to preserve each waiter's registration and wakeups.
#[allow(
    clippy::disallowed_types,
    reason = "tracks registrations in the EAL's process-wide ports, which outlive model executions"
)]
static HOLDERS: concurrency::process_global::Mutex<Vec<(DevIndex, RawFd, RawFd)>> =
    concurrency::process_global::Mutex::new(Vec::new());

/// Lock the process-wide registry of queue interrupt owners.
#[allow(
    clippy::disallowed_types,
    reason = "tracks registrations in the EAL's process-wide ports, which outlive model executions"
)]
fn holders() -> concurrency::process_global::MutexGuard<'static, Vec<(DevIndex, RawFd, RawFd)>> {
    HOLDERS
        .lock()
        .unwrap_or_else(concurrency::process_global::PoisonError::into_inner)
}

/// Arm `queue`'s interrupt on `port`, holding the port's lock. Returns the driver's result.
///
/// # Safety
///
/// The port and queue must exist.
#[allow(
    clippy::disallowed_types,
    reason = "guards calls into the EAL's process-wide ports, which outlive model executions"
)]
unsafe fn enable(port: DevIndex, queue: RxQueueIndex) -> i32 {
    let _guard = PORT_LOCKS[usize::from(port.as_u16())]
        .lock()
        .unwrap_or_else(concurrency::process_global::PoisonError::into_inner);
    // SAFETY: the caller guarantees the port and queue exist.
    unsafe { dpdk_sys::rte_eth_dev_rx_intr_enable(port.as_u16(), queue.as_u16()) }
}

/// Disarm `queue`'s interrupt on `port`, holding the port's lock.
///
/// # Safety
///
/// The port and queue must exist.
#[allow(
    clippy::disallowed_types,
    reason = "guards calls into the EAL's process-wide ports, which outlive model executions"
)]
unsafe fn disable(port: DevIndex, queue: RxQueueIndex) {
    let _guard = PORT_LOCKS[usize::from(port.as_u16())]
        .lock()
        .unwrap_or_else(concurrency::process_global::PoisonError::into_inner);
    // SAFETY: the caller guarantees the port and queue exist.
    unsafe { dpdk_sys::rte_eth_dev_rx_intr_disable(port.as_u16(), queue.as_u16()) };
}

/// Why setting up or using a wait failed.
#[derive(Debug, thiserror::Error)]
pub enum InterruptError {
    /// The kernel would not create the epoll set.
    #[error("could not create an epoll set: {0}")]
    Epoll(std::io::Error),
    /// The queue's device has no receive interrupts: it was configured without them, or its driver
    /// has none.
    #[error("port {port} queue {queue} has no receive interrupt: {code:?}")]
    Unsupported {
        /// The port.
        port: u16,
        /// The queue.
        queue: u16,
        /// What the driver said.
        code: Errno,
    },
    /// The queue has no interrupt descriptor. The DPDK lookup provides no specific error code.
    #[error("port {port} queue {queue} has no receive interrupt event descriptor")]
    NoEventFd {
        /// The port.
        port: u16,
        /// The queue.
        queue: u16,
    },
    /// The queue shares its interrupt with a queue in another worker's set, so it cannot wake this
    /// one reliably.
    #[error("port {port} queue {queue} shares its interrupt with another worker's queue")]
    Shared {
        /// The port.
        port: u16,
        /// The queue.
        queue: u16,
    },
    /// The queue's driver arms and disarms other queues' interrupts than the ones asked for (see
    /// [`arms_each_queue`]), so the queue could not be relied on to wake this one.
    #[error("port {port} queue {queue}: the {driver} driver arms other queues' interrupts")]
    ArmsAnotherQueue {
        /// The port.
        port: u16,
        /// The queue.
        queue: u16,
        /// The driver's name.
        driver: String,
    },
    /// Registering or arming a queue's interrupt failed.
    #[error("port {port} queue {queue}: {what} failed: {code:?}")]
    Queue {
        /// The port.
        port: u16,
        /// The queue.
        queue: u16,
        /// What was being done.
        what: &'static str,
        /// What the driver said.
        code: Errno,
    },
    /// The EAL would not add a file descriptor to the set.
    #[error("could not watch file descriptor {fd}: {code:?}")]
    Fd {
        /// The descriptor.
        fd: RawFd,
        /// What the EAL said.
        code: Errno,
    },
    /// The wait failed. The EAL logs the cause but does not preserve `errno` reliably.
    #[error("epoll wait failed; the EAL logged why")]
    Wait,
}

/// A file descriptor other than a queue's that wakes the waiter, as the EAL tracks it.
///
/// The EAL retains a mutable pointer until unregistration. Own the allocation through a raw
/// pointer so moving its Rust owner does not assert unique access to the event.
struct Extra {
    event: NonNull<dpdk_sys::rte_epoll_event>,
    fd: RawFd,
}

impl Extra {
    fn new(fd: RawFd) -> Self {
        let mut event = Box::new(dpdk_sys::rte_epoll_event::default());
        event.epdata.event = (EPOLLIN | EPOLLET) as u32;
        // No callback: nothing is read on the caller's behalf.
        event.epdata.cb_fun = None;
        Self {
            event: Box::into_non_null(event),
            fd,
        }
    }
}

impl Drop for Extra {
    fn drop(&mut self) {
        // SAFETY: this allocation came from Box::into_non_null and has one owner. RxWaiter removes
        // the registration and closes its epoll descriptor before dropping extras. A failed
        // registration never gives the EAL ownership of the pointer.
        unsafe { drop(Box::from_raw(self.event.as_ptr())) };
    }
}

/// What a [`RxWaiter::wait`] woke up for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Woke {
    /// Receive interrupts raised.
    pub queues: usize,
    /// Other watched file descriptors that are readable, each counted once.
    pub other: usize,
    /// A signal handler ran on this thread and ended the wait early, with nothing else to report.
    pub signalled: bool,
}

impl Woke {
    /// Whether the wait ended at its deadline, with nothing to report.
    #[must_use]
    pub fn timed_out(&self) -> bool {
        self.queues == 0 && self.other == 0 && !self.signalled
    }
}

/// One lcore's epoll set: the receive interrupts of its queues, and other descriptors to wake on.
///
/// Borrows the queues' devices for `'dev`: the interrupts must leave the set before the devices
/// stop, which dropping the waiter does.
pub struct RxWaiter<'dev> {
    // Close before freeing extras, including when unregistering an event fails.
    epfd: OwnedFd,
    /// Every queue watched, to arm and disarm.
    queues: Vec<(DevIndex, RxQueueIndex)>,
    /// The queues whose interrupt this set added (one per shared descriptor), to remove again.
    added: Vec<(DevIndex, RxQueueIndex, RawFd)>,
    extras: Vec<Extra>,
    armed: bool,
    _dev: PhantomData<&'dev ()>,
}

impl core::fmt::Debug for RxWaiter<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RxWaiter")
            .field("epfd", &self.epfd)
            .field("queues", &self.queues)
            .field("extras", &self.extras.len())
            .field("armed", &self.armed)
            .finish()
    }
}

impl<'dev> RxWaiter<'dev> {
    /// An empty set.
    ///
    /// # Errors
    ///
    /// [`InterruptError::Epoll`] if the kernel will not create one.
    pub fn new() -> Result<Self, InterruptError> {
        let Epoll(epfd) = Epoll::new(EpollCreateFlags::EPOLL_CLOEXEC)
            .map_err(|e| InterruptError::Epoll(e.into()))?;
        Ok(Self {
            epfd,
            queues: Vec::new(),
            added: Vec::new(),
            extras: Vec::new(),
            armed: false,
            _dev: PhantomData,
        })
    }

    /// Wake on `queue`'s receive interrupt.
    ///
    /// # Errors
    ///
    /// [`InterruptError::NoEventFd`] or [`InterruptError::Unsupported`] if the queue's device has
    /// no receive interrupts, [`InterruptError::ArmsAnotherQueue`] if its driver cannot arm them
    /// one queue at a time, [`InterruptError::Shared`] if its interrupt is another worker's too,
    /// [`InterruptError::Queue`] if the driver will not add it.
    pub fn watch(&mut self, queue: &RxQueue<'dev>) -> Result<(), InterruptError> {
        let port = queue.dev;
        let index = queue.config.queue_index;
        // A port whose information cannot be read fails the descriptor lookup below as well.
        if let Ok(info) = port.info()
            && !arms_each_queue(&info)
        {
            return Err(InterruptError::ArmsAnotherQueue {
                port: port.as_u16(),
                queue: index.as_u16(),
                driver: info.driver_name().to_owned(),
            });
        }
        // SAFETY: the port and queue exist for 'dev.
        let fd =
            unsafe { dpdk_sys::rte_eth_dev_rx_intr_ctl_q_get_fd(port.as_u16(), index.as_u16()) };
        // DPDK returns -1 for every failure without a specific error code.
        if fd < 0 {
            return Err(InterruptError::NoEventFd {
                port: port.as_u16(),
                queue: index.as_u16(),
            });
        }
        let epfd = self.epfd.as_raw_fd();
        let mut holders = holders();
        match holders.iter().find(|&&(p, f, _)| p == port && f == fd) {
            // Another of this worker's queues shares the interrupt: arming both arms it.
            Some(&(_, _, holder)) if holder == epfd => {
                self.queues.push((port, index));
                return Ok(());
            }
            Some(_) => {
                return Err(InterruptError::Shared {
                    port: port.as_u16(),
                    queue: index.as_u16(),
                });
            }
            None => {}
        }
        // SAFETY: the port and queue exist for 'dev, and the EAL owns the event it registers.
        let ret = unsafe {
            dpdk_sys::rte_eth_dev_rx_intr_ctl_q(
                port.as_u16(),
                index.as_u16(),
                self.epfd.as_raw_fd(),
                dpdk_sys::RTE_INTR_EVENT_ADD as i32,
                core::ptr::null_mut(),
            )
        };
        match ret {
            0 => {
                holders.push((port, fd, epfd));
                self.queues.push((port, index));
                self.added.push((port, index, fd));
                Ok(())
            }
            errno::NEG_EOPNOTSUPP | errno::NEG_EPERM => Err(InterruptError::Unsupported {
                port: port.as_u16(),
                queue: index.as_u16(),
                code: Errno(ret),
            }),
            _ => Err(InterruptError::Queue {
                port: port.as_u16(),
                queue: index.as_u16(),
                what: "adding the interrupt",
                code: Errno(ret),
            }),
        }
    }

    /// Register `fd` for edge-triggered readability notifications. The caller must drain it.
    ///
    /// The EAL collects ready events until its output array is full. Level-triggered registration
    /// would repeatedly report an undrained descriptor within the same wait.
    ///
    /// # Errors
    ///
    /// [`InterruptError::Fd`] if the EAL will not add it.
    ///
    /// # Safety
    ///
    /// `fd` must stay open for as long as the waiter lives.
    pub unsafe fn watch_fd(&mut self, fd: BorrowedFd<'_>) -> Result<(), InterruptError> {
        let extra = Extra::new(fd.as_raw_fd());
        // SAFETY: the allocation lives until unregistration and is only accessed through raw
        // pointers while the EAL retains it. Moving Extra does not invalidate those pointers.
        let ret = unsafe {
            dpdk_sys::rte_epoll_ctl(
                self.epfd.as_raw_fd(),
                EPOLL_CTL_ADD,
                fd.as_raw_fd(),
                extra.event.as_ptr(),
            )
        };
        if ret != 0 {
            return Err(InterruptError::Fd {
                fd: fd.as_raw_fd(),
                code: Errno(ret),
            });
        }
        self.extras.push(extra);
        Ok(())
    }

    /// How many queues the set holds.
    #[must_use]
    pub fn queues(&self) -> usize {
        self.queues.len()
    }

    /// Whether the queues' interrupts are armed.
    #[must_use]
    pub fn armed(&self) -> bool {
        self.armed
    }

    /// Arm every queue's interrupt. Poll the queues once more before [waiting](Self::wait): a
    /// packet that arrived before this may not raise one.
    ///
    /// # Errors
    ///
    /// [`InterruptError::Queue`] if a driver will not arm a queue; those already armed are
    /// disarmed again.
    pub fn arm(&mut self) -> Result<(), InterruptError> {
        for (at, &(port, queue)) in self.queues.iter().enumerate() {
            // SAFETY: the port and queue exist for 'dev.
            let ret = unsafe { enable(port, queue) };
            if ret != 0 {
                for &(port, queue) in &self.queues[..at] {
                    // SAFETY: as above.
                    unsafe { disable(port, queue) };
                }
                return Err(InterruptError::Queue {
                    port: port.as_u16(),
                    queue: queue.as_u16(),
                    what: "arming the interrupt",
                    code: Errno(ret),
                });
            }
        }
        self.armed = true;
        Ok(())
    }

    /// Disarm every queue's interrupt before polling again to avoid interrupt overhead.
    pub fn disarm(&mut self) {
        if !self.armed {
            return;
        }
        for &(port, queue) in &self.queues {
            // SAFETY: the port and queue exist for 'dev. Some drivers acknowledge the interrupt
            // here (mlx5 reads its completion event), so it is done whether or not one was raised.
            unsafe { disable(port, queue) };
        }
        self.armed = false;
    }

    /// Wait for a queue interrupt, a readable descriptor, a handled signal, or a timeout.
    ///
    /// Convert `longest` to whole milliseconds, clamped to `1..=i32::MAX`. This sets the kernel
    /// timeout; scheduling can delay the return. Callers with less than 1 ms left should not wait.
    /// A handled signal ends the wait rather than restarting the timeout, so repeated signals
    /// cannot repeatedly extend the requested wait.
    ///
    /// # Errors
    ///
    /// [`InterruptError::Wait`] if the wait fails.
    pub fn wait(&mut self, longest: Duration) -> Result<Woke, InterruptError> {
        let mut events = [dpdk_sys::rte_epoll_event::default(); MAX_EVENTS];
        let timeout = i32::try_from(longest.as_millis())
            .unwrap_or(i32::MAX)
            .max(1);
        // SAFETY: the events array outlives the call, which writes at most MAX_EVENTS entries. The
        // EAL acknowledges each raised queue interrupt through the callback it registered.
        let ret = unsafe {
            dpdk_sys::rte_epoll_wait_interruptible(
                self.epfd.as_raw_fd(),
                events.as_mut_ptr(),
                MAX_EVENTS as i32,
                timeout,
            )
        };
        // A failed wait returns -1. The EAL logs the reason, unless a signal interrupted it.
        let Ok(count) = usize::try_from(ret) else {
            if nix::errno::Errno::last() == nix::errno::Errno::EINTR {
                return Ok(Woke {
                    signalled: true,
                    ..Woke::default()
                });
            }
            return Err(InterruptError::Wait);
        };
        let events = &events[..count];
        // A descriptor written to again while the EAL collects is reported again: count each once.
        // (Queue interrupts are acknowledged as they are reported.)
        let other = self
            .extras
            .iter()
            .filter(|extra| events.iter().any(|event| event.fd == extra.fd))
            .count();
        let queues = events
            .iter()
            .filter(|event| !self.extras.iter().any(|extra| extra.fd == event.fd))
            .count();
        Ok(Woke {
            queues,
            other,
            signalled: false,
        })
    }
}

impl Drop for RxWaiter<'_> {
    fn drop(&mut self) {
        self.disarm();
        // Unregister before closing epfd: the EAL retains its number and could otherwise act on
        // an unrelated descriptor that reuses it.
        let epfd = self.epfd.as_raw_fd();
        let mut holders = holders();
        for &(port, queue, fd) in &self.added {
            // SAFETY: the port and queue exist for 'dev.
            unsafe {
                dpdk_sys::rte_eth_dev_rx_intr_ctl_q(
                    port.as_u16(),
                    queue.as_u16(),
                    epfd,
                    dpdk_sys::RTE_INTR_EVENT_DEL as i32,
                    core::ptr::null_mut(),
                )
            };
            holders.retain(|&(p, f, holder)| !(p == port && f == fd && holder == epfd));
        }
        drop(holders);
        for extra in &mut self.extras {
            // SAFETY: the event was added by this waiter and its raw allocation is still live.
            unsafe {
                dpdk_sys::rte_epoll_ctl(
                    self.epfd.as_raw_fd(),
                    EPOLL_CTL_DEL,
                    extra.fd,
                    extra.event.as_ptr(),
                )
            };
        }
    }
}

#[cfg(test)]
mod tests;
