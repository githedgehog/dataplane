// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! DPDK's hierarchical scheduler (`rte_sched`), and CoDel over its queues.

use alloc::vec;
use core::ffi::{CStr, c_int};
use core::fmt::{self, Display, Formatter};
use core::ptr::{NonNull, null_mut};

use concurrency::sync::OnceLock;
use dpdk_sys::{
    RTE_SCHED_BE_QUEUES_PER_PIPE, RTE_SCHED_QUEUES_PER_PIPE, RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE,
    rte_color, rte_mbuf, rte_mbuf_dynfield, rte_mbuf_dynfield_register, rte_mbuf_sched_queue_get,
    rte_sched_pipe_config, rte_sched_pipe_params, rte_sched_port, rte_sched_port_config,
    rte_sched_port_dequeue, rte_sched_port_enqueue, rte_sched_port_free, rte_sched_port_params,
    rte_sched_port_pkt_write, rte_sched_queue_read_stats, rte_sched_queue_stats,
    rte_sched_subport_config, rte_sched_subport_params, rte_sched_subport_profile_params,
};
use tracing::{debug, error};

use super::codel::{Backlog, Codel, CodelParams, CodelParamsError, Departure};
use crate::mem::Mbuf;
use crate::socket::SocketId;

/// Traffic classes in one pipe. The last one is best effort; the rest are
/// served in strict priority order above it.
pub const TRAFFIC_CLASSES: usize = RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE as usize;

/// The best-effort traffic class, which is the only one with more than one
/// queue.
pub const BEST_EFFORT: u32 = TRAFFIC_CLASSES as u32 - 1;

/// Queues in the best-effort traffic class, shared out by WRR.
pub const BEST_EFFORT_QUEUES: usize = RTE_SCHED_BE_QUEUES_PER_PIPE as usize;

/// Queues in one pipe: one per strict-priority traffic class, plus the
/// best-effort ones.
pub const QUEUES_PER_PIPE: u32 = RTE_SCHED_QUEUES_PER_PIPE;

/// A colour, as `rte_meter` and `rte_sched` use the term.
///
/// The scheduler itself does not act on colour; it stores it in the packet for
/// the congestion manager, which is the only thing that reads it. Weighted RED
/// keeps a separate threshold set per colour. CoDel does not, because it
/// measures each packet's own delay rather than classifying it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Color {
    #[default]
    Green,
    Yellow,
    Red,
}

impl Color {
    fn as_raw(self) -> rte_color::Type {
        match self {
            Color::Green => rte_color::RTE_COLOR_GREEN,
            Color::Yellow => rte_color::RTE_COLOR_YELLOW,
            Color::Red => rte_color::RTE_COLOR_RED,
        }
    }
}

/// One queue's position in the scheduling hierarchy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueuePath {
    pub subport: u32,
    pub pipe: u32,
    /// `0..TRAFFIC_CLASSES`. [`BEST_EFFORT`] is the last one.
    pub traffic_class: u32,
    /// Always 0 outside the best-effort class, which is the only one with more
    /// than one queue.
    pub queue: u32,
}

/// The part of a [`QueuePath`] that does not fit the port it was offered to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvalidQueuePath {
    /// `subport` was at or above the port's subport count.
    Subport,
    /// `pipe` was at or above the subport's pipe count.
    Pipe,
    /// `traffic_class` was at or above [`TRAFFIC_CLASSES`].
    TrafficClass,
    /// `queue` was non-zero on a strict-priority traffic class, or at or above
    /// [`BEST_EFFORT_QUEUES`] on the best-effort one.
    Queue,
}

impl Display for InvalidQueuePath {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            InvalidQueuePath::Subport => write!(f, "subport out of range"),
            InvalidQueuePath::Pipe => write!(f, "pipe out of range"),
            InvalidQueuePath::TrafficClass => write!(f, "traffic class out of range"),
            InvalidQueuePath::Queue => write!(f, "queue out of range for its traffic class"),
        }
    }
}

impl core::error::Error for InvalidQueuePath {}

/// A token bucket plus its per-traffic-class rates.
///
/// Rates are bytes per second and `burst` is bytes, both as `rte_sched` counts
/// them: one credit is one byte on the wire, including the framing overhead
/// configured on the port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Shaper {
    /// Sustained rate.
    pub rate_bytes_per_second: u64,
    /// Bucket depth: how much may be sent back to back after an idle period.
    pub burst_bytes: u64,
    /// Per-traffic-class ceilings. Each is enforced over `tc_period_ms`.
    pub tc_rate_bytes_per_second: [u64; TRAFFIC_CLASSES],
    /// The window the per-class ceilings are enforced over. `rte_sched`
    /// requires this to be non-zero.
    pub tc_period_ms: u64,
}

impl Shaper {
    /// A shaper that lets any single traffic class use the whole rate.
    ///
    /// This is the "no class-level policy" setting: the strict-priority
    /// ordering between classes still decides who goes first, but no class is
    /// capped below the aggregate. It is what a subport wants, because
    /// `rte_sched` insists a subport rate every class, used or not.
    #[must_use]
    pub fn flat(rate_bytes_per_second: u64, burst_bytes: u64, tc_period_ms: u64) -> Shaper {
        Shaper {
            rate_bytes_per_second,
            burst_bytes,
            tc_rate_bytes_per_second: [rate_bytes_per_second; TRAFFIC_CLASSES],
            tc_period_ms,
        }
    }

    /// The same, but rating only the classes that have a queue.
    ///
    /// A *pipe* shaper must rate exactly the classes with a non-zero `qsize`
    /// and no others -- see [`PortError::TrafficClassRateWithoutQueue`]. Deriving
    /// the pattern from the queue sizes is how not to trip over that.
    #[must_use]
    pub fn for_queues(
        rate_bytes_per_second: u64,
        burst_bytes: u64,
        tc_period_ms: u64,
        qsize: &[u16; TRAFFIC_CLASSES],
    ) -> Shaper {
        let mut tc_rate_bytes_per_second = [0; TRAFFIC_CLASSES];
        for (rate, &size) in tc_rate_bytes_per_second.iter_mut().zip(qsize) {
            if size != 0 {
                *rate = rate_bytes_per_second;
            }
        }
        Shaper {
            rate_bytes_per_second,
            burst_bytes,
            tc_rate_bytes_per_second,
            tc_period_ms,
        }
    }

    /// Check what `rte_sched` checks about any shaper.
    fn validate(&self, port_rate: u64) -> Result<(), PortError> {
        if self.rate_bytes_per_second == 0 || self.rate_bytes_per_second > port_rate {
            return Err(PortError::ShaperRateOutOfRange);
        }
        if self.burst_bytes == 0 {
            return Err(PortError::ShaperBurstZero);
        }
        if self.tc_period_ms == 0 {
            return Err(PortError::ShaperPeriodZero);
        }
        for (class, &rate) in self.tc_rate_bytes_per_second.iter().enumerate() {
            if rate > self.rate_bytes_per_second {
                return Err(PortError::TrafficClassRateAboveShaper(class));
            }
        }
        Ok(())
    }
}

/// A pipe's shaping, plus how it splits its best-effort class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PipeProfile {
    pub shaper: Shaper,
    /// Weight used when best-effort traffic is oversubscribed at the subport.
    pub tc_ov_weight: u8,
    /// WRR weights across the best-effort queues. All must be non-zero.
    pub wrr_weights: [u8; BEST_EFFORT_QUEUES],
}

impl PipeProfile {
    /// A pipe that shapes to `shaper` and shares best effort evenly.
    #[must_use]
    pub fn even(shaper: Shaper) -> PipeProfile {
        PipeProfile {
            shaper,
            tc_ov_weight: 1,
            wrr_weights: [1; BEST_EFFORT_QUEUES],
        }
    }
}

/// Everything needed to stand up a scheduler port.
///
/// # This is not the full hierarchy yet
///
/// `rte_sched` lets every subport pick from a table of subport profiles and
/// every pipe from a per-subport table of pipe profiles. This draft configures
/// one of each and points every subport and every pipe at it, which is enough
/// for a port that shapes uniformly and still exercises the whole enqueue,
/// schedule and dequeue path. Adding the tables is an additive change: nothing
/// here has to move for a profile index to appear.
#[derive(Debug, Clone)]
pub struct PortParams {
    /// Name for DPDK's memory allocation. Must be unique in the process, and
    /// must not contain an interior NUL.
    pub name: String,
    /// NUMA node to allocate on. `rte_sched` rejects a negative socket, so
    /// [`SocketId::ANY`] will not do.
    pub socket: SocketId,
    /// Line rate of the port being scheduled.
    pub rate_bytes_per_second: u64,
    /// Largest frame, excluding the framing overhead below.
    pub mtu: u32,
    /// Per-packet on-wire overhead the shaper should charge but that is not in
    /// the mbuf's length: preamble, start-of-frame delimiter, FCS and the
    /// interframe gap. 24 bytes for Ethernet, which is `rte_sched`'s own
    /// default.
    pub frame_overhead: u32,
    /// Subports. Must be a non-zero power of two.
    pub subports: u32,
    /// Pipes in each subport. Must be a non-zero power of two, and it sizes the
    /// pipe field of every packet's queue id, so it is fixed for the whole port.
    pub pipes_per_subport: u32,
    /// Shaping applied to each subport.
    pub subport_shaper: Shaper,
    /// Depth of each traffic class's queue, in packets. Each must be zero or a
    /// power of two, and the best-effort one must be non-zero.
    ///
    /// This is the *only* bound on how much memory the port can hold, because
    /// this draft runs `rte_sched` with its congestion management switched off;
    /// see [`PortCodel`].
    pub qsize: [u16; TRAFFIC_CLASSES],
    /// Shaping applied to each pipe.
    pub pipe: PipeProfile,
}

/// Why a [`Port`] could not be created.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortError {
    /// The name contained an interior NUL byte.
    NameNotNulTerminable,
    /// [`SocketId::ANY`], or any other socket that reads as negative.
    /// `rte_sched` allocates from a specific node and refuses to guess.
    SocketMustBeSpecific,
    /// `subports` was zero or not a power of two.
    SubportsNotPowerOfTwo,
    /// `pipes_per_subport` was zero or not a power of two.
    PipesNotPowerOfTwo,
    /// `subports * pipes_per_subport * 16` does not fit a `u32`.
    ///
    /// Queue ids are `u32`, and [`PortCodel`] sizes itself from that count, so
    /// a port that cannot count its own queues would silently under-allocate
    /// its controllers and route every packet down an error path.
    TooManyQueues,
    /// A `qsize` entry was not zero or a power of two.
    QueueSizeNotPowerOfTwo,
    /// The best-effort traffic class had a zero `qsize`. `rte_sched` requires
    /// it to be usable even if nothing is classified into it.
    BestEffortQueueSizeZero,
    /// A shaper's sustained rate was zero, or above the port's line rate.
    ShaperRateOutOfRange,
    /// A shaper's token bucket was zero bytes deep.
    ShaperBurstZero,
    /// A shaper's enforcement period was zero.
    ShaperPeriodZero,
    /// This traffic class was rated above the shaper that contains it.
    TrafficClassRateAboveShaper(usize),
    /// This traffic class had no subport rate. `rte_sched` requires a subport
    /// to rate every class, whether or not the class has a queue -- unlike a
    /// pipe, which must rate exactly the ones that do.
    SubportTrafficClassRateZero(usize),
    /// This traffic class has no queue, but the pipe rates it anyway.
    ///
    /// `rte_sched` treats a rate on a queueless class as a configuration
    /// mistake rather than a harmless no-op, and refuses the whole pipe
    /// profile. [`Shaper::for_queues`] derives the pattern from the queue sizes
    /// so this cannot happen.
    TrafficClassRateWithoutQueue(usize),
    /// This traffic class has a queue, but the pipe does not rate it. The queue
    /// would exist with no way to be served.
    QueueWithoutTrafficClassRate(usize),
    /// A weight that `rte_sched` requires to be non-zero -- the best-effort
    /// oversubscription weight, or one of the WRR weights -- was zero.
    ZeroWeight,
    /// `rte_sched_port_config` refused the parameters.
    ///
    /// DPDK reports *which* parameter only through its own log, and sets no
    /// `rte_errno`, so this variant carries nothing. The pre-checks above cover
    /// the geometry; what is left is mostly rate arithmetic, chiefly a token
    /// bucket or traffic class rate above the port rate.
    PortRejected,
    /// `rte_sched_subport_config` refused, with this status.
    SubportRejected(c_int),
    /// `rte_sched_pipe_config` refused, with this status.
    PipeRejected(c_int),
}

impl Display for PortError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            PortError::NameNotNulTerminable => write!(f, "name contains an interior NUL"),
            PortError::SocketMustBeSpecific => write!(f, "socket must be a specific NUMA node"),
            PortError::SubportsNotPowerOfTwo => write!(f, "subports is not a power of two"),
            PortError::PipesNotPowerOfTwo => {
                write!(f, "pipes_per_subport is not a power of two")
            }
            PortError::TooManyQueues => write!(f, "the port has more queues than a u32 can count"),
            PortError::QueueSizeNotPowerOfTwo => write!(f, "a qsize is not a power of two"),
            PortError::BestEffortQueueSizeZero => {
                write!(f, "the best-effort traffic class has a zero qsize")
            }
            PortError::ShaperRateOutOfRange => {
                write!(f, "a shaper rate is zero or above the port rate")
            }
            PortError::ShaperBurstZero => write!(f, "a shaper burst is zero"),
            PortError::ShaperPeriodZero => write!(f, "a shaper enforcement period is zero"),
            PortError::TrafficClassRateAboveShaper(class) => {
                write!(f, "traffic class {class} is rated above its shaper")
            }
            PortError::SubportTrafficClassRateZero(class) => {
                write!(f, "traffic class {class} has no subport rate")
            }
            PortError::TrafficClassRateWithoutQueue(class) => {
                write!(f, "traffic class {class} is rated but has no queue")
            }
            PortError::QueueWithoutTrafficClassRate(class) => {
                write!(f, "traffic class {class} has a queue but no pipe rate")
            }
            PortError::ZeroWeight => write!(f, "a scheduling weight is zero"),
            PortError::PortRejected => write!(f, "rte_sched_port_config rejected the parameters"),
            PortError::SubportRejected(status) => {
                write!(f, "rte_sched_subport_config returned {status}")
            }
            PortError::PipeRejected(status) => write!(f, "rte_sched_pipe_config returned {status}"),
        }
    }
}

impl core::error::Error for PortError {}

/// One queue's counters, as `rte_sched` keeps them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct QueueStats {
    pub packets: u64,
    pub bytes: u64,
    pub packets_dropped: u64,
    pub bytes_dropped: u64,
    /// Of the drops, the ones the congestion manager made rather than the tail
    /// of a full queue. Zero throughout this draft, which runs with congestion
    /// management off; CoDel's drops happen after the packet has left the
    /// queue, so `rte_sched` never sees them.
    pub packets_cman_dropped: u64,
    /// Packets in the queue at the moment of the read.
    pub depth: u16,
}

/// A configured `rte_sched` port.
///
/// # One thread at a time
///
/// `rte_sched_port_enqueue` and `rte_sched_port_dequeue` are not thread-safe,
/// and DPDK expects a port to belong to one core. [`Port::enqueue`] and
/// [`Port::dequeue`] therefore take `&mut self`, which makes the borrow checker
/// enforce that; `Port` is [`Send`] so it can be moved to the core that will
/// run it, and deliberately not [`Sync`].
///
/// # The queues hold mbufs
///
/// A port with packets in it owns them, and [`Drop`] frees them. Those mbufs
/// come from a [`Pool`](crate::mem::Pool), which nothing here stops from being
/// dropped first -- the same lifetime hole that exists between a pool and a
/// device queue. Do not drop the pool while a port is alive.
pub struct Port {
    raw: NonNull<rte_sched_port>,
    subports: u32,
    pipes_per_subport: u32,
    queues: u32,
}

// SAFETY: `rte_sched_port` is a plain allocation with no thread affinity; DPDK
// only requires that one thread use it at a time, which `&mut self` on every
// operation that touches the queues already enforces. `Sync` is deliberately
// not implemented.
unsafe impl Send for Port {}

impl Drop for Port {
    fn drop(&mut self) {
        debug!("freeing rte_sched port");
        // SAFETY: `raw` came from `rte_sched_port_config` and has not been freed;
        // `Drop` runs once. Any mbufs still queued are freed by DPDK here.
        unsafe { rte_sched_port_free(self.raw.as_ptr()) }
    }
}

impl Port {
    /// Configure a port, its subports and its pipes.
    ///
    /// Congestion management is left off: see [`PortCodel`] for what replaces
    /// it and why.
    ///
    /// # Errors
    ///
    /// [`PortError`], naming the stage that refused.
    #[allow(clippy::cast_possible_wrap)] // socket is checked against c_int::MAX below
    pub fn new(params: &PortParams) -> Result<Port, PortError> {
        let name = std::ffi::CString::new(params.name.as_str())
            .map_err(|_| PortError::NameNotNulTerminable)?;
        let socket = params.socket.as_c_uint();
        if socket > c_int::MAX as u32 {
            return Err(PortError::SocketMustBeSpecific);
        }
        if !params.subports.is_power_of_two() {
            return Err(PortError::SubportsNotPowerOfTwo);
        }
        if !params.pipes_per_subport.is_power_of_two() {
            return Err(PortError::PipesNotPowerOfTwo);
        }
        let queues = params
            .subports
            .checked_mul(params.pipes_per_subport)
            .and_then(|q| q.checked_mul(QUEUES_PER_PIPE))
            .ok_or(PortError::TooManyQueues)?;
        if params.qsize.iter().any(|&q| q != 0 && !q.is_power_of_two()) {
            return Err(PortError::QueueSizeNotPowerOfTwo);
        }
        if params.qsize[BEST_EFFORT as usize] == 0 {
            return Err(PortError::BestEffortQueueSizeZero);
        }
        params
            .subport_shaper
            .validate(params.rate_bytes_per_second)?;
        params.pipe.shaper.validate(params.rate_bytes_per_second)?;
        // `rte_sched` rates a subport's classes unconditionally and a pipe's
        // only where there is a queue to serve. Two opposite rules over the same
        // array, checked here because DPDK reports both as one -EINVAL.
        for (class, &rate) in params
            .subport_shaper
            .tc_rate_bytes_per_second
            .iter()
            .enumerate()
        {
            if rate == 0 {
                return Err(PortError::SubportTrafficClassRateZero(class));
            }
        }
        for (class, (&rate, &size)) in params
            .pipe
            .shaper
            .tc_rate_bytes_per_second
            .iter()
            .zip(&params.qsize)
            .enumerate()
        {
            match (rate, size) {
                (0, 0) => {}
                (0, _) => return Err(PortError::QueueWithoutTrafficClassRate(class)),
                (_, 0) => return Err(PortError::TrafficClassRateWithoutQueue(class)),
                _ => {}
            }
        }
        if params.pipe.tc_ov_weight == 0 || params.pipe.wrr_weights.contains(&0) {
            return Err(PortError::ZeroWeight);
        }

        let mut subport_profile = rte_sched_subport_profile_params {
            tb_rate: params.subport_shaper.rate_bytes_per_second,
            tb_size: params.subport_shaper.burst_bytes,
            tc_rate: params.subport_shaper.tc_rate_bytes_per_second,
            tc_period: params.subport_shaper.tc_period_ms,
        };
        let mut port_params = rte_sched_port_params {
            name: name.as_ptr(),
            socket: socket as c_int,
            rate: params.rate_bytes_per_second,
            mtu: params.mtu,
            frame_overhead: params.frame_overhead,
            n_subports_per_port: params.subports,
            subport_profiles: &raw mut subport_profile,
            n_subport_profiles: 1,
            n_max_subport_profiles: 1,
            n_pipes_per_subport: params.pipes_per_subport,
        };

        // SAFETY: `port_params` and everything it points at are live for this
        // call. DPDK copies what it needs; the name is copied too.
        let raw = unsafe { rte_sched_port_config(&raw mut port_params) };
        let Some(raw) = NonNull::new(raw) else {
            error!("rte_sched_port_config rejected the parameters for '{name:?}'");
            return Err(PortError::PortRejected);
        };

        let port = Port {
            raw,
            subports: params.subports,
            pipes_per_subport: params.pipes_per_subport,
            queues,
        };

        let mut pipe_profile = rte_sched_pipe_params {
            tb_rate: params.pipe.shaper.rate_bytes_per_second,
            tb_size: params.pipe.shaper.burst_bytes,
            tc_rate: params.pipe.shaper.tc_rate_bytes_per_second,
            tc_period: params.pipe.shaper.tc_period_ms,
            tc_ov_weight: params.pipe.tc_ov_weight,
            wrr_weights: params.pipe.wrr_weights,
        };
        let mut subport_params = rte_sched_subport_params {
            n_pipes_per_subport_enabled: params.pipes_per_subport,
            qsize: params.qsize,
            pipe_profiles: &raw mut pipe_profile,
            n_pipe_profiles: 1,
            n_max_pipe_profiles: 1,
            // No congestion management: CoDel takes that job on the dequeue
            // side. A null here is DPDK's documented way of saying so.
            cman_params: null_mut(),
        };

        for subport in 0..params.subports {
            // SAFETY: `port.raw` is live, and `subport_params` (with the pipe
            // profile it points at) outlives the call. DPDK copies the profile
            // table into the subport.
            let status = unsafe {
                rte_sched_subport_config(port.raw.as_ptr(), subport, &raw mut subport_params, 0)
            };
            if status != 0 {
                error!("rte_sched_subport_config({subport}) returned {status}");
                return Err(PortError::SubportRejected(status));
            }
            for pipe in 0..params.pipes_per_subport {
                // SAFETY: `port.raw` is live and the subport above is configured.
                let status = unsafe { rte_sched_pipe_config(port.raw.as_ptr(), subport, pipe, 0) };
                if status != 0 {
                    error!("rte_sched_pipe_config({subport}, {pipe}) returned {status}");
                    return Err(PortError::PipeRejected(status));
                }
            }
        }

        debug!(
            "configured rte_sched port '{name:?}': {} subports x {} pipes = {} queues",
            params.subports, params.pipes_per_subport, port.queues,
        );
        Ok(port)
    }

    /// Queue ids in this port. Queue ids are dense over `0..queues()`, which is
    /// what lets [`PortCodel`] index its state by queue id directly.
    #[must_use]
    pub fn queues(&self) -> u32 {
        self.queues
    }

    /// Write a packet's place in the hierarchy into the packet.
    ///
    /// This is the classification step: `rte_sched` reads the queue back out of
    /// the mbuf at enqueue and never looks at the packet's contents. The queue
    /// id also survives the trip through the scheduler, which is how
    /// [`PortCodel`] tells dequeued packets apart.
    ///
    /// # Errors
    ///
    /// [`InvalidQueuePath`] if the path does not fit this port. Left unchecked,
    /// `rte_sched` would silently fold the out-of-range bits into a different
    /// queue's id.
    pub fn classify(
        &self,
        pkt: &mut Mbuf,
        path: QueuePath,
        color: Color,
    ) -> Result<(), InvalidQueuePath> {
        if path.subport >= self.subports {
            return Err(InvalidQueuePath::Subport);
        }
        if path.pipe >= self.pipes_per_subport {
            return Err(InvalidQueuePath::Pipe);
        }
        if path.traffic_class >= TRAFFIC_CLASSES as u32 {
            return Err(InvalidQueuePath::TrafficClass);
        }
        let queues_in_class = if path.traffic_class == BEST_EFFORT {
            BEST_EFFORT_QUEUES as u32
        } else {
            1
        };
        if path.queue >= queues_in_class {
            return Err(InvalidQueuePath::Queue);
        }
        // SAFETY: `self.raw` is live, `pkt` is a live mbuf we hold uniquely, and
        // the path is in range for this port's geometry.
        unsafe {
            rte_sched_port_pkt_write(
                self.raw.as_ptr(),
                pkt.raw.as_ptr(),
                path.subport,
                path.pipe,
                path.traffic_class,
                path.queue,
                color.as_raw(),
            );
        }
        Ok(())
    }

    /// The queue a packet was classified into.
    ///
    /// Valid from [`Port::classify`] onwards, including after the packet comes
    /// back out of [`Port::dequeue`]: `rte_sched` reads this field but never
    /// clears it.
    #[must_use]
    pub fn queue_of(pkt: &Mbuf) -> u32 {
        // SAFETY: `pkt` is a live mbuf; the call only reads `hash.sched`.
        unsafe { rte_mbuf_sched_queue_get(pkt.raw.as_ptr()) }
    }

    /// Offer packets to the scheduler, returning how many it kept.
    ///
    /// # Every packet is consumed
    ///
    /// `pkts` is emptied whatever the return value, because `rte_sched` takes
    /// ownership of all of them: it queues the ones it keeps and frees the ones
    /// it drops. The count is a count, not a prefix -- DPDK does not say *which*
    /// packets it dropped, and there is no way to ask.
    ///
    /// The one exception is a burst of more than `u32::MAX` packets, which DPDK
    /// cannot be handed at all: that returns 0 and leaves `pkts` untouched.
    pub fn enqueue(&mut self, pkts: &mut Vec<Mbuf>) -> usize {
        let Ok(n) = u32::try_from(pkts.len()) else {
            return 0;
        };
        if n == 0 {
            return 0;
        }
        // SAFETY: `Mbuf` is `repr(transparent)` over a non-null `*mut rte_mbuf`,
        // so the buffer is a valid `*mut *mut rte_mbuf` of `n` live mbufs.
        let accepted =
            unsafe { rte_sched_port_enqueue(self.raw.as_ptr(), pkts.as_mut_ptr().cast(), n) };
        // DPDK now owns every one of them, kept or freed, so the `Mbuf`s must
        // not run their destructors. Truncating without dropping is exactly
        // that, and it keeps the allocation for the next burst.
        // SAFETY: 0 is never greater than the capacity, and no element needs
        // dropping.
        unsafe { pkts.set_len(0) };
        usize::try_from(accepted).unwrap_or(0)
    }

    /// Take up to `max` packets from the scheduler, appending them to `out`.
    ///
    /// Returns how many were appended.
    pub fn dequeue(&mut self, out: &mut Vec<Mbuf>, max: usize) -> usize {
        let Ok(max_u32) = u32::try_from(max) else {
            return 0;
        };
        if max_u32 == 0 {
            return 0;
        }
        let base = out.len();
        out.reserve(max);
        // SAFETY: `out` has room for `max` more elements after `base`, and
        // `Mbuf` is `repr(transparent)` over `*mut rte_mbuf`.
        let taken = unsafe {
            rte_sched_port_dequeue(
                self.raw.as_ptr(),
                out.as_mut_ptr().add(base).cast(),
                max_u32,
            )
        };
        let taken = usize::try_from(taken).unwrap_or(0);
        // SAFETY: DPDK initialised `taken` entries starting at `base`, each a
        // non-null mbuf we now own.
        unsafe { out.set_len(base + taken) };
        taken
    }

    /// Read and *clear* one queue's counters.
    ///
    /// # This is destructive
    ///
    /// `rte_sched_queue_read_stats` zeroes the queue's counters as a side
    /// effect of reporting them, which its documentation does not mention. Two
    /// callers cannot both have the totals; whoever reads first takes them. That
    /// is why [`PortCodel`] does not use this to find the backlog, and why
    /// nothing on the datapath should call it.
    ///
    /// # Errors
    ///
    /// The DPDK status if `queue` is out of range for this port.
    pub fn queue_stats(&mut self, queue: u32) -> Result<QueueStats, c_int> {
        let mut stats = rte_sched_queue_stats::default();
        let mut depth: u16 = 0;
        // SAFETY: `self.raw` is live; both out-parameters are live locals.
        let status = unsafe {
            rte_sched_queue_read_stats(self.raw.as_ptr(), queue, &raw mut stats, &raw mut depth)
        };
        if status != 0 {
            return Err(status);
        }
        Ok(QueueStats {
            packets: stats.n_pkts,
            bytes: stats.n_bytes,
            packets_dropped: stats.n_pkts_dropped,
            bytes_dropped: stats.n_bytes_dropped,
            packets_cman_dropped: stats.n_pkts_cman_dropped,
            depth,
        })
    }
}

/// The dynamic mbuf field carrying the time a packet was handed to the
/// scheduler.
///
/// CoDel needs each packet's sojourn time, and a sojourn time is a subtraction
/// between two moments the packet has to carry itself: `rte_sched` keeps no
/// per-packet timing, and there is nowhere else to put it that survives the
/// queue.
#[derive(Debug, Clone, Copy)]
pub struct EnqueueStamp {
    offset: usize,
}

/// The name DPDK knows the stamp by. Anything else in the process that
/// registers the same name with the same layout shares the field.
const STAMP_FIELD_NAME: &CStr = c"dataplane_sched_enqueue_stamp";

/// Registration is process-wide and permanent -- DPDK has no way to give a
/// dynamic field back -- so it happens once and is remembered.
static STAMP: OnceLock<Result<EnqueueStamp, c_int>> = OnceLock::new();

impl EnqueueStamp {
    /// Reserve the field, or return the offset already reserved for it.
    ///
    /// # Errors
    ///
    /// The `rte_errno` DPDK set: `ENOENT` when the mbuf has no room left for
    /// another dynamic field, `EPERM` in a secondary process, `EEXIST` if
    /// something else in the process claimed this name with a different layout.
    ///
    /// # Panics
    ///
    /// Never: the name is a compile-time constant well under DPDK's 64-byte
    /// limit, so the copy below cannot overrun.
    pub fn register() -> Result<EnqueueStamp, c_int> {
        *STAMP.get_or_init(|| {
            let mut params = rte_mbuf_dynfield {
                name: [0; 64],
                size: size_of::<u64>(),
                align: align_of::<u64>(),
                flags: 0,
            };
            let name = STAMP_FIELD_NAME.to_bytes_with_nul();
            debug_assert!(name.len() <= params.name.len(), "field name is too long");
            for (slot, &byte) in params.name.iter_mut().zip(name) {
                #[allow(clippy::cast_possible_wrap)] // c_char is signed on this target
                {
                    *slot = byte as core::ffi::c_char;
                }
            }
            // SAFETY: `params` is a live, fully initialised descriptor; DPDK only
            // reads it.
            let offset = unsafe { rte_mbuf_dynfield_register(&raw const params) };
            if offset < 0 {
                // SAFETY: reading the thread-local `rte_errno`.
                let errno = unsafe { dpdk_sys::rte_errno_get() };
                error!("rte_mbuf_dynfield_register failed: rte_errno = {errno}");
                return Err(errno);
            }
            let offset = usize::try_from(offset).unwrap_or(0);
            debug!("reserved mbuf dynfield for the sched enqueue stamp at {offset}");
            Ok(EnqueueStamp { offset })
        })
    }

    /// Stamp a packet with the time it is being handed to the scheduler.
    ///
    /// Must be called on every packet before [`Port::enqueue`]. An unstamped
    /// packet reads back whatever the field last held, which is another packet's
    /// enqueue time -- a plausible-looking sojourn measured against the wrong
    /// packet, which is worse than an obviously wrong one.
    pub fn set(&self, pkt: &mut Mbuf, now: u64) {
        // SAFETY: `offset` came from DPDK's own reservation inside the mbuf
        // structure, so the field is within the allocation, aligned for `u64`,
        // and reserved for us alone. `pkt` is held uniquely.
        unsafe { self.field(pkt.raw.as_ptr()).write(now) }
    }

    /// Stamp a whole burst.
    pub fn set_all(&self, pkts: &mut [Mbuf], now: u64) {
        for pkt in pkts {
            self.set(pkt, now);
        }
    }

    /// Read back what [`EnqueueStamp::set`] wrote.
    #[must_use]
    pub fn get(&self, pkt: &Mbuf) -> u64 {
        // SAFETY: as above; the field is live and initialised if `set` was called,
        // and readable as a `u64` either way.
        unsafe { self.field(pkt.raw.as_ptr()).read() }
    }

    /// The field's address inside an mbuf. DPDK spells this `RTE_MBUF_DYNFIELD`,
    /// which is a macro and therefore not bound.
    ///
    /// # Safety
    ///
    /// `pkt` must be a live mbuf.
    unsafe fn field(&self, pkt: *mut rte_mbuf) -> *mut u64 {
        // SAFETY: the caller guarantees `pkt` is live, and `offset` is inside it.
        unsafe { pkt.cast::<u8>().add(self.offset).cast::<u64>() }
    }
}

/// CoDel over every queue of one [`Port`].
///
/// # Why CoDel cannot be an `rte_sched` congestion manager
///
/// `rte_sched`'s congestion management hook runs inside
/// `rte_sched_port_enqueue`, and `rte_sched_cman_mode` is a closed enum of two:
/// [`Red`](super::Red) and [`Pie`](super::Pie). Even if it were open, the hook
/// is in the wrong place. CoDel's input is the sojourn time of the packet it is
/// deciding about, and that is not knowable until the packet leaves. An
/// enqueue-time AQM can only work from a proxy for it.
///
/// So CoDel goes on the other side: stamp at enqueue, subtract at dequeue,
/// filter the burst `rte_sched` hands back. The scheduler is untouched --
/// shaping, strict priority and WRR all still run exactly as configured, since
/// none of them consults the congestion manager anyway.
///
/// # What each half bounds
///
/// `rte_sched`'s `qsize` tail drop bounds *memory*; CoDel bounds *delay*. That
/// is the same division of labour Linux uses when it stacks `codel` under a
/// queue limit, and it is why turning `rte_sched`'s own congestion management
/// off costs nothing: the tail drop is still there.
///
/// # The cost of dropping late
///
/// A packet dropped here has already been scheduled, so it has already spent
/// the shaper credits it was going to spend. Those credits are wasted. This is
/// inherent to measuring delay rather than guessing at it, it is what Linux's
/// `sch_codel` does too, and it is bounded by the drop rate -- which, if CoDel
/// is working, is small.
///
/// # One controller per queue is most of what `fq_codel` is
///
/// A single CoDel over a queue shared by many bulk senders sits above its
/// target: the drop rate it can produce climbs only as the square root of how
/// long the congestion has lasted, and every dip under target costs it a fresh
/// interval of grace. What closes that gap is giving each flow its own queue
/// and its own controller, which is what Linux's `fq_codel` does and what plain
/// CoDel does not.
///
/// This is per-queue, so traffic that `rte_sched` has already split across
/// pipes is already split across controllers, and a busy pipe cannot spend
/// another pipe's grace period. What it does not do is hash flows into queues
/// by itself -- classification decides that, and if everything lands in one
/// queue this is plain CoDel again.
/// `sim::aimd_senders_see_the_queue_each_policy_holds` measures the plain case.
///
/// # Memory
///
/// One controller per queue, allocated up front, because the queue id is a
/// dense index and a lookup on the datapath should be an offset. A port with
/// 4096 pipes has 65536 queues; at roughly 56 bytes of state each that is a few
/// megabytes. Size the pipe count for the hierarchy actually wanted rather than
/// for the maximum.
pub struct PortCodel {
    queues: Box<[Codel]>,
    stamp: EnqueueStamp,
}

/// Why a [`PortCodel`] could not be built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortCodelError {
    /// The CoDel parameters did not validate.
    Params(CodelParamsError),
    /// The enqueue-time stamp could not be reserved in the mbuf, with this
    /// `rte_errno`. See [`EnqueueStamp::register`].
    NoStampField(c_int),
}

impl Display for PortCodelError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            PortCodelError::Params(err) => write!(f, "{err}"),
            PortCodelError::NoStampField(errno) => {
                write!(
                    f,
                    "could not reserve the enqueue stamp: rte_errno = {errno}"
                )
            }
        }
    }
}

impl core::error::Error for PortCodelError {}

impl PortCodel {
    /// One CoDel controller per queue of `port`, all with the same parameters.
    ///
    /// # Errors
    ///
    /// [`PortCodelError`] if the parameters are wrong or the mbuf has no room
    /// for the enqueue stamp.
    pub fn new(port: &Port, params: CodelParams) -> Result<PortCodel, PortCodelError> {
        let codel = Codel::new(params).map_err(PortCodelError::Params)?;
        let stamp = EnqueueStamp::register().map_err(PortCodelError::NoStampField)?;
        let queues = usize::try_from(port.queues()).unwrap_or(0);
        Ok(PortCodel {
            queues: vec![codel; queues].into_boxed_slice(),
            stamp,
        })
    }

    /// The stamp this instance reads. Hand every packet to
    /// [`EnqueueStamp::set_all`] with the same clock before [`Port::enqueue`].
    #[must_use]
    pub fn stamp(&self) -> EnqueueStamp {
        self.stamp
    }

    /// Run CoDel over a burst that just came out of [`Port::dequeue`].
    ///
    /// Dropped packets are removed from `pkts` and freed; the rest stay, in
    /// order. Returns how many were dropped.
    ///
    /// # Why a burst can be filtered in one pass
    ///
    /// [`Codel::depart`] requires that a drop be followed by the next packet
    /// *from the same queue*. A burst satisfies that by construction: packets
    /// from one queue appear in it in the order that queue yielded them, so
    /// walking the burst front to back and dispatching each packet to its own
    /// controller feeds every controller exactly its own stream, in order.
    ///
    /// The one place this departs from RFC 8289 is that the packet after a drop
    /// may not be in this burst at all. The RFC would pull it immediately;
    /// here it arrives on the next call. The control loop is timed in
    /// milliseconds and a burst is microseconds, so the difference is well
    /// inside the interval CoDel is measuring over -- but it is a difference,
    /// and it is the reason the state machine is written to resume rather than
    /// to loop.
    pub fn filter(&mut self, pkts: &mut Vec<Mbuf>, now: u64) -> usize {
        let mut dropped = 0;
        let queues = &mut self.queues;
        let stamp = self.stamp;
        pkts.retain_mut(|pkt| {
            let index = usize::try_from(Port::queue_of(pkt)).unwrap_or(usize::MAX);
            let Some(codel) = queues.get_mut(index) else {
                // The queue id came out of the same port these controllers were
                // sized from, so this cannot happen. Deliver rather than drop:
                // a packet is better than a lost one.
                error!("dequeued packet from queue {index}, which is outside the port");
                return true;
            };
            let sojourn = now.saturating_sub(stamp.get(pkt));
            match codel.depart(sojourn, Backlog::Unmeasured, now) {
                Departure::Deliver => true,
                Departure::Drop => {
                    dropped += 1;
                    // Removing it from the `Vec` drops the `Mbuf`, which frees it.
                    false
                }
            }
        });
        dropped
    }

    /// The controller for one queue, for tests and observability.
    #[must_use]
    pub fn queue(&self, queue: u32) -> Option<&Codel> {
        self.queues.get(usize::try_from(queue).ok()?)
    }

    /// Tell one queue's controller that the queue ran dry.
    ///
    /// See [`Codel::mark_queue_empty`]. Nothing in `rte_sched` reports this, so
    /// it is the caller's to supply if it knows -- typically after a dequeue
    /// that returned less than it asked for, which means the scheduler ran out
    /// of eligible packets.
    pub fn mark_queue_empty(&mut self, queue: u32) {
        if let Ok(index) = usize::try_from(queue)
            && let Some(codel) = self.queues.get_mut(index)
        {
            codel.mark_queue_empty();
        }
    }
}

#[cfg(test)]
mod tests {
    use net::buffer::Append;

    use super::{
        BEST_EFFORT, Color, EnqueueStamp, InvalidQueuePath, PipeProfile, Port, PortCodel,
        PortError, PortParams, QUEUES_PER_PIPE, QueuePath, Shaper, TRAFFIC_CLASSES,
    };
    use crate::mem::{Mbuf, Pool, PoolConfig, PoolParams};
    use crate::sched::{CodelParams, CodelParamsError, PortCodelError};
    use crate::socket::SocketId;
    use crate::with_eal;

    /// Ticks (nanoseconds) in a millisecond.
    const MS: u64 = 1_000_000;
    /// 10 Gbit/s, in the bytes per second `rte_sched` counts in.
    const RATE: u64 = 10_000_000_000 / 8;
    const MTU: u32 = 1500;
    /// Frames the tests build. Short, because the shaper is not what is under
    /// test here and a short frame drains faster.
    const FRAME_BYTES: u16 = 64;
    /// Depth of the best-effort queue, in packets.
    const QUEUE_DEPTH: u16 = 64;

    const FIRST_QUEUE: QueuePath = QueuePath {
        subport: 0,
        pipe: 0,
        traffic_class: BEST_EFFORT,
        queue: 0,
    };

    /// The NUMA node to build on.
    ///
    /// Not `SocketId::current()`: a Rust test thread is not an EAL lcore, so
    /// `rte_socket_id` reports "any", which `rte_sched` refuses -- it allocates
    /// on a specific node and will not guess.
    fn socket() -> SocketId {
        SocketId::iter()
            .next()
            .expect("the EAL has at least one socket")
    }

    fn params(name: &str, pipes: u32) -> PortParams {
        let mut qsize = [0u16; TRAFFIC_CLASSES];
        qsize[BEST_EFFORT as usize] = QUEUE_DEPTH;
        PortParams {
            name: name.to_string(),
            socket: socket(),
            rate_bytes_per_second: RATE,
            mtu: MTU,
            frame_overhead: 24,
            subports: 1,
            pipes_per_subport: pipes,
            subport_shaper: Shaper::flat(RATE, RATE, 10),
            qsize,
            pipe: PipeProfile::even(Shaper::for_queues(RATE, RATE, 10, &qsize)),
        }
    }

    /// A pool for one test.
    ///
    /// # Declare this before the [`Port`]
    ///
    /// A port frees the packets still in its queues when it is dropped, so it
    /// has to be dropped before the pool those packets came from. Rust drops
    /// locals in reverse declaration order, so the pool goes first in the
    /// source and last at runtime. Nothing in the types enforces that yet;
    /// see the note on [`Port`].
    fn pool(name: &str) -> Pool {
        Pool::new_pkt_pool(
            PoolConfig::new(
                name,
                PoolParams {
                    size: 1023,
                    cache_size: 0,
                    ..PoolParams::default()
                },
            )
            .expect("valid pool config"),
        )
        .expect("pool allocates")
    }

    /// Allocate `count` mbufs with a real length, all classified into `path`.
    fn burst(pool: &Pool, port: &Port, path: QueuePath, count: usize) -> Vec<Mbuf> {
        let mut pkts = pool.alloc_bulk(count);
        assert_eq!(pkts.len(), count, "pool should have had room");
        for pkt in &mut pkts {
            pkt.append(FRAME_BYTES).expect("mbuf has tailroom");
            port.classify(pkt, path, Color::Green)
                .expect("path is valid for this port");
        }
        pkts
    }

    /// The queue id `path` resolves to on `port`.
    ///
    /// Taken from a packet rather than computed, because the layout of the id
    /// -- how many bits the pipe takes, where the traffic class sits -- is
    /// `rte_sched`'s own and is not exported. Recomputing it here would be a
    /// second copy of a private encoding, and the copy that was wrong would be
    /// the one that indexes [`PortCodel`]'s state.
    fn queue_id(pool: &Pool, port: &Port, path: QueuePath) -> u32 {
        let pkts = burst(pool, port, path, 1);
        Port::queue_of(&pkts[0])
    }

    /// Drain the port until it stops yielding packets, or until `rounds` calls
    /// have gone by.
    ///
    /// `rte_sched` hands packets back a few at a time as its grinder walks the
    /// pipe bitmap, and only releases what the shaper has credits for, so one
    /// call returning nothing early does not mean the port is empty.
    fn drain(port: &mut Port, out: &mut Vec<Mbuf>, rounds: usize) {
        let mut idle = 0;
        for _ in 0..rounds {
            if port.dequeue(out, 32) == 0 {
                idle += 1;
                if idle > 4 {
                    break;
                }
            } else {
                idle = 0;
            }
        }
    }

    /// The whole path: classify, enqueue, schedule, dequeue.
    #[with_eal]
    #[test]
    fn sched_port_round_trips_packets() {
        let pool = pool("codel_round_trip_pool");
        let mut port = Port::new(&params("codel_round_trip", 4)).expect("port configures");
        assert_eq!(port.queues(), 4 * QUEUES_PER_PIPE);

        let mut pkts = burst(&pool, &port, FIRST_QUEUE, 16);
        let accepted = port.enqueue(&mut pkts);
        assert_eq!(
            accepted, 16,
            "an empty 64-deep queue should take 16 packets"
        );
        assert!(pkts.is_empty(), "enqueue consumes the burst either way");

        let mut out = Vec::new();
        drain(&mut port, &mut out, 32);
        assert_eq!(out.len(), 16, "everything enqueued should come back out");
    }

    /// The queue a packet was classified into survives the scheduler, which is
    /// what lets [`PortCodel`] keep per-queue state without a side table.
    #[with_eal]
    #[test]
    fn queue_id_survives_the_scheduler() {
        let pool = pool("codel_queue_id_pool");
        let mut port = Port::new(&params("codel_queue_id", 4)).expect("port configures");

        let path = QueuePath {
            subport: 0,
            pipe: 2,
            traffic_class: BEST_EFFORT,
            queue: 3,
        };
        let mut pkts = burst(&pool, &port, path, 4);
        let expected = Port::queue_of(&pkts[0]);
        assert_eq!(port.enqueue(&mut pkts), 4);

        let mut out = Vec::new();
        drain(&mut port, &mut out, 16);
        assert_eq!(out.len(), 4);
        for pkt in &out {
            assert_eq!(
                Port::queue_of(pkt),
                expected,
                "the queue id was lost or rewritten in the scheduler",
            );
        }
    }

    /// A queue over its size limit tail-drops inside `rte_sched`, which frees
    /// the packets it refuses.
    ///
    /// This is what still bounds memory once congestion management is off; see
    /// [`PortCodel`].
    #[with_eal]
    #[test]
    fn a_full_queue_tail_drops_inside_the_scheduler() {
        let pool = pool("codel_tail_drop_pool");
        let mut port = Port::new(&params("codel_tail_drop", 1)).expect("port configures");
        let queue = queue_id(&pool, &port, FIRST_QUEUE);

        // The queue holds 64. Offer 100 without dequeuing anything.
        let offered = 100;
        let mut pkts = burst(&pool, &port, FIRST_QUEUE, offered);
        let accepted = port.enqueue(&mut pkts);
        assert!(
            accepted <= usize::from(QUEUE_DEPTH),
            "a {QUEUE_DEPTH}-deep queue accepted {accepted} packets",
        );
        assert!(
            accepted >= usize::from(QUEUE_DEPTH) - 1,
            "it should have filled, but took {accepted}",
        );

        let stats = port.queue_stats(queue).expect("queue is in range");
        assert_eq!(
            stats.packets_cman_dropped, 0,
            "congestion management is off, so no drop is attributable to it",
        );
        assert_eq!(
            stats.packets_dropped,
            (offered - accepted) as u64,
            "every refused packet should be counted as a drop",
        );
    }

    /// A burst that has not waited is not congestion, and CoDel leaves it alone.
    #[with_eal]
    #[test]
    fn port_codel_leaves_a_fast_queue_alone() {
        let pool = pool("codel_fast_pool");
        let mut port = Port::new(&params("codel_fast", 1)).expect("port configures");
        let mut codel = PortCodel::new(
            &port,
            CodelParams {
                target: 5 * MS,
                interval: 100 * MS,
                mtu_bytes: u64::from(MTU),
            },
        )
        .expect("CoDel configures");
        let stamp = codel.stamp();

        let start = 1_000 * MS;
        let mut dropped = 0;
        for round in 0..8u64 {
            let at = start + round * MS;
            let mut pkts = burst(&pool, &port, FIRST_QUEUE, 16);
            stamp.set_all(&mut pkts, at);
            assert_eq!(port.enqueue(&mut pkts), 16);

            let mut out = Vec::new();
            drain(&mut port, &mut out, 16);
            assert_eq!(out.len(), 16);
            // A tenth of the target: nothing here has waited.
            dropped += codel.filter(&mut out, at + MS / 2);
            assert_eq!(out.len(), 16, "nothing should have been removed");
        }
        assert_eq!(
            dropped, 0,
            "CoDel dropped {dropped} packets from a queue nothing waited in",
        );
    }

    /// A standing queue does get dropped, through the real scheduler.
    ///
    /// The clock is the caller's, so the test can hold the queue over target
    /// for as long as CoDel needs without waiting on a real one: the stamp says
    /// the packets were enqueued long ago, and `now` says an interval has
    /// passed.
    #[with_eal]
    #[test]
    fn port_codel_drops_a_standing_queue() {
        const TARGET: u64 = 5 * MS;
        const INTERVAL: u64 = 100 * MS;

        let pool = pool("codel_standing_pool");
        let mut port = Port::new(&params("codel_standing", 1)).expect("port configures");
        let queue = queue_id(&pool, &port, FIRST_QUEUE);
        let mut codel = PortCodel::new(
            &port,
            CodelParams {
                target: TARGET,
                interval: INTERVAL,
                mtu_bytes: u64::from(MTU),
            },
        )
        .expect("CoDel configures");
        let stamp = codel.stamp();

        // Every packet claims to have been queued ten targets ago, and time
        // advances a millisecond per round, so the standing queue persists
        // across the whole interval CoDel measures over.
        let mut now = 1_000 * MS;
        let mut dropped = 0;
        let mut delivered = 0;
        for _ in 0..(4 * INTERVAL / MS) {
            let mut pkts = burst(&pool, &port, FIRST_QUEUE, 8);
            stamp.set_all(&mut pkts, now - 10 * TARGET);
            assert_eq!(port.enqueue(&mut pkts), 8);

            let mut out = Vec::new();
            drain(&mut port, &mut out, 8);
            assert_eq!(out.len(), 8, "the queue should have drained each round");
            dropped += codel.filter(&mut out, now);
            delivered += out.len();
            now += MS;
        }

        assert!(dropped > 0, "CoDel never dropped from a standing queue");
        assert!(
            delivered > dropped,
            "CoDel dropped {dropped} and delivered {delivered}; that is not \
             congestion control, that is a broken link",
        );
        let controller = codel.queue(queue).expect("the queue has a controller");
        assert!(
            controller.count() >= 3,
            "four intervals of standing queue should have climbed past one drop \
             per interval, but count is {}",
            controller.count(),
        );
    }

    /// Registration is idempotent: the second caller gets the same field.
    #[with_eal]
    #[test]
    fn the_enqueue_stamp_is_reserved_once() {
        let pool = pool("codel_stamp_pool");
        let first = EnqueueStamp::register().expect("mbuf has room for the stamp");
        let second = EnqueueStamp::register().expect("second registration succeeds");
        assert_eq!(first.offset, second.offset);

        let mut pkts = pool.alloc_bulk(1);
        first.set(&mut pkts[0], 0xdead_beef);
        assert_eq!(second.get(&pkts[0]), 0xdead_beef);
    }

    /// The geometry checks run before DPDK sees the path, so a bad one is a
    /// typed error rather than a packet quietly folded into another queue.
    #[with_eal]
    #[test]
    fn classify_rejects_paths_outside_the_port() {
        let pool = pool("codel_paths_pool");
        let port = Port::new(&params("codel_paths", 2)).expect("port configures");
        let mut pkt = pool.alloc_bulk(1).pop().expect("one mbuf");

        let ok = FIRST_QUEUE;
        assert_eq!(
            port.classify(&mut pkt, QueuePath { subport: 1, ..ok }, Color::Green),
            Err(InvalidQueuePath::Subport),
        );
        assert_eq!(
            port.classify(&mut pkt, QueuePath { pipe: 2, ..ok }, Color::Green),
            Err(InvalidQueuePath::Pipe),
        );
        assert_eq!(
            port.classify(
                &mut pkt,
                QueuePath {
                    traffic_class: TRAFFIC_CLASSES as u32,
                    ..ok
                },
                Color::Green,
            ),
            Err(InvalidQueuePath::TrafficClass),
        );
        // A strict-priority class has exactly one queue.
        assert_eq!(
            port.classify(
                &mut pkt,
                QueuePath {
                    traffic_class: 0,
                    queue: 1,
                    ..ok
                },
                Color::Green,
            ),
            Err(InvalidQueuePath::Queue),
        );
        assert_eq!(port.classify(&mut pkt, ok, Color::Green), Ok(()));
    }

    /// The geometry `rte_sched` insists on is checked here, with a name on each
    /// rule, rather than surfacing as a null return and a line in DPDK's log.
    #[with_eal]
    #[test]
    fn port_rejects_bad_geometry() {
        assert_eq!(
            Port::new(&PortParams {
                subports: 3,
                ..params("codel_bad_subports", 1)
            })
            .err(),
            Some(PortError::SubportsNotPowerOfTwo),
        );
        assert_eq!(
            Port::new(&params("codel_bad_pipes", 3)).err(),
            Some(PortError::PipesNotPowerOfTwo),
        );
        let mut qsize = [0u16; TRAFFIC_CLASSES];
        qsize[BEST_EFFORT as usize] = 63;
        assert_eq!(
            Port::new(&PortParams {
                qsize,
                ..params("codel_bad_qsize", 1)
            })
            .err(),
            Some(PortError::QueueSizeNotPowerOfTwo),
        );
        assert_eq!(
            Port::new(&PortParams {
                qsize: [0; TRAFFIC_CLASSES],
                ..params("codel_no_be", 1)
            })
            .err(),
            Some(PortError::BestEffortQueueSizeZero),
        );
        // A pipe that rates a class with no queue, which `rte_sched` calls a
        // configuration mistake rather than a harmless extra.
        assert_eq!(
            Port::new(&PortParams {
                pipe: PipeProfile::even(Shaper::flat(RATE, RATE, 10)),
                ..params("codel_rate_no_queue", 1)
            })
            .err(),
            Some(PortError::TrafficClassRateWithoutQueue(0)),
        );
        // And the other way round: a queue nothing will serve.
        let mut both = params("codel_queue_no_rate", 1);
        both.qsize[0] = 64;
        assert_eq!(
            Port::new(&both).err(),
            Some(PortError::QueueWithoutTrafficClassRate(0)),
        );
        // A subport must rate every class, queue or no queue.
        assert_eq!(
            Port::new(&PortParams {
                subport_shaper: Shaper::for_queues(RATE, RATE, 10, &params("x", 1).qsize),
                ..params("codel_subport_gap", 1)
            })
            .err(),
            Some(PortError::SubportTrafficClassRateZero(0)),
        );
        assert_eq!(
            Port::new(&PortParams {
                pipe: PipeProfile {
                    tc_ov_weight: 0,
                    ..params("x", 1).pipe
                },
                ..params("codel_zero_weight", 1)
            })
            .err(),
            Some(PortError::ZeroWeight),
        );
        assert_eq!(
            Port::new(&PortParams {
                socket: SocketId::ANY,
                ..params("codel_any_socket", 1)
            })
            .err(),
            Some(PortError::SocketMustBeSpecific),
        );
    }

    /// A bad CoDel configuration is refused before any queue state is built.
    #[with_eal]
    #[test]
    fn port_codel_rejects_bad_parameters() {
        let port = Port::new(&params("codel_bad_params", 1)).expect("port configures");
        assert_eq!(
            PortCodel::new(
                &port,
                CodelParams {
                    target: 0,
                    interval: MS,
                    mtu_bytes: u64::from(MTU),
                },
            )
            .err(),
            Some(PortCodelError::Params(CodelParamsError::TargetZero)),
        );
    }
}
