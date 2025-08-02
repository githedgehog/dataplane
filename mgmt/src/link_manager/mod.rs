// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! First up, we need to manage network namespaces.
//!
//! This needs to be done via trait (or something that facilitates dependency injection) because the
//! threading model makes no sense without that.
//!
//! More specifically, the way you configure a thread in DPDK requires some extra stuff over and
//! above creating a system thread.
//! But we want to be able to support an `AF_PACKET` driver in addition to a DPDK-based driver.
//!
//! In the case of the `AF_PACKET` based driver we won't have DPDK at all.  But we will still
//! have the same basic threading structure.
//!
//! This begs the question: what are the types of threads that the drivers will need
//!
//! 1. pipeline threads: threads which actually process packets.  These are our
//!    workhorse threads.
//!
//!    * pipeline threads should typically run on isolated cores.
//!    * I do not currently think they should run an async runtime.
//!      Instead, they should use a library like [`kanal`](https://github.com/fereidani/kanal) to
//!      tx/rx messages with an async thread (see `trap-worker`s) to trap packets to the kernel.
//!    * Ideally, pipeline threads have almost zero privileges.
//!    * These threads MUST run in the `link` network namespace.
//!
//! 2. I/O threads: threads which are responsible for writing packets to and receiving packets from
//!    the network.
//!
//!    * These threads MUST run in the `link` network namespace.
//!    * These threads SHOULD exist in a 1:1 mapping with pipeline threads.
//!    * These threads SHOULD be pinned to the SMT sibling of the core the pipeline thread is
//!      running on.
//!    * I/O threads MAY also run some processing tasks (e.g. parsing).  Polling the queue as
//!      quickly as possible is unlikely to be efficient.
//!    * These threads MUST send and receive vectors of packet buffers to the pipeline threads via a
//!      sync queue.
//!    * These threads MAY run with higher privileges than pipeline threads.
//!      Specifically, they MAY need `CAP_NET_RAW` and possibly `CAP_SYS_RAWIO`.
//!    * These threads SHOULD run with only the privileges needed to tx/rx packets to the NIC
//!      queue(s).
//!
//! 3. Trap thread
//!
//!    * The trap thread MUST run in the `vpc` network namespace.
//!    * There MUST be a single thread that holds the rx side of an MPSC queue.
//!    * The tx side of the queue(s) MUST be held by the pipeline and/or I/O threads.
//!    * The trap-thread SHOULD run with only the privileges required to tx/rx packets to/from the
//!      tap devices in the `vpc` network namespace.
//!
//! 4. vpc-manager thread
//!
//!     * The primary job of the `vpc-manager` thread is to configure the `vpc` network namespace as
//!       required by the control plane services running there (e.g. FRR).
//!     * The `vpc-manager` SHOULD be a single thread.
//!     * The `vpc-manager` MUST run with the `CAP_NET_ADMIN` capability.
//!     * The `vpc-manager` MAY run with the `CAP_SYS_ADMIN` capability, but this SHOULD be avoided
//!       if possible.
//!     * The `vpc-manager` MUST run an async runtime.
