// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! DPDK poll-mode driver.
//!
//! Each worker owns one RX/TX queue pair per port and processes each burst on the
//! receiving thread. Queue handles borrow their devices; mbufs borrow the EAL.
//!
//! RSS is disabled, so only queue 0 receives traffic. Ports need a kernel netdev
//! because the pipeline identifies interfaces by ifindex. Forwarding runs in software.

mod port;
mod worker;
