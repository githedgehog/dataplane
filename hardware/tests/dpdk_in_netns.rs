// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Does DPDK still work from a thread in a non-initial network namespace?
//!
//! This is a feasibility probe, not a feature test. The dataplane is meant to end up spanning two
//! network namespaces: the control plane stays in the host's, while the packet path runs in an
//! isolated one that owns the NICs. That design rests on an assumption nothing in this tree has
//! ever checked -- that a thread can `setns` into another network namespace and still drive a DPDK
//! port from there.
//!
//! # Why this is an mlx5 question specifically
//!
//! A device bound to `vfio-pci` has no network-namespace association at all: it is a character
//! device under `/dev/vfio`, the kernel networking stack does not know it exists, and no namespace
//! can take it away. For those NICs the answer is "of course it works" and there is nothing to
//! probe.
//!
//! mlx5 is the opposite case, and the one that matters, because it is the production target. DPDK
//! attaches to it through the RDMA verbs/DevX interface while `mlx5_core` keeps the netdev, so the
//! PMD depends on two things the kernel *does* namespace: the RDMA device, and the netdev it is
//! associated with.
//!
//! The RDMA subsystem has two namespace modes, and which one the machine is in decides the whole
//! design:
//!
//! ```text
//! rdma system show
//! netns exclusive ...   RDMA devices belong to one namespace and are invisible outside it
//! netns shared ...      every RDMA device is visible from every namespace
//! ```
//!
//! Under `shared`, a namespace cannot own a NIC and the isolation the design wants is not
//! available. Under `exclusive` -- which is what the target machines are in -- a device can be
//! moved into a namespace, which is what makes the design possible, and also what makes attaching
//! from the *wrong* namespace fail.
//!
//! # What each mode of this probe establishes
//!
//! `N_NETNS_MODE` selects which question is being asked, because `rte_eal_init` may only run once
//! per process and each answer needs its own:
//!
//! | mode | thread runs in | expectation |
//! |---|---|---|
//! | `host` | the namespace it inherited | the port probes -- the control, proving the rig works |
//! | `unshared` | a fresh, empty namespace | under `exclusive` the port should *not* probe |
//!
//! An `unshared` run that finds the port would mean RDMA is not gating on the namespace here, and
//! that the packet path could stay wherever it likes. An `unshared` run that finds nothing confirms
//! the constraint the design has to be built around: **the EAL must be initialized on a thread that
//! is already in the namespace the devices live in**, which in turn means the whole DPDK datapath
//! -- an `Eal` is `!Send`, and every port, queue and mbuf is branded with its lifetime -- has to
//! live on that side.
//!
//! # Running it
//!
//! Needs `CAP_SYS_ADMIN` to create a namespace, on top of the three capabilities every mlx5 DPDK
//! test needs (see [`dpdk_on_nic`](dpdk_on_nic)).
//!
//! ```text
//! RUSTFLAGS="--cfg netns_tests" cargo nextest run -p dataplane-hardware --test dpdk_in_netns
//! ```

#![cfg(netns_tests)]

use std::path::Path;

use dpdk::eal;

/// The PCI address to probe. Required: this test moves nothing and assumes nothing.
const PCI_ENV: &str = "N_NETNS_PCI";

/// Which question to ask -- see the module docs.
const MODE_ENV: &str = "N_NETNS_MODE";

/// Read the RDMA subsystem's namespace mode, so a run's result can be interpreted.
///
/// Parsed from `/sys/class/infiniband/*/`? No -- the mode is not exposed there. It comes from
/// netlink, which `rdma system show` reads, so this reports what it can see and leaves the rest to
/// the operator.
fn rdma_netns_hint() -> String {
    // The RDMA devices visible to *this* namespace. Under `exclusive` this is the direct
    // observation that matters, and it needs no tooling.
    match std::fs::read_dir("/sys/class/infiniband") {
        Ok(entries) => {
            let names: Vec<String> = entries
                .flatten()
                .map(|e| e.file_name().to_string_lossy().to_string())
                .collect();
            if names.is_empty() {
                "none visible".to_string()
            } else {
                names.join(", ")
            }
        }
        Err(e) => format!("cannot read /sys/class/infiniband: {e}"),
    }
}

/// Identify the current network namespace, so the log shows the thread really moved.
fn netns_id() -> String {
    std::fs::read_link("/proc/thread-self/ns/net")
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|e| format!("unknown ({e})"))
}

#[test]
fn dpdk_from_a_thread_in_another_network_namespace() {
    let pci = std::env::var(PCI_ENV)
        .unwrap_or_else(|_| panic!("set {PCI_ENV} to the PCI address of an mlx5 port to probe"));
    let mode = std::env::var(MODE_ENV).unwrap_or_else(|_| "host".to_string());
    let unshare = match mode.as_str() {
        "host" => false,
        "unshared" => true,
        other => panic!("{MODE_ENV} must be 'host' or 'unshared', got {other:?}"),
    };

    eprintln!("[netns] mode={mode}, probing {pci}");
    eprintln!("[netns] main thread netns: {}", netns_id());
    eprintln!("[netns] rdma devices visible here: {}", rdma_netns_hint());
    eprintln!(
        "[netns] /dev/infiniband present: {}",
        Path::new("/dev/infiniband").exists()
    );

    // Everything happens on a spawned thread, because that is the shape the design needs: the
    // process keeps its own namespace for the control plane and hands one thread to the datapath.
    // `unshare(CLONE_NEWNET)` affects the calling thread alone, which is the property the whole
    // approach depends on.
    let probed = std::thread::spawn(move || {
        if unshare {
            nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWNET)
                .expect("failed to unshare the network namespace (needs CAP_SYS_ADMIN)");
            eprintln!("[netns] worker thread moved to netns: {}", netns_id());
            eprintln!(
                "[netns] rdma devices visible to the worker: {}",
                rdma_netns_hint()
            );
        } else {
            eprintln!("[netns] worker thread stayed in netns: {}", netns_id());
        }

        // `rte_eal_init` runs *here*, on the thread whose namespace is under test. That is the
        // whole point: if it had to run on the main thread the datapath could not be isolated.
        let eal = eal::init([
            "dpdk-netns-probe",
            "--in-memory",
            "--file-prefix",
            "hh-netns-probe",
            "-a",
            pci.as_str(),
        ]);
        let count = eal.dev.iter().count();
        eprintln!("[netns] EAL probed {count} port(s)");
        count
    })
    .join()
    .expect("the probing thread panicked");

    match mode.as_str() {
        "host" => assert_eq!(
            probed, 1,
            "the control run probed {probed} ports rather than 1, so the rig is wrong and the \
             'unshared' result would mean nothing"
        ),
        // Deliberately not an assertion on the outcome: this run exists to *find out*, and both
        // answers are informative. It reports, loudly, and leaves the judgement to the reader.
        _ => {
            if probed == 0 {
                eprintln!(
                    "[netns] RESULT: the port is NOT reachable from a fresh namespace. The EAL \
                     must be initialized on a thread already in the namespace that owns the \
                     devices, and the whole DPDK datapath has to live there with it."
                );
            } else {
                eprintln!(
                    "[netns] RESULT: the port IS reachable from a fresh namespace ({probed} \
                     probed). RDMA is not gating on the namespace here, so the datapath need not \
                     be pinned to one."
                );
            }
        }
    }
}
