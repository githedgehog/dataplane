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
//! # Two independent gates, and why the probe separates them
//!
//! Reaching an mlx5 port requires passing two checks that have nothing to do with each other, and
//! conflating them produces a confident wrong conclusion in either direction:
//!
//! 1. **Enumeration, through sysfs.** `libibverbs` finds devices by reading
//!    `/sys/class/infiniband`. Sysfs is *tagged with the network namespace it was mounted in*, and
//!    a `setns` does not retag an already-mounted instance. So a thread that moves into a namespace
//!    keeps seeing the device list of wherever `/sys` was mounted -- listing devices it cannot use,
//!    or listing none when the devices are right there. Getting the current namespace's view
//!    requires a fresh `sysfs` mount made *after* the move, which in turn requires a private mount
//!    namespace so the rest of the process is undisturbed.
//! 2. **Access, through the RDMA subsystem.** Under `netns exclusive` the kernel checks the opening
//!    task's namespace against the device's when `/dev/infiniband/uverbs*` is opened. Those
//!    character devices live in devtmpfs, which is *not* namespaced, so they are visible from
//!    everywhere regardless -- their presence says nothing about whether they can be opened.
//!
//! Each gate can fail while the other would have passed, and each has a symptom that looks exactly
//! like the other's: "no devices found". The modes below exist to tell them apart.
//!
//! # What each mode of this probe establishes
//!
//! `N_NETNS_MODE` selects which question is being asked, because `rte_eal_init` may only run once
//! per process and each answer needs its own:
//!
//! | mode | thread runs in | establishes |
//! |---|---|---|
//! | `host` | the namespace it inherited | whether the port is reachable from where the process started |
//! | `unshared` | a fresh, empty namespace | whether RDMA gates on the namespace at all |
//! | `join` | the namespace at `N_NETNS_PATH` | whether a *moved* device is reachable by a thread that follows it |
//!
//! `join` additionally honours `N_NETNS_REMOUNT_SYS=1`, which unshares the mount namespace and
//! mounts a fresh `sysfs` after the move. Running `join` both ways is what distinguishes gate 1
//! from gate 2: if the plain run finds nothing and the remounting run finds the port, the obstacle
//! was sysfs tagging and the design needs a mount-namespace step it did not previously know about.
//! If neither finds it, the obstacle is RDMA access and no amount of mounting will help.
//!
//! Because `host` means different things depending on where the devices are, the expected outcome
//! is supplied rather than assumed: `N_NETNS_EXPECT` is the port count to assert on, and when it is
//! unset a run reports its result without judging it.
//!
//! # What it measured
//!
//! Against a BlueField-3 whose two ports had been moved into a namespace with
//! `devlink dev reload pci/0000:02:00.<n> netns experiment`, all four runs from one binary:
//!
//! | netns | sysfs | `open(uverbs*)` | devices enumerated | ports probed |
//! |---|---|---|---|---|
//! | host | inherited | `EPERM` | none | 0 |
//! | `experiment` | inherited | OK | none | 0 |
//! | `experiment` | fresh | OK | `mlx5_0`, `mlx5_1` | **1** |
//!
//! The two gates separate cleanly, and each row isolates one of them. Entering the namespace is
//! what flips the `open` from `EPERM` to success, and nothing else does; mounting a fresh sysfs is
//! what flips enumeration from empty to found, and nothing else does. Neither step alone gets a
//! port. Both together do, and the full forwarding path then runs in that namespace unmodified:
//! `dpdk_pipeline_on_nic`, driven across the same pair, verified 64 of 64 frames with no loss.
//!
//! So the design holds, with one requirement it did not previously state: **the thread that jumps
//! into the namespace must also unshare its mount namespace and mount a fresh sysfs there.** A
//! `setns` alone is not enough, and the way it fails -- an empty device list -- looks exactly like
//! the hardware not being there.
//!
//! Two traps are worth keeping, because both produce a confident wrong answer:
//!
//! - The mount must be made after making the mount tree private (`MS_REC | MS_PRIVATE`). Under the
//!   shared propagation a typical host uses, mounting over `/sys` otherwise propagates back out and
//!   replaces the host's own `/sys`.
//! - `EPERM` from `open(uverbs*)` is only evidence of the RDMA namespace check once the caller is
//!   known to be allowed the device at all. A container's default device cgroup denies char major
//!   231 and fails the open with the identical error, from any namespace -- which is what it did
//!   here until the rule was added, briefly making a solvable problem look like a kernel refusal.
//!
//! # Running it
//!
//! Needs `CAP_SYS_ADMIN` -- to create a namespace, to join one, and to mount sysfs -- on top of the
//! three capabilities every mlx5 DPDK test needs (see [`dpdk_on_nic`](dpdk_on_nic)).
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

/// For `join` mode, the network namespace to enter, as a path to a namespace file.
const PATH_ENV: &str = "N_NETNS_PATH";

/// For `join` mode, whether to mount a fresh sysfs after entering the namespace.
const REMOUNT_ENV: &str = "N_NETNS_REMOUNT_SYS";

/// The port count this run should find, if the caller knows what to expect.
const EXPECT_ENV: &str = "N_NETNS_EXPECT";

/// The RDMA devices visible to the calling thread, as `libibverbs` would enumerate them.
///
/// This reads sysfs on purpose rather than asking netlink: sysfs is the thing `libibverbs` reads,
/// so this reports what the PMD is about to see, including when that differs from what the kernel
/// would say the current namespace owns.
fn rdma_devices_visible() -> String {
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

/// Whether `/dev/infiniband/uverbs*` can actually be opened from here.
///
/// This is the direct observation of gate 2, and the only one that separates "the namespace refuses
/// me" from "I could not find the device". Under `netns exclusive` the kernel rejects the open with
/// `EPERM` when the caller's namespace is not the device's, so an `EPERM` here is a positive
/// identification of the namespace check rather than an inference from an empty list.
fn uverbs_open_report() -> String {
    let Ok(entries) = std::fs::read_dir("/dev/infiniband") else {
        return "no /dev/infiniband".to_string();
    };
    let mut results = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.starts_with("uverbs") {
            continue;
        }
        let outcome = match std::fs::File::open(entry.path()) {
            Ok(_) => "open OK".to_string(),
            Err(e) => format!("{e}"),
        };
        results.push(format!("{name}: {outcome}"));
    }
    if results.is_empty() {
        "no uverbs devices".to_string()
    } else {
        results.join("; ")
    }
}

/// Identify the current network namespace, so the log shows the thread really moved.
fn netns_id() -> String {
    std::fs::read_link("/proc/thread-self/ns/net")
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|e| format!("unknown ({e})"))
}

/// Report the namespaces and device visibility of whichever thread calls this.
fn report(who: &str) {
    eprintln!("[netns] {who} netns: {}", netns_id());
    eprintln!(
        "[netns] {who} rdma devices in sysfs: {}",
        rdma_devices_visible()
    );
    eprintln!("[netns] {who} uverbs: {}", uverbs_open_report());
}

/// What the probing thread should do to its namespaces before initializing the EAL.
enum Move {
    /// Stay put.
    Stay,
    /// Create a fresh, empty network namespace.
    Unshare,
    /// Enter an existing network namespace, optionally remounting sysfs afterwards.
    Join { path: String, remount_sys: bool },
}

/// Enter the namespace at `path`, and optionally give this thread a private `/sys` that reflects it.
///
/// The mount namespace is unshared *before* sysfs is mounted, and the root is made private first,
/// so neither the new mount nor its removal propagates anywhere else. Without that, mounting over
/// `/sys` would change it for every other thread in this process -- and, depending on how the
/// caller's mounts are set up, for the machine.
fn enter_namespace(path: &str, remount_sys: bool) {
    let file = std::fs::File::open(path)
        .unwrap_or_else(|e| panic!("cannot open network namespace {path}: {e}"));
    nix::sched::setns(file, nix::sched::CloneFlags::CLONE_NEWNET).unwrap_or_else(|e| {
        panic!("cannot enter network namespace {path}: {e} (needs CAP_SYS_ADMIN)")
    });
    eprintln!("[netns] entered {path}");

    if !remount_sys {
        return;
    }

    nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWNS)
        .expect("cannot unshare the mount namespace (needs CAP_SYS_ADMIN)");
    nix::mount::mount(
        None::<&str>,
        "/",
        None::<&str>,
        nix::mount::MsFlags::MS_REC | nix::mount::MsFlags::MS_PRIVATE,
        None::<&str>,
    )
    .expect("cannot make the mount tree private");
    nix::mount::mount(
        Some("sysfs"),
        "/sys",
        Some("sysfs"),
        nix::mount::MsFlags::empty(),
        None::<&str>,
    )
    .expect("cannot mount a fresh sysfs");
    eprintln!("[netns] mounted a fresh sysfs, tagged with this namespace");
}

#[test]
fn dpdk_from_a_thread_in_another_network_namespace() {
    let pci = std::env::var(PCI_ENV)
        .unwrap_or_else(|_| panic!("set {PCI_ENV} to the PCI address of an mlx5 port to probe"));
    let mode = std::env::var(MODE_ENV).unwrap_or_else(|_| "host".to_string());
    let remount_sys = std::env::var(REMOUNT_ENV).is_ok_and(|v| v == "1");
    let plan = match mode.as_str() {
        "host" => Move::Stay,
        "unshared" => Move::Unshare,
        "join" => Move::Join {
            path: std::env::var(PATH_ENV)
                .unwrap_or_else(|_| panic!("'join' mode needs {PATH_ENV}")),
            remount_sys,
        },
        other => panic!("{MODE_ENV} must be 'host', 'unshared' or 'join', got {other:?}"),
    };
    let expect: Option<usize> = std::env::var(EXPECT_ENV)
        .ok()
        .map(|v| v.parse().expect("N_NETNS_EXPECT must be a port count"));

    eprintln!("[netns] mode={mode}, remount_sys={remount_sys}, probing {pci}");
    report("main thread");
    eprintln!(
        "[netns] /dev/infiniband present: {}",
        Path::new("/dev/infiniband").exists()
    );

    // Everything happens on a spawned thread, because that is the shape the design needs: the
    // process keeps its own namespace for the control plane and hands one thread to the datapath.
    // `unshare` and `setns` both affect the calling thread alone, which is the property the whole
    // approach depends on.
    let probed = std::thread::spawn(move || {
        match plan {
            Move::Stay => {}
            Move::Unshare => {
                nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWNET)
                    .expect("failed to unshare the network namespace (needs CAP_SYS_ADMIN)");
            }
            Move::Join { path, remount_sys } => enter_namespace(&path, remount_sys),
        }
        report("worker thread");

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

    match expect {
        Some(expected) => assert_eq!(
            probed, expected,
            "expected {expected} port(s) from mode '{mode}', found {probed}"
        ),
        // Deliberately not an assertion: an exploratory run exists to *find out*, and both answers
        // are informative. It reports, loudly, and leaves the judgement to the reader.
        None => {
            if probed == 0 {
                eprintln!("[netns] RESULT: the port is NOT reachable in mode '{mode}'.");
            } else {
                eprintln!(
                    "[netns] RESULT: the port IS reachable in mode '{mode}' ({probed} probed)."
                );
            }
        }
    }
}
