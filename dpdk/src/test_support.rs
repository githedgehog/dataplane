// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use concurrency::sync::OnceLock;

use crate::eal::Eal;

static EAL: OnceLock<Eal> = OnceLock::new();
#[must_use]
pub fn start_eal() -> &'static Eal {
    EAL.get_or_init(|| {
        let cpus = allowed_cpus();
        let eal_id = format!("{}", id::Id::<Eal>::new());
        let core_pinning = format!("0@({cpus})");
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
        crate::eal::init(args.iter().copied())
    })
}
#[allow(clippy::expect_used)]
fn allowed_cpus() -> String {
    use nix::sched::{CpuSet, sched_getaffinity};
    use nix::unistd::Pid;
    let set = sched_getaffinity(Pid::from_raw(0)).expect("sched_getaffinity");
    (0..CpuSet::count())
        .filter(|&i| set.is_set(i).unwrap_or(false))
        .map(|x| x.to_string())
        .collect::<Vec<_>>()
        .join(",")
}
