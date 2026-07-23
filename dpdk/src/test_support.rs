// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use concurrency::sync::OnceLock;

use crate::eal::Eal;

static EAL: OnceLock<Eal> = OnceLock::new();
#[must_use]
pub fn start_eal() -> &'static Eal {
    EAL.get_or_init(|| {
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
        crate::eal::init(args.iter().copied())
    })
}
