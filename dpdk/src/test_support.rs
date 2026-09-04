// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use concurrency::sync::OnceLock;

use crate::eal::{Eal, EalShared};

/// The shared projection of the process-wide test EAL.
///
/// The projection rather than the [`Eal`] itself: `Eal` is `!Send + !Sync` (it stays on the
/// thread that initialised it), and a `static` requires both. The owning handle is leaked below,
/// which is what makes the `'static` projection sound.
static EAL: OnceLock<EalShared<'static>> = OnceLock::new();

/// Initialise the process-wide test EAL, once, and return a shared handle to it.
///
/// Every `#[with_eal]` test funnels through here. Note this deliberately never tears the EAL
/// down: the owning [`Eal`] is leaked, so neither the mempool registry nor `rte_eal_cleanup` runs
/// at the end of a test binary. That was already true when this held the `Eal` in a `OnceLock`
/// (which never drops its contents either) and is fine for a process about to exit -- but it does
/// mean the teardown path is not exercised by unit tests.
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
