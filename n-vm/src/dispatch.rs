// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Runtime helpers called by code generated from `#[in_vm]`.
//!
//! The macro keeps only tier selection in generated code. Container launch,
//! VM launch, runtime setup, and error formatting live here as normal Rust.

use std::future::Future;

use crate::backend::{EffectiveBackend, HypervisorBackend, RequestedBackend};
use crate::config::{Accel, VmConfig};
use crate::container::ContainerOutcome;
use n_vm_protocol::{ENV_ACCEL, ENV_BACKEND, ENV_IN_TEST_CONTAINER, ENV_IN_VM, ENV_MARKER_VALUE};

/// Returns `true` when running inside the VM guest.
#[inline]
pub fn is_in_vm() -> bool {
    std::env::var(ENV_IN_VM).as_deref() == Ok(ENV_MARKER_VALUE)
}

/// Returns `true` when running inside the Docker container tier.
#[inline]
pub fn is_in_test_container() -> bool {
    std::env::var(ENV_IN_TEST_CONTAINER).as_deref() == Ok(ENV_MARKER_VALUE)
}

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_thread_names(true)
        .without_time()
        .with_test_writer()
        .with_line_number(true)
        .with_target(true)
        .with_file(true)
        .try_init();
}

/// Runs an async test body on a current-thread runtime inside the VM guest.
///
/// # Panics
///
/// Panics if the tokio runtime cannot be created.
pub fn block_on_in_guest<F: Future<Output = ()>>(f: F) {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to build tokio runtime for async #[in_vm] test body")
        .block_on(f);
}

/// Runs an async test body on a multi-threaded runtime inside the VM guest.
///
/// # Panics
///
/// Panics if the tokio runtime cannot be created.
pub fn block_on_in_guest_multi_thread<F: Future<Output = ()>>(worker_threads: Option<usize>, f: F) {
    let mut builder = tokio::runtime::Builder::new_multi_thread();
    builder.enable_all();
    if let Some(n) = worker_threads {
        builder.worker_threads(n);
    }
    builder
        .build()
        .expect("failed to build multi-threaded tokio runtime for async #[in_vm] test body")
        .block_on(f);
}

/// Container-tier dispatch: boot a VM and re-execute the test inside it.
///
/// The backend and acceleration mode were resolved by the host tier and
/// passed in via [`ENV_BACKEND`] / [`ENV_ACCEL`]; this reads them and
/// dispatches to the right backend so the choice is not baked in at
/// compile time.  An absent/unrecognised backend defaults to
/// cloud-hypervisor (the historical default).
///
/// # Panics
///
/// Panics if:
/// - The tokio runtime cannot be created.
/// - The VM infrastructure returns an error.
/// - The test running inside the VM reports failure.
pub fn run_container_tier<F: FnOnce()>(test_fn: F, vm_config: VmConfig) {
    let backend = EffectiveBackend::from_env(std::env::var(ENV_BACKEND).ok().as_deref());
    let accel = Accel::from_env(std::env::var(ENV_ACCEL).ok().as_deref());

    match backend {
        EffectiveBackend::Qemu => {
            run_container_tier_for::<crate::Qemu, _>(test_fn, vm_config, accel);
        }
        EffectiveBackend::CloudHypervisor => {
            run_container_tier_for::<crate::CloudHypervisor, _>(test_fn, vm_config, accel);
        }
    }
}

/// Monomorphised container-tier body for a single backend.
fn run_container_tier_for<B: HypervisorBackend, F: FnOnce()>(
    test_fn: F,
    vm_config: VmConfig,
    accel: Accel,
) {
    // Invariant: a TCG (cross-arch) run must use an emulation-capable
    // backend.  The host tier never selects a non-emulating backend for
    // TCG, but assert it here so a future regression surfaces loudly.
    debug_assert!(
        B::CAN_EMULATE || accel == Accel::Kvm,
        "backend `{}` cannot emulate, but TCG acceleration was selected",
        B::NAME,
    );

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .expect("failed to build tokio runtime for #[in_vm] container tier");

    let _guard = runtime.enter();

    runtime.block_on(async {
        init_tracing();

        let init_span = tracing::span!(tracing::Level::INFO, "hypervisor");
        let _guard = init_span.enter();

        let output = crate::run_in_vm::<B, _>(test_fn, vm_config, accel)
            .await
            .unwrap_or_else(|err| {
                panic!("VM infrastructure error:\n{:?}", miette::Report::new(err))
            });

        eprintln!("{output}");
        assert!(output.success, "VM test failed (see output above)");
    });
}

/// Host-tier dispatch: launch a Docker container and re-run the test inside it.
///
/// `requested` is the backend the test asked for via `#[in_vm]`.  It is
/// resolved against the Docker daemon's architecture and the requested
/// capabilities: a cross-arch guest runs under QEMU/TCG, a test that
/// *explicitly* requires cloud-hypervisor on a cross-arch host is skipped,
/// and a test requesting a capability the guest ISA can't provide (e.g.
/// a virtual IOMMU on aarch64) is skipped.
///
/// Skips are reported by returning normally with a `SKIPPED:` log line --
/// libtest/nextest have no runtime "ignored" state, so a skipped test
/// counts as passed.  This keeps cross-arch runs honest by minimising
/// skips: only the unsupported combinations are affected; everything else
/// runs under emulation.
///
/// # Panics
///
/// Panics if:
/// - The Docker container infrastructure returns an error.
/// - The container exits with a non-zero code.
/// - The container does not report an exit code at all.
pub fn run_host_tier<F: FnOnce()>(test_fn: F, requested: RequestedBackend, vm_config: VmConfig) {
    eprintln!("===== BEGIN NESTED TEST ENVIRONMENT =====");

    let outcome = crate::run_test_in_vm(test_fn, requested, vm_config).unwrap_or_else(|err| {
        panic!(
            "test container infrastructure error:\n{:?}",
            miette::Report::new(err)
        )
    });

    eprintln!("=====  END NESTED TEST ENVIRONMENT  =====");

    match outcome {
        ContainerOutcome::Skipped { reason } => {
            eprintln!("SKIPPED: {reason}");
        }
        ContainerOutcome::Ran(state) => match state.exit_code {
            Some(0) => {}
            Some(code) => {
                panic!("test container exited with code {code}");
            }
            None => {
                panic!("test container did not return an exit code");
            }
        },
    }
}
