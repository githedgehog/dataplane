// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Runtime helpers called by code generated from `#[n_vm::test]`.
//!
//! The macro keeps only tier selection in generated code. Container launch,
//! VM launch, runtime setup, and error formatting live here as normal Rust.

use std::future::Future;

use crate::backend::{EffectiveBackend, HypervisorBackend};
use crate::config::{Accel, GuestRuntime, VmConfig};
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

/// Runs an async test body on the runtime its configuration asked for.
///
/// One entry point rather than one per scheduler, because the choice now
/// lives in a `const` the macro cannot read: a proc macro can branch on a
/// token but not on a value.  The shape is a [`GuestRuntime`], so the match
/// happens here, in ordinary code, where it can be tested.
///
/// # Panics
///
/// Panics if the tokio runtime cannot be created.
pub fn block_on_in_guest_with<F: Future<Output = ()>>(runtime: GuestRuntime, f: F) {
    let mut builder = match runtime {
        GuestRuntime::CurrentThread => tokio::runtime::Builder::new_current_thread(),
        GuestRuntime::MultiThread { .. } => tokio::runtime::Builder::new_multi_thread(),
    };
    builder.enable_all();
    if let GuestRuntime::MultiThread {
        worker_threads: Some(n),
    } = runtime
    {
        builder.worker_threads(n);
    }
    builder
        .build()
        .expect("failed to build tokio runtime for async #[n_vm::test] test body")
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
        .expect("failed to build tokio runtime for #[n_vm::test] container tier");

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
/// The backend the test asked for comes from `vm_config`.  It is
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
pub fn run_host_tier<F: FnOnce()>(test_fn: F, vm_config: VmConfig) {
    eprintln!("===== BEGIN NESTED TEST ENVIRONMENT =====");

    let outcome = crate::run_test_in_vm(test_fn, vm_config).unwrap_or_else(|err| {
        panic!(
            "test container infrastructure error:\n{:?}",
            miette::Report::new(err)
        )
    });

    eprintln!("=====  END NESTED TEST ENVIRONMENT  =====");

    match outcome {
        ContainerOutcome::Skipped { reason } => {
            report_skip(
                crate::test_identity::TestIdentity::resolve::<F>().test_name,
                &reason,
            );
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

/// Records a skipped test, and fails it when the run does not tolerate
/// skips.
///
/// libtest has no run-time "skipped" state: `#[ignore]` is a compile-time
/// decision, so a test that skips here is counted as **passed**, and the
/// reason it printed is swallowed by output capture unless the test also
/// fails.  A profile can therefore skip nearly everything and still report
/// a clean run -- which is exactly what a Flatcar run does today, where 12
/// of 16 "passes" never boot a VM.
///
/// So the reason is written somewhere that survives: a file named by
/// [`ENV_SKIP_LOG`], outside libtest's capture and outside the
/// process-per-test model, so a whole run's skips accumulate in one place
/// CI can assert on.
///
/// [`ENV_STRICT_SKIPS`] turns a skip into a failure, for a run that is
/// meant to exercise everything and where a skip is a hole in what is being
/// certified rather than a neutral outcome.
fn report_skip(test_name: &str, reason: &str) {
    eprintln!("SKIPPED: {reason}");

    if let Ok(path) = std::env::var(n_vm_protocol::ENV_SKIP_LOG)
        && !path.is_empty()
    {
        // Appended, not rewritten: nextest runs each test in its own
        // process, so the records of one run arrive from many writers.
        // `O_APPEND` keeps single short writes from interleaving.
        use std::io::Write as _;
        let record = format!(
            "{{\"test\":{},\"profile\":{},\"reason\":{}}}\n",
            json_string(test_name),
            json_string(&std::env::var(n_vm_protocol::ENV_PROFILE).unwrap_or_default()),
            json_string(reason),
        );
        // Best-effort: failing to record a skip must not turn a skip into a
        // failure, which would be a worse outcome than the missing record.
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
        {
            let _ = f.write_all(record.as_bytes());
        }
    }

    if std::env::var(n_vm_protocol::ENV_STRICT_SKIPS).is_ok_and(|v| !v.is_empty()) {
        panic!(
            "test skipped, and {} is set: {reason}",
            n_vm_protocol::ENV_STRICT_SKIPS,
        );
    }
}

/// Minimal JSON string escaping, to avoid a serde dependency in a path
/// that writes at most a few dozen short records per run.
fn json_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod test {
    use super::json_string;

    /// A skip reason is free text that ends up inside a JSON record, and
    /// the reasons already contain backticks and quotes.  Escaping wrong
    /// would produce a log that no parser can read -- silently, since
    /// nothing reads it during the run that wrote it.
    #[test]
    fn escapes_quotes_and_backslashes() {
        assert_eq!(json_string(r#"a "quoted" word"#), r#""a \"quoted\" word""#);
        assert_eq!(json_string(r"back\slash"), r#""back\\slash""#);
    }

    #[test]
    fn escapes_control_characters() {
        assert_eq!(json_string("line\nbreak"), r#""line\nbreak""#);
        assert_eq!(json_string("tab\there"), r#""tab\there""#);
        // Anything else below 0x20 has no short form and must be \uXXXX.
        assert_eq!(json_string("\u{1}"), r#""\u0001""#);
    }

    /// Reason strings routinely carry backticks and paths; those are
    /// ordinary characters and must survive untouched.
    #[test]
    fn leaves_ordinary_text_alone() {
        let reason = "kernel profile `flatcar` runs on qemu; use N_VM_PROFILE=<name>";
        assert_eq!(json_string(reason), format!("\"{reason}\""));
    }
}
