// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Compiled-in sanitizer configuration.
//!
//! Sanitizer runtimes look up a handful of weakly-defined `extern "C"` hooks at
//! startup (e.g. `__tsan_default_suppressions`). By defining strong versions of
//! those hooks we bake our suppression lists and runtime options straight into
//! the binary: no external suppression file and no `TSAN_OPTIONS=...` env var is
//! required to run a sanitized `dataplane`.
//!
//! That matters because the sanitized image is deployed by machinery we do not
//! own. In VLAB the `dataplane` container is a `DaemonSet` whose environment is
//! fixed by the gateway controller, so there is no seam through which to pass
//! `TSAN_OPTIONS`. Keeping the configuration next to the code it configures
//! also keeps it reviewable in one place rather than spread across three
//! repositories (see `development/code/avoid-global-reasoning.md`).
//!
//! Each hook is gated on a `cfg` emitted by `build.rs` (which sniffs
//! `-Zsanitizer=<kind>` out of the rustflags), so the symbol is only present in
//! the matching sanitizer build. To add suppressions for another sanitizer,
//! register its rustflag token in `build.rs` and add the corresponding hook
//! here.
//!
//! Note that the runtime still reads the `TSAN_OPTIONS` environment variable,
//! and anything set there overrides what `__tsan_default_options` returns. These
//! are defaults, not a policy you have to fight.

#[cfg(sanitize_thread)]
#[unsafe(no_mangle)]
extern "C" fn __tsan_default_suppressions() -> *const core::ffi::c_char {
    // Trailing `"\0"` makes this a valid C string: the sanitizer hook returns a raw
    // `*const c_char` that the TSan runtime reads until a NUL, and `include_str!`
    // alone yields no terminator. `suppress.txt` never contains an interior NUL, so
    // the whole file survives to the terminator.
    concat!(include_str!("tsan.suppress"), "\0").as_ptr().cast()
}

/// Default `TSAN_OPTIONS` for a sanitized `dataplane`.
///
/// The runtime parses the `TSAN_OPTIONS` environment variable *after* this
/// string, so an operator can still override any of these at run time.
#[cfg(sanitize_thread)]
#[unsafe(no_mangle)]
extern "C" fn __tsan_default_options() -> *const core::ffi::c_char {
    // `exitcode=0` is the load-bearing one. TSan's default is to exit 66 once a
    // race has been reported, which for a long-lived daemon under a supervisor
    // (k8s `DaemonSet`, systemd, ...) turns "we found a race" into a restart
    // loop. The restart both destroys the evidence -- `crictl logs` without
    // `-p` only shows the current container -- and disguises the finding as an
    // unrelated liveness failure. We would rather keep running and leave the
    // report on stderr where log collection can find it.
    //
    // `halt_on_error=0` is already the default; it is spelled out because it is
    // the other half of the same intent and we do not want a future runtime
    // default flip to change behavior silently.
    //
    // Deliberately *not* set here:
    //   - `log_path`: reports must go to stderr so they land in container logs.
    //   - `history_size`: raising it buys deeper "previous access" stacks at a
    //     real memory cost, and memory is the binding constraint on the VLAB
    //     gateway VM. Set it via the env var when you need the depth.
    //   - `detect_deadlocks=1` (plus `second_deadlock_stack=1`): on-topic for
    //     lock-order hunting, but the detector is noisy enough that it should
    //     be an explicit opt-in rather than baked into every sanitized image.
    c"exitcode=0 halt_on_error=0".as_ptr().cast()
}
