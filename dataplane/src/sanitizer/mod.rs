// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Compiled-in sanitizer configuration.
//!
//! Sanitizer runtimes look up a handful of weakly-defined `extern "C"` hooks at
//! startup (e.g. `__tsan_default_suppressions`). By defining strong versions of
//! those hooks we bake our suppression lists straight into the binary: no
//! external suppression file and no `TSAN_OPTIONS=suppressions=...` env var is
//! required to run a sanitized `dataplane`.
//!
//! Each hook is gated on a `cfg` emitted by `build.rs` (which sniffs
//! `-Zsanitizer=<kind>` out of the rustflags), so the symbol is only present in
//! the matching sanitizer build. To add suppressions for another sanitizer,
//! register its rustflag token in `build.rs` and add the corresponding hook
//! here.

#[cfg(sanitize_thread)]
#[unsafe(no_mangle)]
extern "C" fn __tsan_default_suppressions() -> *const core::ffi::c_char {
    // Trailing `"\0"` makes this a valid C string: the sanitizer hook returns a raw
    // `*const c_char` that the TSan runtime reads until a NUL, and `include_str!`
    // alone yields no terminator. `suppress.txt` never contains an interior NUL, so
    // the whole file survives to the terminator.
    #[cfg(sanitize_thread)]
    const SUPPRESSIONS: &str = concat!(include_str!("./tsan.suppress"), "\0");

    SUPPRESSIONS.as_ptr().cast()
}
