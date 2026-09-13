// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! On-demand dump of a profile-instrumented build's counters.
//!
//! A `-Cprofile-generate` build writes its counters from an `atexit` handler, which the dataplane
//! never reaches: it runs until something kills it, and a kill loses them. `SIGUSR1` asks for them
//! without stopping, so a profile can be taken from a run that is still under load -- which is the
//! only run whose profile is worth anything.
//!
//! The signal arrives via `dataplane-init`, which forwards it to the process it supervises; see
//! `DATAPLANE_DEV_PROFILE_DUMP` there. Where the counters land is `LLVM_PROFILE_FILE`'s business,
//! not ours.

/// Write the counters collected so far.
///
/// Gated on `profile_generate`, which [`nix/profiles.nix`] sets from the same `instrumentation`
/// argument that adds `-Cprofile-generate`. The cfg and the flag cannot come apart, so the symbol
/// this needs is present whenever the call is compiled.
#[cfg(profile_generate)]
pub fn dump() {
    use tracing::{error, info};

    // SAFETY: `__llvm_profile_write_file` comes from the profiling runtime that
    // `-Cprofile-generate` links in. Writing is serialised by that runtime, so calling it while
    // the datapath keeps running is safe -- the counters are merely a snapshot, which is what we
    // want. It returns 0 on success and non-zero when it could not write.
    let rc = unsafe {
        unsafe extern "C" {
            fn __llvm_profile_write_file() -> core::ffi::c_int;
        }
        __llvm_profile_write_file()
    };
    if rc == 0 {
        info!("wrote profile counters");
    } else {
        // Almost always `LLVM_PROFILE_FILE` naming a directory that does not exist or is not
        // writable. Worth saying out loud: the signal is otherwise silent, and a profile that was
        // never written looks exactly like one that was.
        error!("could not write profile counters: __llvm_profile_write_file returned {rc}");
    }
}

/// Say so, rather than leaving a requested dump to look like it happened.
#[cfg(not(profile_generate))]
pub fn dump() {
    tracing::warn!(
        "asked to dump profile counters, but this build has none: \
         rebuild with `instrumentation=pgo`"
    );
}
