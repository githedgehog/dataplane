// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors
// Fixture for rust-no-direct-std-sync-import. `BAD` lines must be reported,
// `OK` lines must not.
#![allow(unused)]

use std::sync::Arc; // BAD: plain import
use std::sync::atomic::AtomicU64; // BAD: atomic::X
use std::sync::{Mutex, mpsc}; // BAD: Mutex in a group; OK: mpsc is not guarded
use std::{
    collections::HashMap,
    sync::{atomic::Ordering, RwLock}, // BAD x2: nested group (opengrep 1.x missed this)
};
use std::sync::mpsc::channel; // OK: mpsc is not guarded
use std::time::Duration; // OK: not std::sync

use std::sync::Weak; // nosemgrep: rust-no-direct-std-sync-import
// nosemgrep: rust-no-direct-std-sync-import
use std::sync::OnceLock; // OK: suppressed by the line above
use std::sync::Barrier; // codeql[rust-no-direct-std-sync-import]
use std::sync::Condvar; // nosemgrep: some-other-rule  BAD: wrong rule id

mod facade {
    pub mod sync {
        pub use std::sync::Arc as FacadeArc; // BAD: still spelled std::sync
    }
}
use facade::sync::FacadeArc; // OK: through a facade

fn uses() {
    let a = std::sync::Arc::new(1); // BAD: fully qualified
    let b = std::sync::LazyLock::new(|| 2); // BAD: fully qualified
    let c = std::sync::atomic::AtomicBool::new(false); // BAD: atomic
    let d = Arc::new(3); // OK: name only, the import is what is reported
    // std::sync::Arc in a comment: OK
}

// Shapes the workspace uses for suppressions (see concurrency/src/process_global.rs).
#[allow(clippy::disallowed_types)]
// nosemgrep: rust-no-direct-std-sync-import
pub use std::sync::{
    Once, PoisonError, // OK: a multi-line group is one match anchored at `use`
    RwLockReadGuard,
};

struct Holder {
    // nosemgrep: rust-no-direct-std-sync-import
    inner: std::sync::Mutex<u8>, // OK: standalone comment above a field
    other: std::sync::RwLock<u8>, // BAD: the suppression above is for the line before
}

fn in_macro_args() {
    assert!(std::sync::Arc::strong_count(&std::sync::Arc::new(1)) == 1); // BAD x2: macro arguments are source text
}
