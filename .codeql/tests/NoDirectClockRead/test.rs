// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors
// Fixture for rust-no-direct-clock-read.
#![allow(unused)]

use std::time::{Instant, SystemTime};

mod clock {
    pub use std::time::Instant;
    pub fn now() -> Instant {
        Instant::now() // BAD here: the real exclusion is by path (clock/src/)
    }
}

struct Stopwatch;
impl Stopwatch {
    fn elapsed(&self) -> u64 {
        0
    }
}

fn reads() {
    let a = Instant::now(); // BAD
    let b = std::time::Instant::now(); // BAD
    let c = SystemTime::now(); // BAD
    let d = std::time::SystemTime::now(); // BAD
    let e = a.elapsed(); // BAD: Instant::elapsed reads the clock
    let f = Stopwatch.elapsed(); // BAD: opengrep matches any receiver
    let g = clock::now(); // OK: the facade
    let h = clock::Instant::now(); // BAD: resolves to std even through the re-export
    let i = Instant::now(); // nosemgrep: rust-no-direct-clock-read
    let j = a.checked_add(std::time::Duration::from_secs(1)); // OK
}

fn in_macro_args() {
    // nosemgrep: rust-no-direct-clock-read
    let a = Instant::now(); // OK: standalone comment above
    assert!(Instant::now() >= a); // BAD: macro arguments are source text
}
