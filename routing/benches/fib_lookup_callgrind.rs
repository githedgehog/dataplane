// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! The same fib lookup as `fib_lookup.rs`, counted instead of timed.
//!
//! Same fixtures, same shapes, same measured body -- all of it from `common`, so the two cannot
//! drift into answering different questions while still looking comparable.
//!
//! Callgrind executes the program on a synthetic machine and counts what it does: instructions
//! retired, and hits and misses against a modelled cache. That buys repeatability a wall-clock
//! benchmark cannot have -- no scheduler, no frequency scaling, no neighbours -- at the cost of
//! measuring a CPU nobody ships. See `development/code/benchmarking.md` for how far apart the two
//! answers were on a real change, and for where these tools should not be believed at all.

use std::hint::black_box;

use iai_callgrind::{
    Cachegrind, Dhat, LibraryBenchmarkConfig, library_benchmark, library_benchmark_group, main,
};

mod common;
use common::{Fixture, fixture, lookup};

// Acquiring the read guard, which the measured bodies below have to do and the criterion bench
// hoists out of its loop. Subtract this to compare the two.
#[library_benchmark]
#[bench::guard_only(args = (1, 1), setup = fixture)]
fn enter_only(fixture: &'static Fixture) {
    black_box(fixture.writer.enter().expect("fib is readable"));
}

/// Expand the shared shape list into one `#[bench::id(...)]` per shape.
///
/// The criterion bench loops over the same list; attributes cannot be looped over, which is why
/// the list is a macro rather than a `const`.
macro_rules! shape_benches {
    ($($id:ident = ($groups:expr, $entries:expr)),* $(,)?) => {
        #[library_benchmark]
        $(#[bench::$id(args = ($groups, $entries), setup = fixture)])*
        fn lpm_entry_prefix(fixture: &'static Fixture) {
            lookup(fixture);
        }
    };
}
for_each_shape!(shape_benches);

// The same lookup under the rest of the valgrind family, so the wiring is known to work before
// somebody needs it in a hurry.
//
// Cachegrind is given this machine's geometry rather than left to guess. It guesses L1 correctly
// anyway -- it reads `CPUID` -- but it collapses L2 and L3 into one "LL" and picks 8 MB where this
// host has a 32 MB L3, so the level that actually differs is worth stating. These values are this
// workstation's, not a target's; `lscpu --caches` prints them as size,ways,line. Deriving them
// from the host would make a CI result depend on which runner it landed on, which is worse than a
// number that is at least consistently one machine's.
#[library_benchmark(
    config = LibraryBenchmarkConfig::default()
        .tool(Cachegrind::default().args([
            "--D1=32768,8,64",
            "--I1=32768,8,64",
            "--LL=33554432,16,64",
        ]))
        .tool(Dhat::default())
)]
#[bench::g1_e1(args = (1, 1), setup = fixture)]
#[bench::g16_e4(args = (16, 4), setup = fixture)]
fn under_other_tools(fixture: &'static Fixture) {
    lookup(fixture);
}

library_benchmark_group!(
    name = fib_lookup;
    benchmarks = enter_only, lpm_entry_prefix, under_other_tools
);
main!(library_benchmark_groups = fib_lookup);
