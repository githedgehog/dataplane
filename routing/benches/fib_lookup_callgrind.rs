// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! The same fib lookup as `fib_lookup.rs`, counted instead of timed.
//!
//! Callgrind executes the program on a synthetic machine and counts what it does: instructions
//! retired, and hits and misses against a modelled cache hierarchy. That buys repeatability a
//! wall-clock benchmark cannot have -- no scheduler, no frequency scaling, no neighbours -- at the
//! cost of measuring a CPU nobody ships. It does not model this machine's out-of-order execution,
//! it has no AVX-512, and its cache model is a simplification of any real one.
//!
//! So the numbers here are not predictions of time. They are useful for two things: catching a
//! change in how much *work* a path does, which is stable enough to gate in CI; and, read next to
//! `fib_lookup.rs`, showing where counting and timing disagree -- which is where a real machine's
//! behaviour is doing something the model cannot see.
//!
//! The fixtures are deliberately identical to the criterion bench so the two can be compared.
//!
//! `development/code/benchmarking.md` measures how far apart the two harnesses get on a real
//! change, and records what the other valgrind tools do and do not scope to. Read it before
//! pointing any of them at DPDK: valgrind reports a CPU it can emulate, so `rte_acl` runs to
//! completion having executed no AVX-512 at all.

use std::hint::black_box;

use iai_callgrind::{
    Cachegrind, Dhat, LibraryBenchmarkConfig, library_benchmark, library_benchmark_group, main,
};

mod common;
use common::{Fixture, fixture, lookup};

#[library_benchmark]
#[bench::guard_only(args = (1, 1), setup = fixture)]
fn enter_only(fixture: &'static Fixture) {
    black_box(fixture.writer.enter().expect("fib is readable"));
}

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
