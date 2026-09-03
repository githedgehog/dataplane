// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

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
