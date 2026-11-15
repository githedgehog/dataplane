// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors
// Fixture for rust-no-clock-read-in-drop.
#![allow(unused)]

mod clock {
    pub fn now() -> u64 {
        0
    }
    pub fn system_now() -> u64 {
        0
    }
}
use clock::now;

struct A;
impl Drop for A {
    fn drop(&mut self) {
        let t = clock::now(); // BAD
        let w = clock::system_now(); // BAD
        let f = || clock::now(); // BAD: closures inside drop count
        let n = now(); // BAD: imported name, opengrep cannot see this one
        let s = clock::now(); // nosemgrep: rust-no-clock-read-in-drop
    }
}

struct B;
impl B {
    fn drop(&mut self) {
        let t = clock::now(); // BAD: opengrep matches any `fn drop(&mut self)`
    }
    fn close(&mut self) {
        let t = clock::now(); // OK: not drop
    }
}

fn drop(x: u32) {
    let t = clock::now(); // OK: not `drop(&mut self)`
}
