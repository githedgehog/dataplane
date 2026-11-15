// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![allow(unused)]
use std::sync::Mutex;

struct Bank { a: Mutex<u32>, b: Mutex<u32> }

impl Bank {
    fn a_then_b(&self) {
        let ga = self.a.lock().unwrap();
        let gb = self.b.lock().unwrap(); // BAD: a -> b
    }
    fn b_then_a(&self) {
        let gb = self.b.lock().unwrap();
        self.take_a(); // BAD: b -> a, through a call
    }
    fn take_a(&self) { *self.a.lock().unwrap() += 1; }

    fn reentrant(&self) {
        let ga = self.a.lock().unwrap();
        self.take_a(); // BAD: a while a is held
    }
    fn dropped_first(&self) {
        let ga = self.a.lock().unwrap();
        drop(ga);
        let gb = self.b.lock().unwrap(); // OK: a was dropped
    }
    fn if_condition(&self) {
        if *self.b.lock().unwrap() > 0 {
            self.take_a(); // OK: the condition's temporary guard is gone
        }
    }
}

fn suppressed(bank: &Bank) {
    let ga = bank.a.lock().unwrap();
    // codeql[rust-lock-order]
    bank.take_a(); // OK: suppressed
}

mod tests {
    use super::*;
    fn two_instances(x: &Bank, y: &Bank) {
        let g = x.a.lock().unwrap();
        let h = y.a.lock().unwrap(); // OK: test code
    }
}
