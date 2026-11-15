// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![allow(unused)]
use std::sync::{Mutex, MutexGuard};

struct S { m: Mutex<u32> }

async fn tick() {}

struct FlowTableReadGuard<'a>(MutexGuard<'a, u32>);
impl S {
    fn read_table(&self) -> FlowTableReadGuard<'_> { FlowTableReadGuard(self.m.lock().unwrap()) }

    async fn held(&self) {
        let g = self.m.lock().unwrap();
        tick().await; // BAD: sync guard alive
    }
    async fn dropped(&self) {
        let g = self.m.lock().unwrap();
        drop(g);
        tick().await; // OK
    }
    async fn scoped(&self) {
        {
            let g = self.m.lock().unwrap();
        }
        tick().await; // OK: guard's block ended
    }
    async fn temporary(&self) {
        let v = *self.m.lock().unwrap();
        tick().await; // OK: temporary died with its statement
    }
    async fn custom_guard(&self) {
        let t = self.read_table();
        tick().await; // BAD: custom guard type
    }
    async fn in_option(&self) {
        let g = Some(self.m.lock().unwrap());
        tick().await; // BAD: guard kept alive inside Option
    }
    async fn nested_block(&self) {
        let g = self.m.lock().unwrap();
        let fut = async { tick().await }; // OK: this await suspends the inner future, not this one
        drop(g);
        fut.await; // OK
    }
    async fn suppressed(&self) {
        let g = self.m.lock().unwrap();
        // codeql[rust-guard-across-await]
        tick().await; // OK: suppressed
    }
}
