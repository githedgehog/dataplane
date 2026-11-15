// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors
#![allow(unused)]

/// Stand-in for `tokio::task::spawn_blocking`: matched by name.
fn spawn_blocking<F: FnOnce() -> R, R>(f: F) -> R {
    f()
}

async fn tick() {}

async fn direct() {
    let cfg = std::fs::read_to_string("/etc/x"); // BAD: fs in async code
    std::thread::sleep(std::time::Duration::from_millis(1)); // BAD: thread
    tick().await;
}

fn load_config() -> String {
    std::fs::read_to_string("/etc/y").unwrap_or_default() // BAD: reached from async code
}

async fn indirect() {
    let c = load_config();
    tick().await;
}

async fn offloaded() {
    let c = spawn_blocking(|| std::fs::read_to_string("/etc/z")); // OK: off the executor
    let h = std::thread::spawn(|| std::fs::read("/etc/w")); // OK: own thread
    tick().await;
}

fn sync_only() {
    let c = std::fs::read("/etc/v"); // OK: never runs on the executor
}

async fn suppressed() {
    // codeql[rust-blocking-in-async]
    let c = std::fs::read("/etc/u"); // OK: suppressed
}
