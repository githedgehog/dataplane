// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! `config` takes the path of a `const`, not an inline value.
//!
//! Accepting an expression here would work, but it would put the
//! configuration back inside an attribute -- which is the one place an
//! editor cannot offer completion, hover, or go-to-definition on it.
//! Requiring a named item is what keeps the value in ordinary Rust.

#[n_vm::test(config = 42)]
fn config_must_be_a_path() {}

fn main() {}
