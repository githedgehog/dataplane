// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![deny(clippy::all, clippy::pedantic)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::must_use_candidate)] // Do not want to remove pub methods yet

mod old_impl;
pub use old_impl::*;
