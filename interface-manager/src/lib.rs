// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Reconcile the intended state of the linux networking stack with its observed state.

#![deny(
    unsafe_code,
    missing_docs,
    clippy::all,
    clippy::pedantic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]
#![allow(missing_docs)] // multi-index-map generates undocumented structures
#![allow(clippy::unsafe_derive_deserialize)] // generated code uses unsafe

use std::marker::PhantomData;
use std::sync::Arc;

pub mod interface;
pub mod netns;

use rtnetlink::Handle;

/// `Manager` is the primary entry point to interface reconciliation logic.
///
/// It is a newtype wrapper around a netlink handle, with a `PhantomData<R>` use to allow
/// for multiple implementations of the `rekon` traits (based on the type `R`) which we are
/// reconciling.
#[derive(Clone, Debug)]
pub struct Manager<R: ?Sized> {
    handle: Arc<Handle>,
    _marker: PhantomData<R>,
}

impl<R> Manager<R> {
    /// Crate a new `Manager` from an [`Arc<Handle>`].
    #[must_use]
    pub fn new(handle: Arc<Handle>) -> Self {
        Manager {
            handle,
            _marker: PhantomData,
        }
    }
}

/// Convenience method for reducing syntactic noise when creating ephemeral `Manager` structs.
pub fn manager_of<T>(other: impl Into<Manager<T>>) -> Manager<T> {
    other.into()
}

impl<T, U> From<&Manager<T>> for Manager<U> {
    fn from(handle: &Manager<T>) -> Self {
        Self::new(handle.handle.clone())
    }
}
