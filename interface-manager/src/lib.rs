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

use crate::interface::TapRegistry;
use concurrency::sync::Arc;
use std::marker::PhantomData;

pub mod interface;
pub mod monitor;
pub mod tc;

use rtnetlink::Handle;

/// `Manager` is the primary entry point to interface reconciliation logic.
///
/// It is a newtype wrapper around a netlink handle, with a `PhantomData<R>` use to allow
/// for multiple implementations of the `rekon` traits (based on the type `R`) which we are
/// reconciling.
#[derive(Clone, Debug)]
pub struct Manager<R: ?Sized> {
    handle: Arc<Handle>,
    taps: Arc<TapRegistry>,
    _marker: PhantomData<R>,
}

impl<R> Manager<R> {
    /// Create a new `Manager` from an [`Arc<Handle>`] and the registry of tap devices this
    /// process holds open.
    ///
    /// The registry is shared rather than owned.  A tap device lives exactly as long as somebody
    /// holds its descriptor, so every manager derived from this one has to reach the same
    /// registry; were each to have its own, a tap created through one manager would be destroyed
    /// by the drop of another.
    #[must_use]
    pub fn new(handle: Arc<Handle>, taps: Arc<TapRegistry>) -> Self {
        Manager {
            handle,
            taps,
            _marker: PhantomData,
        }
    }
}

/// Convenience method for reducing syntactic noise when creating ephemeral `Manager` structs.
pub fn manager_of<T>(other: impl Into<Manager<T>>) -> Manager<T> {
    other.into()
}

impl<T, U> From<&Manager<T>> for Manager<U> {
    fn from(other: &Manager<T>) -> Self {
        Self::new(other.handle.clone(), other.taps.clone())
    }
}
