// SPDX-License-Identifier: MIT
//! Network interface management tools for the dataplane

#![deny(
    unsafe_code,
    missing_docs,
    clippy::all,
    clippy::pedantic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]
#![allow(unsafe_code)] // we panic in contract checks with simple unwrap()
#![allow(missing_docs)] // TEMPORARY: block merge
#![allow(clippy::unsafe_derive_deserialize)] // generated code uses unsafe

use std::marker::PhantomData;
use std::sync::Arc;

pub mod interface;

use rtnetlink::Handle;

#[derive(Clone, Debug)]
pub struct Manager<R> {
    handle: Arc<Handle>,
    _marker: PhantomData<R>,
}

impl<R> Manager<R> {
    #[must_use]
    pub fn new(handle: Arc<Handle>) -> Self {
        Manager {
            handle,
            _marker: PhantomData,
        }
    }
}

pub fn manager_of<T>(other: impl Into<Manager<T>>) -> Manager<T> {
    other.into()
}

impl<T, U> From<&Manager<T>> for Manager<U> {
    fn from(handle: &Manager<T>) -> Self {
        Self::new(handle.handle.clone())
    }
}
