#![cfg(dataplane_concurrency_slot = "default")]

use crate::sync::Arc;
use arc_swap::ArcSwap;

#[repr(transparent)]
pub struct Slot<T>(ArcSwap<T>);

impl<T> Slot<T> {
    #[inline]
    pub fn from_pointee(value: T) -> Self {
        Self(ArcSwap::from_pointee(value))
    }

    #[inline]
    pub fn load_full(&self) -> Arc<T> {
        self.0.load_full()
    }

    #[inline]
    pub fn swap(&self, new: Arc<T>) -> Arc<T> {
        self.0.swap(new)
    }
}
