#![cfg(dataplane_concurrency_slot = "fallback")]

use crate::sync::{Arc, Mutex};

pub struct Slot<T>(Mutex<Arc<T>>);

impl<T> Slot<T> {
    pub fn from_pointee(value: T) -> Self {
        Self(Mutex::new(Arc::new(value)))
    }

    pub fn load_full(&self) -> Arc<T> {
        Arc::clone(&self.0.lock())
    }

    pub fn swap(&self, new: Arc<T>) -> Arc<T> {
        let mut guard = self.0.lock();
        core::mem::replace(&mut *guard, new)
    }
}
