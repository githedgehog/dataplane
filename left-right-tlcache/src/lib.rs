// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Small crate to provide thread-local storage of left-right "read handles".
//! TL;DR: the `ReadHandle<T>` type that allows concurrent reads over some type T cannot
//! be safely shared among distinct threads. There are cases where multiple threads may need
//! to read multiple T's but the set of T's (and read handles) may not be known upfront and
//! change over time.
//!
//! So, a mechanism is needed to:
//!    - ensure that threads discover read handles for multiple instances of T
//!    - ensure they are provided with non-shared read handles for those T's
//!
//! This crate provides a type to that end that relies on a thread-local cache of read-handles.
//! Having a thread-local set of read-handles avoids the potentially-expensive creation of those
//! every time an instance of T needs to be read (e.g. a FIB). This type assumes that each of the
//! T instances (or their handles) can be identified by some Key. In order to populate the local
//! cache of read handles a read-handle "provider" is needed. Neither the key types, T or the provider
//! are prescribed here. The provider functionality is implemented as a trait.
//!
//! An alternative approach to the problem would use `thread_local::ThreadLocal<Q>`. However, the latter
//! requires Q to be `Send`, which is not necessarily the case of `ReadHandle<T>`. Specifically,
//! `ReadHandle<T>` is Send only if T is Sync.
//!
//! The use of this type requires:
//!   - implementing trait `ReadHandleProvider` to provide `ReadHandle<T>` 's based on some key value.
//!   - implementing trait `Identity` for T in `ReadHandle<T>`
//!   - declaring a thread-local `ReadHandleCache` object
//!
//! Note: providers must be Sync since the thread-local caches for distinct threads will poll them.

use ahash::RandomState;
use left_right::{ReadHandle, ReadHandleFactory};
use std::cell::RefCell;
use std::collections::HashMap;
use std::hash::Hash;
use std::rc::Rc;
use std::thread::LocalKey;
use thiserror::Error;

pub trait ReadHandleProvider: Sync {
    type Data;
    type Key;

    /// A provider should provide per thread `ReadHandles`. However, it is safer if we require providers
    /// to give us factories as that shields us from buggy providers returning ReadHandles that are not
    /// unique per thread. There should be no performance penalty of offering factories instead of read handles
    /// since factory::handle() is identical to rhandle::clone()
    #[allow(clippy::type_complexity)]
    fn get_factory(
        &self,
        key: &Self::Key,
    ) -> Option<(&ReadHandleFactory<Self::Data>, Self::Key, u64)>;

    /// Ask the provider about the identity of T for the `ReadHandle<T>` accessible via some key.
    /// This is needed for the cache to be able to invalidate entries that point to `ReadHandle<T>`'s
    /// for T's that should no longer be accessed by that key.
    fn get_identity(&self, key: &Self::Key) -> Option<Self::Key>;

    /// Get version. Provider should promise to provide a distinct value (e.g. monotonically increasing)
    /// anytime there's a change in the collection of read handles / factories it owns.
    fn get_version(&self) -> u64;
}

/// Trait to determine the real identity of a `T` wrapped in left-right. That is,
/// the identity of `T` in a `ReadHandle<T>`. This is needed to invalidate cache entries
/// with keys that are alias of their identity.
pub trait Identity<K> {
    fn identity(&self) -> K;
}

#[derive(Debug, PartialEq, Error)]
pub enum ReadHandleCacheError<K> {
    #[error("Reader not found for key {0}")]
    NotFound(K),
    #[error("Reader for key {0} is not accessible")]
    NotAccessible(K),
}

/// An entry in a thread-local `ReadHandleCache<K,T>` to hold a `ReadHandle<T>`
/// along with its identity, which may match the key to find it or not.
struct ReadHandleEntry<T, K> {
    rhandle: Rc<ReadHandle<T>>,
    identity: K,
    version: u64,
}
impl<T: Identity<K>, K: PartialEq> ReadHandleEntry<T, K> {
    fn new(identity: K, rhandle: Rc<ReadHandle<T>>, version: u64) -> Self {
        Self {
            rhandle,
            identity,
            version,
        }
    }
    fn is_valid(&self, key: &K, provider: &impl ReadHandleProvider<Data = T, Key = K>) -> bool {
        if self.rhandle.was_dropped() {
            return false;
        }
        if *key == self.identity {
            return true;
        }
        if self.version == provider.get_version() {
            return true;
        }
        let Some(identity) = provider.get_identity(key) else {
            return false;
        };
        if self.identity != identity {
            return false;
        }
        // this is just extra sanity
        match self.rhandle.enter() {
            Some(t) => t.identity() == identity,
            None => false,
        }
    }
}

pub struct ReadHandleCache<K: Hash + Eq + Clone, T> {
    handles: RefCell<HashMap<K, ReadHandleEntry<T, K>, RandomState>>,
}
impl<K, T> ReadHandleCache<K, T>
where
    K: Hash + Eq + Clone,
    T: Identity<K>,
{
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            handles: RefCell::new(HashMap::with_hasher(RandomState::with_seed(0))),
        }
    }
    pub fn get_reader(
        thread_local: &'static LocalKey<Self>,
        key: K,
        provider: &impl ReadHandleProvider<Data = T, Key = K>,
    ) -> Result<Rc<ReadHandle<T>>, ReadHandleCacheError<K>> {
        thread_local.with(|local| {
            let mut map = local.handles.borrow_mut();

            // cache has a valid handle for that key
            if let Some(entry) = map.get(&key)
                && entry.is_valid(&key, provider)
            {
                return Ok(Rc::clone(&entry.rhandle));
            }

            let result = {
                // get a factory for the key from the provider to build a fresh handle from it
                // provider returns identity of object and version for entry invalidation
                let (factory, identity, version) = provider
                    .get_factory(&key)
                    .ok_or_else(|| ReadHandleCacheError::NotFound(key.clone()))?;

                // store a new entry locally with a handle, its identity and version, for the given key
                let rhandle = Rc::new(factory.handle());
                let entry = ReadHandleEntry::new(identity.clone(), Rc::clone(&rhandle), version);
                map.insert(key.clone(), entry);

                Ok(rhandle)
            };
            if result.is_err() {
                // clean-up cache on failure
                map.remove(&key);
            }
            result
        })
    }
}

/// Create a thread-local `ReadHandleCache` with a given name, to access
/// `ReadHandle<T>`'s identified with some type of key.
/// Example:
/// ```
/// use left_right::{ReadHandle, ReadHandleFactory};
/// use dataplane_left_right_tlcache::make_thread_local_readhandle_cache;
/// use dataplane_left_right_tlcache::ReadHandleCache;
/// use dataplane_left_right_tlcache::Identity;
///
/// struct LeftRightWrappedType;
/// impl Identity<u32> for LeftRightWrappedType {
///     fn identity(&self) -> u32 {0}
/// }
///
/// make_thread_local_readhandle_cache!(MYCACHE, u32, LeftRightWrappedType);
/// ```
#[macro_export]
macro_rules! make_thread_local_readhandle_cache {
    ($name:ident, $key_t:ty, $rhandle_t:ty) => {
        thread_local! {
            static $name: ReadHandleCache<$key_t, $rhandle_t> = ReadHandleCache::new();
        }
    };
}
