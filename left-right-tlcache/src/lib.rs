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
//!   - declaring a thread-local `ReadHandleCache` object
//!
//! Note: providers must be Sync since the thread-local caches for distinct threads will poll them.

use left_right::{ReadHandle, ReadHandleFactory};
use std::cell::RefCell;
use std::collections::HashMap;
use std::hash::Hash;
use std::rc::Rc;
use std::thread::LocalKey;

pub trait ReadHandleProvider: Sync {
    type Data;
    type Key;

    /// A provider should provide per thread `ReadHandles`. However, it is safer if we require providers
    /// to give us factories as that shields us from buggy providers returning ReadHandles that are not
    /// unique per thread. There should be no performance penalty of offering factories instead of read handles
    /// since factory::handle() is identical to rhandle::clone()
    fn get_factory(&self, key: &Self::Key) -> Option<&ReadHandleFactory<Self::Data>>;
}

#[derive(Debug)]
pub enum ReadHandleCacheError<K> {
    NotFound(K),
    NotAccessible(K),
}

pub struct ReadHandleCache<K: Hash + Eq, T> {
    handles: RefCell<HashMap<K, Rc<ReadHandle<T>>>>,
}
impl<K, T> ReadHandleCache<K, T>
where
    K: Hash + Eq + Clone,
{
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            handles: RefCell::new(HashMap::new()),
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
            if let Some(rhandle) = map.get(&key)
                && !rhandle.was_dropped()
            {
                return Ok(Rc::clone(rhandle));
            }

            // Either we've found a handle but was invalid or we did not find it.
            // In either case, request a fresh handle to the provider, which may:
            //    1) fail to provide one with that key
            //    2) provide a valid one
            //    3) provide an invalid one (e.g. if the `WriteHandle<T>` was dropped).
            // We don't require providers to provide good readhandles/factories, nor
            // want to return invalid handles to callers, so we validate them too.
            // A valid readhandle is one where, at least now, can be 'entered'.

            let result = {
                let fresh = provider
                    .get_factory(&key)
                    .map(|factory| factory.handle())
                    .ok_or_else(|| ReadHandleCacheError::NotFound(key.clone()))?;

                if fresh.was_dropped() {
                    Err(ReadHandleCacheError::NotAccessible(key.clone()))
                } else {
                    let fresh = Rc::new(fresh);
                    map.entry(key.clone())
                        .and_modify(|e| *e = Rc::clone(&fresh))
                        .or_insert_with(|| Rc::clone(&fresh));

                    Ok(fresh)
                }
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
///
/// struct LeftRightWrappedType;
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
