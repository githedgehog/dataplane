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

    /// Method for a provider to produce an iterator over the read handles (factories)
    /// This returns (version, iterator<Key, factory, Id>)
    #[allow(clippy::type_complexity)]
    fn get_iter(
        &self,
    ) -> (
        u64,
        impl Iterator<Item = (Self::Key, &ReadHandleFactory<Self::Data>, Self::Key)>,
    );
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
    refresh_version: RefCell<u64>, // version when last refresh mas made
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
            refresh_version: RefCell::new(0),
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

            // get a factory for the key from the provider to build a fresh handle from it
            // provider returns identity of object and version for entry invalidation
            let (factory, identity, version) = provider.get_factory(&key).ok_or_else(|| {
                map.remove(&key);
                ReadHandleCacheError::NotFound(key.clone())
            })?;

            // obtain handle but don't store it nor return it if there is no writer / data
            let rhandle = factory.handle();
            if rhandle.was_dropped() {
                // can remove element with key, but also all which point to the same identity
                map.retain(|_key, entry| entry.identity != identity);
                return Err(ReadHandleCacheError::NotAccessible(key.clone()));
            }

            // store a new entry locally with a handle, its identity and version, for the given key
            let rhandle = Rc::new(rhandle);
            let entry = ReadHandleEntry::new(identity.clone(), Rc::clone(&rhandle), version);
            map.insert(key.clone(), entry);

            // if the querying key is not the identity, update entry for key = identity. This helps in consistency
            // and avoids having duplicate readhandles for the same T, which should expedite checks with many read handles
            // if T's are accessed by multiple keys.
            if key != identity {
                map.insert(
                    identity.clone(),
                    ReadHandleEntry::new(identity, Rc::clone(&rhandle), version),
                );
            }
            Ok(rhandle)
        })
    }

    pub fn purge(thread_local: &'static LocalKey<Self>) {
        thread_local.with(|local| {
            local.handles.borrow_mut().clear();
            *local.refresh_version.borrow_mut() = 0;
        });
    }

    #[allow(unused)]
    fn purge_unreadable(thread_local: &'static LocalKey<Self>) {
        thread_local.with(|local| {
            let mut handles = local.handles.borrow_mut();
            handles.retain(|_, e| !e.rhandle.was_dropped());
        });
    }

    // Do a full refresh of the cache
    pub fn refresh(
        thread_local: &'static LocalKey<Self>,
        provider: &impl ReadHandleProvider<Data = T, Key = K>,
    ) {
        // skip refresh if the version has not changed
        let cache_refresh_version = thread_local.with(|local| *local.refresh_version.borrow());
        let provider_version = provider.get_version();
        if cache_refresh_version == provider_version {
            // this should not be needed
            Self::purge_unreadable(thread_local);
            return;
        }

        // get all readers (factories) from the provider
        let (version, iterator) = provider.get_iter();

        // theoretically, it could happen that while we call get_version() and get_iter(), the underlying collection
        // has changed and both differ
        if version != provider_version {
            Self::refresh(thread_local, provider);
            return;
        }

        // filter out all unusable readers from iterator
        let iterator = iterator.filter(|(_key, factory, _id)| {
            let rhandle = factory.handle();
            !rhandle.was_dropped()
        });

        // split the iterator in two: primaries and aliases
        let (primaries, aliases): (Vec<_>, Vec<_>) = iterator.partition(|(key, _, id)| key == id);

        // update local cache, consuming the iterator
        thread_local.with(|local| {
            let mut handles = local.handles.borrow_mut();

            // purge all unusable readers
            handles.retain(|_key, entry| !entry.rhandle.was_dropped());

            // update primaries first and store an Rc of the latest rhandles in a temporary map
            let mut temporary = HashMap::new();
            for (key, factory, id) in primaries {
                handles
                    .entry(key.clone())
                    .and_modify(|e| {
                        if e.version != version {
                            *e = ReadHandleEntry::new(
                                id.clone(),
                                Rc::new(factory.handle()),
                                version,
                            );
                        }
                        temporary.insert(id.clone(), Rc::clone(&e.rhandle));
                    })
                    .or_insert_with(|| {
                        let rhandle = Rc::new(factory.handle());
                        temporary.insert(key, Rc::clone(&rhandle));
                        ReadHandleEntry::new(id, rhandle, version)
                    });
            }
            // update entries for aliases to reuse primaries' handles, using the temporary map
            for (key, _factory, id) in aliases {
                if let Some(rhandle) = temporary.get(&id) {
                    handles.insert(
                        key.clone(),
                        ReadHandleEntry::new(id, Rc::clone(rhandle), version),
                    );
                } else {
                    // we should only get here if we got a key (alias) and could not find
                    // the primary object. This would be a provider bug.
                    // TODO: determine what to do here
                }
            }

            *local.refresh_version.borrow_mut() = version;
        });
    }

    /// Get an iterator of read handles from the cache. If refresh is true, the cache will be refreshed first.
    /// This function is mostly useful if we want to iterate over the objects that the cache represents, optionally
    /// refreshing it first. This is useful when the caller does not know _what_ objects are there.
    /// Since `ReadHandleProvider`s must be Sync, threads could simply call `ReadHandleProvider::get_iter()`
    /// directly. However, that would not refresh the cache and would create a new reader for every item returned
    /// by the provider, on each call.
    pub fn iter(
        thread_local: &'static LocalKey<Self>,
        provider: &impl ReadHandleProvider<Data = T, Key = K>,
        refresh: bool,
    ) -> impl Iterator<Item = (K, Rc<ReadHandle<T>>)> {
        if refresh {
            ReadHandleCache::refresh(thread_local, provider);
        }
        thread_local.with(|local| {
            let vector: Vec<(K, Rc<ReadHandle<T>>)> = local
                .handles
                .borrow()
                .iter()
                .map(|(key, e)| (key.clone(), Rc::clone(&e.rhandle)))
                .collect();
            vector.into_iter()
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

#[cfg(test)]
mod tests {
    #![allow(clippy::collapsible_if)]

    use super::*;
    use left_right::{Absorb, ReadHandleFactory, WriteHandle};
    use serial_test::serial;
    use std::sync::Mutex;
    // Our left-right protected struct
    #[derive(Debug, Clone)]
    struct TestStruct {
        id: u64,
        data: String,
    }
    impl TestStruct {
        fn new(id: u64, data: &str) -> Self {
            Self {
                id,
                data: data.to_string(),
            }
        }
    }
    // Implement identity for TestStruct
    impl Identity<u64> for TestStruct {
        fn identity(&self) -> u64 {
            self.id
        }
    }

    // Dummy implementation of Absorb for TestStruct
    #[derive(Debug)]
    enum TestStructChange {
        Update(String),
    }
    impl Absorb<TestStructChange> for TestStruct {
        fn absorb_first(&mut self, op: &mut TestStructChange, _other: &Self) {
            match op {
                TestStructChange::Update(data) => {
                    self.data = data.clone();
                }
            }
        }
        fn sync_with(&mut self, first: &Self) {
            *self = first.clone();
        }
    }

    // create local cache
    make_thread_local_readhandle_cache!(TEST_CACHE, u64, TestStruct);

    // ReadHandle "owner" implementing ReadHandleProvider
    #[derive(Debug)]
    struct TestProviderEntry<TestStruct: Absorb<TestStructChange>, TestStructChange> {
        id: u64,
        factory: ReadHandleFactory<TestStruct>,
        // writer owning the TestStruct. We use option to easily drop it
        // and Mutex to make the provider Sync.
        writer: Option<Mutex<WriteHandle<TestStruct, TestStructChange>>>,
    }
    impl TestProviderEntry<TestStruct, TestStructChange> {
        fn new(
            id: u64,
            factory: ReadHandleFactory<TestStruct>,
            writer: Option<Mutex<WriteHandle<TestStruct, TestStructChange>>>,
        ) -> Self {
            Self {
                id,
                factory,
                writer,
            }
        }
    }
    #[derive(Debug)]
    struct TestProvider {
        data: HashMap<u64, TestProviderEntry<TestStruct, TestStructChange>>,
        version: u64,
    }
    impl TestProvider {
        fn new() -> Self {
            Self {
                data: HashMap::new(),
                version: 0,
            }
        }
        fn add_object(&mut self, key: u64, identity: u64) {
            if key != identity {
                let entry = self.data.get(&identity).unwrap();
                let new = TestProviderEntry::new(identity, entry.factory.clone(), None);
                self.data.insert(key, new);
            } else {
                let object = TestStruct::new(identity, "unset");
                let (w, r) = left_right::new_from_empty(object);
                let entry = TestProviderEntry::new(identity, r.factory(), Some(Mutex::new(w)));
                self.data.insert(key, entry);
                let stored = self.data.get(&key).unwrap();
                assert_eq!(stored.id, identity);
            }
            self.version = self.version.wrapping_add(1);
        }
        fn mod_object(&mut self, key: u64, data: &str) {
            if let Some(object) = self.data.get_mut(&key) {
                if let Some(writer_lock) = &mut object.writer {
                    #[allow(clippy::mut_mutex_lock)] // lock exists just to make provider Sync
                    let mut writer = writer_lock.lock().unwrap();
                    writer.append(TestStructChange::Update(data.to_owned()));
                    writer.publish();
                }
            }
        }
        fn drop_writer(&mut self, key: u64) {
            if let Some(object) = self.data.get_mut(&key) {
                let x = object.writer.take();
                drop(x);
                self.version = self.version.wrapping_add(1);
            }
        }
    }

    // Implement trait ReadHandleProvider
    impl ReadHandleProvider for TestProvider {
        type Data = TestStruct;
        type Key = u64;
        fn get_version(&self) -> u64 {
            self.version
        }
        fn get_factory(
            &self,
            key: &Self::Key,
        ) -> Option<(&ReadHandleFactory<Self::Data>, Self::Key, u64)> {
            self.data
                .get(key)
                .map(|entry| (&entry.factory, entry.id, self.version))
        }
        fn get_identity(&self, key: &Self::Key) -> Option<Self::Key> {
            self.data.get(key).map(|entry| entry.id)
        }
        fn get_iter(
            &self,
        ) -> (
            u64,
            impl Iterator<Item = (Self::Key, &ReadHandleFactory<Self::Data>, Self::Key)>,
        ) {
            let iterator = self
                .data
                .iter()
                .map(|(key, entry)| (*key, &entry.factory, entry.id));

            (self.version, iterator)
        }
    }

    #[serial]
    #[test]
    fn test_readhandle_cache_basic() {
        // start fresh
        ReadHandleCache::purge(&TEST_CACHE);

        // build provider
        let mut provider = TestProvider::new();
        provider.add_object(1, 1);
        provider.add_object(2, 2);
        provider.mod_object(1, "object-1");
        provider.mod_object(2, "object-2");

        // add alias for 1
        provider.add_object(6000, 1);

        {
            let key = 1;
            println!("Test: Access to object with key {key}");
            let h = ReadHandleCache::get_reader(&TEST_CACHE, key, &provider).unwrap();
            let x = h.enter().unwrap();
            let obj = x.as_ref();
            assert_eq!(obj.id, 1);
            assert_eq!(obj.data, "object-1");
        }

        {
            let key = 2;
            println!("Test: Access to object with key {key}");
            let h = ReadHandleCache::get_reader(&TEST_CACHE, key, &provider).unwrap();
            let x = h.enter().unwrap();
            let obj = x.as_ref();
            assert_eq!(obj.id, 2);
            assert_eq!(obj.data, "object-2");
        }

        {
            // 6000 is alias for 1: should access object with id 1
            let key = 6000;
            println!("Test: Access to object with key {key}");
            let h = ReadHandleCache::get_reader(&TEST_CACHE, key, &provider).unwrap();
            let x = h.enter().unwrap();
            let obj = x.as_ref();
            assert_eq!(obj.id, 1);
            assert_eq!(obj.data, "object-1");
        }

        TEST_CACHE.with(|x| {
            let x = x.handles.borrow();
            assert!(x.contains_key(&6000));
            assert!(x.contains_key(&1));
            assert!(x.contains_key(&2));
            assert_eq!(x.len(), 3);
            println!("Test: cache contains entries");
        });

        println!("Change: Let 6000 be a key for 2 instead of 1");
        provider.add_object(6000, 2);
        provider.mod_object(2, "object-2-modified");
        {
            let key = 6000;
            let h = ReadHandleCache::get_reader(&TEST_CACHE, key, &provider).unwrap();
            let x = h.enter().unwrap();
            let obj = x.as_ref();
            assert_eq!(obj.id, 2);
            assert_eq!(obj.data, "object-2-modified");
        }
        {
            let key = 6000;
            println!("Test: Access to object with key {key}");
            let h = ReadHandleCache::get_reader(&TEST_CACHE, key, &provider).unwrap();
            let x = h.enter().unwrap();
            let obj = x.as_ref();
            assert_eq!(obj.id, 2);
            assert_eq!(obj.data, "object-2-modified");
        }

        println!("Change: drop data for object 1. It should not be accessible");
        provider.drop_writer(1);
        {
            let key = 1;
            println!("Test: Access to object with key {key}");
            let h = ReadHandleCache::get_reader(&TEST_CACHE, key, &provider);
            assert!(h.is_err_and(|e| e == ReadHandleCacheError::NotAccessible(key)));
        }

        println!("Change: drop data for object 2: should not be accessible by keys 2 and 6000");
        provider.drop_writer(2);
        {
            let key = 2;
            println!("Test: Access to object with key {key}");
            let h = ReadHandleCache::get_reader(&TEST_CACHE, key, &provider);
            assert!(h.is_err_and(|e| e == ReadHandleCacheError::NotAccessible(key)));
        }
        {
            let key = 6000;
            println!("Test: Access to object with key {key}");
            let h = ReadHandleCache::get_reader(&TEST_CACHE, key, &provider);
            assert!(h.is_err_and(|e| e == ReadHandleCacheError::NotAccessible(key)));
        }

        // ensure cache is clean
        TEST_CACHE.with(|x| {
            let x = x.handles.borrow();
            assert!(!x.contains_key(&6000));
            assert!(!x.contains_key(&1));
            assert!(!x.contains_key(&2));
            assert!(x.is_empty());
            println!("Test: cache is empty");
        });
    }

    #[serial]
    #[test]
    fn test_readhandle_cache_multi_invalidation() {
        // start fresh
        ReadHandleCache::purge(&TEST_CACHE);

        const NUM_ALIASES: u64 = 10;

        // build provider
        let mut provider = TestProvider::new();
        provider.add_object(1, 1);
        provider.mod_object(1, "object-1");

        // add aliases
        for k in 1..=NUM_ALIASES {
            let alias = 100 + k;
            provider.add_object(alias, 1);
        }

        // query for identity and all aliases
        ReadHandleCache::get_reader(&TEST_CACHE, 1, &provider).unwrap();
        for k in 1..=NUM_ALIASES {
            let alias = 100 + k;
            ReadHandleCache::get_reader(&TEST_CACHE, alias, &provider).unwrap();
        }

        // cache should contain NUM_ALIASES + 1 entries
        TEST_CACHE
            .with(|cache| assert_eq!(cache.handles.borrow().len() as u64, (NUM_ALIASES + 1u64)));

        provider.drop_writer(1);

        // do single query for identity
        let h = ReadHandleCache::get_reader(&TEST_CACHE, 1, &provider);
        assert!(h.is_err_and(|e| e == ReadHandleCacheError::NotAccessible(1)));

        // all entries should have been invalidated
        TEST_CACHE.with(|cache| assert!(cache.handles.borrow().is_empty()));

        // querying again with key = identity should fail
        let h = ReadHandleCache::get_reader(&TEST_CACHE, 1, &provider);
        assert!(h.is_err_and(|e| e == ReadHandleCacheError::NotAccessible(1)));

        // querying again with aliases should fail too. Aliases are 100 + k k=1..=NUM_ALIASES
        let alias = 100 + 1;
        let h = ReadHandleCache::get_reader(&TEST_CACHE, alias, &provider);
        assert!(h.is_err_and(|e| e == ReadHandleCacheError::NotAccessible(alias)));
    }

    #[serial]
    #[test]
    fn test_readhandle_cache() {
        // start fresh
        ReadHandleCache::purge(&TEST_CACHE);

        // build provider and populate it
        const NUM_HANDLES: u64 = 1000;
        let mut provider = TestProvider::new();
        for id in 0..=NUM_HANDLES {
            provider.add_object(id, id);
            provider.mod_object(id, format!("object-id-{id}").as_ref());
            provider.add_object(id + NUM_HANDLES + 1, id);
        }

        // access all objects by id
        for id in 0..=NUM_HANDLES {
            let h = ReadHandleCache::get_reader(&TEST_CACHE, id, &provider).unwrap();
            let x = h.enter().unwrap();
            let obj = x.as_ref();
            assert_eq!(obj.id, id);
        }

        // access all objects by alias
        for id in 0..=NUM_HANDLES {
            let alias = id + NUM_HANDLES + 1;
            let h = ReadHandleCache::get_reader(&TEST_CACHE, alias, &provider).unwrap();
            let x = h.enter().unwrap();
            let obj = x.as_ref();
            assert_eq!(obj.id, id);
        }

        // modify all objects and replace all aliases
        for id in 0..=NUM_HANDLES {
            let alias = 2 * NUM_HANDLES + 1 - id;
            provider.mod_object(id, format!("modified-id-{id}").as_ref());
            provider.add_object(alias, id);
        }

        // access objects with re-assigned aliases
        for id in 0..=NUM_HANDLES {
            let alias = 2 * NUM_HANDLES + 1 - id;
            let h = ReadHandleCache::get_reader(&TEST_CACHE, alias, &provider).unwrap();
            let x = h.enter().unwrap();
            let obj = x.as_ref();
            assert_eq!(obj.id, id);
            assert_eq!(obj.data, format!("modified-id-{id}"));
        }

        // invalidate all writers
        for id in 0..=NUM_HANDLES {
            provider.drop_writer(id);
        }

        // access objects from alias: none should be accessible
        for id in 0..=NUM_HANDLES {
            let alias = 2 * NUM_HANDLES + 1 - id;
            let h = ReadHandleCache::get_reader(&TEST_CACHE, alias, &provider);
            assert!(h.is_err_and(|e| e == ReadHandleCacheError::NotAccessible(alias)));
        }

        // all handles from cache should have been removed as we looked up them all
        TEST_CACHE.with(|cache| assert!(cache.handles.borrow().is_empty()));
    }

    #[serial]
    #[test]
    fn test_readhandle_cache_iter() {
        // start fresh
        ReadHandleCache::purge(&TEST_CACHE);

        // build provider and populate it
        const NUM_HANDLES: u64 = 20;
        let mut provider = TestProvider::new();
        for id in 1..=NUM_HANDLES {
            let alias = NUM_HANDLES + id;
            provider.add_object(id, id);
            provider.mod_object(id, format!("object-{id}").as_ref());
            provider.add_object(alias, id);
        }

        // should be empty
        TEST_CACHE.with(|cache| assert!(cache.handles.borrow().is_empty()));

        // request iterator without refresh. Nothing should be returned since cache is empty.
        let iterator = ReadHandleCache::iter(&TEST_CACHE, &provider, false);
        assert_eq!(iterator.count(), 0);

        // request iterator with refresh
        let iterator = ReadHandleCache::iter(&TEST_CACHE, &provider, true);

        // consume it
        let mut count = 0;
        for (_key, rhandle) in iterator {
            count += 1;
            let _guard = rhandle.enter().unwrap();
        }

        // we got all
        assert_eq!(count, NUM_HANDLES * 2);

        // test that if the version of the provider does not change, then the cache is not unnecessarily refreshed.
        // Our test provider does not change version unless we add/drop elements and we don't now.
        {
            // empty cache for testing purposes. Since this will reset iter_version, we save it first
            let saved_iter_version = TEST_CACHE.with(|local| *local.refresh_version.borrow());
            ReadHandleCache::purge(&TEST_CACHE);
            TEST_CACHE.with(|local| *local.refresh_version.borrow_mut() = saved_iter_version);
        }
        // since version did not change, we should not get anything after iterating.
        let iterator = ReadHandleCache::iter(&TEST_CACHE, &provider, true);
        assert_eq!(iterator.count(), 0);
        assert_eq!(TEST_CACHE.with(|local| local.handles.borrow().len()), 0);

        // if we reset the version, then the iterator should refresh the cache.
        TEST_CACHE.with(|local| *local.refresh_version.borrow_mut() = 0);
        let iterator = ReadHandleCache::iter(&TEST_CACHE, &provider, true);
        assert_eq!(iterator.count() as u64, 2 * NUM_HANDLES);
        assert_eq!(
            TEST_CACHE.with(|local| local.handles.borrow().len() as u64),
            2 * NUM_HANDLES
        );

        // test that refresh/iter filters out invalid handles (need refresh) 2 should have been invalidated
        provider.drop_writer(1);
        let iterator = ReadHandleCache::iter(&TEST_CACHE, &provider, true);
        let vec: Vec<(u64, Rc<ReadHandle<TestStruct>>)> = iterator.collect();
        assert_eq!(vec.len() as u64, (NUM_HANDLES - 1) * 2);
    }
}
