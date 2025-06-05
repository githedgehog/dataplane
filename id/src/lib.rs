// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! A typed identifier.
//!
//! The goal of this crate is to create compile-time associations between IDs and types.
//!
//! This association helps prevent us from conflating id types while avoiding the need to write a
//! different `FooId` type for each type which needs an id.

use core::fmt::{Debug, Formatter};
use std::cmp::Ordering;
use std::fmt::Display;
use std::hash::{Hash, Hasher};
use std::marker::PhantomData;
use uuid::Uuid;

#[allow(unused_imports)] // re-export
#[cfg(any(test, feature = "bolero"))]
pub use contract::*;

/// An abstract, typed ID.
///
/// # Example
///
/// ```
/// # use std::collections::HashSet;
/// # use dataplane_id::Id;
///
/// pub struct User {
///     id: Id<Self>,
///     name: String,
///     orders: HashSet<Id<Order>>,
/// }
///
/// pub struct Order {
///     id: Id<Self>,
///     user: Id<User>,
///     items: Vec<Id<Item>>,
/// }
///
/// pub struct Item {
///     id: Id<Self>,
///     name: String,
///     price: f64,
/// }
///
/// ```
///
/// The [Id] type can be of service in disambiguating the return types of functions and resisting
/// programming errors.
///
/// As a somewhat trite example, consider
///
/// ```
/// # use uuid::Uuid;
/// # type DbConnection = (); // stub, for example
/// # type User = (); // stub, for example
/// /// List the users
/// fn list(connection: &mut DbConnection) -> Vec<Uuid> {
///     // ...
///     # todo!()
/// }
/// ```
///
/// In this case the `list` function returns a list of user ids from a database of some kind.
/// This is both more explicit and less error-prone when written as
///
/// ```
/// # use dataplane_id::Id;
/// # type DbConnection = (); // stub, for example
/// # type User = (); // stub, for example
/// fn list(connection: &mut DbConnection) -> Vec<Id<User>> {
///     // ...
///     # todo!()
/// }
/// ```
///
/// Further, consider this method.
///
/// ```rust,compile_fail
/// # use dataplane_id::Id;
/// # struct User; // stub, for example
/// # struct Order; // stub, for example
/// fn simple_example(mut user_id: Id<User>, order_id: Id<Order>) {
///     user_id = order_id; // <- this won't compile, and that's a good thing
/// }
/// ```
///
/// The fact that this does not compile is very useful; it has prevented us from conflating our ids.
///
/// [UUID]: https://en.wikipedia.org/wiki/Universally_unique_identifier
///
/// If you need something besides [`Uuid`] as your ID type, I recommend making a `type` alias such as
///
/// ```
/// # use dataplane_id::Id;
/// # type MySpecialType = (); // stub, for example
/// type MySpecialId<T> = Id<T, MySpecialType>;
/// ```
///
/// if you need to use `MySpecialType` instead of [`Uuid`] for your special type of tagged id.
///
/// [UUID]: https://en.wikipedia.org/wiki/Universally_unique_identifier
#[cfg_attr(feature = "serde", allow(clippy::unsafe_derive_deserialize))] // not used in deserialize method
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(transparent)]
pub struct Id<T: ?Sized, U = Uuid>(U, PhantomData<T>);

impl<T, U> Copy for Id<T, U> where U: Copy {}

impl<T, U> Hash for Id<T, U>
where
    U: Hash,
{
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl<T, U> Clone for Id<T, U>
where
    U: Clone,
{
    fn clone(&self) -> Self {
        Self(self.0.clone(), PhantomData)
    }
}

impl<T, U> PartialEq for Id<T, U>
where
    U: PartialEq,
{
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl<T, U> Eq for Id<T, U> where U: Eq {}

impl<T, U> PartialOrd for Id<T, U>
where
    U: Ord,
{
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<T, U> Ord for Id<T, U>
where
    U: Ord,
{
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.cmp(&other.0)
    }
}

impl<T, U> AsRef<U> for Id<T, U> {
    fn as_ref(&self) -> &U {
        &self.0
    }
}

impl<T, U> Display for Id<T, U>
where
    U: Display,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        <_ as Display>::fmt(&self.0, f)
    }
}

impl<T, U> Debug for Id<T, U>
where
    U: Debug,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        <_ as Debug>::fmt(&self.0, f)
    }
}

impl<T, U> Default for Id<T, U>
where
    U: Default,
{
    fn default() -> Self {
        Self(U::default(), PhantomData)
    }
}

impl<T> Id<T> {
    /// Generate a new `Id<T>`.
    /// Namespace UUID used for generating namespaced [UUIDv5] identifiers
    ///
    /// [UUIDv5]: https://datatracker.ietf.org/doc/html/rfc9562#section-5.5
    pub const NAMESPACE_UUID: Uuid = Uuid::from_u128(0x8178d539_96b8_40fd_8fbf_402503aa204a);

    /// Generate a new [`Id<U>`].
    /// This method returns a transparently wrapped [Uuid] which is compile-time tagged with the
    /// type parameter `T`.
    /// The annotation consumes no space and has no runtime overhead whatsoever.
    /// The only function of `T` is to distinguish this type from other [Id] types.
    #[must_use]
    pub fn new() -> Id<T> {
        Id(Uuid::new_v4(), PhantomData)
    }

    /// Strip type safety and return the wrapped (untyped) [Uuid]
    #[must_use]
    pub const fn into_raw(self) -> Uuid {
        self.0
    }

    /// Return a reference to the underlying (untyped) [Uuid].
    #[must_use]
    pub const fn as_raw(&self) -> &Uuid {
        &self.0
    }

    /// Create a typed version of `uuid`.
    ///
    /// # Note
    ///
    /// You generally should not need this method.
    /// In particular, you should not attempt to convert `Id<U>` into `Id<T>` by removing and
    /// re-adding the types as doing so defeats the core function of this type.
    ///
    /// The appropriate use for this method is to add a compile-time type annotation to a [Uuid]
    /// in situations where you received the [Uuid] in a context where you may conclusively infer
    /// the type of data associated with that [Uuid].
    ///
    /// You _should not_ use this method in situations where you are generating a [Uuid] and wish
    /// to associate it with a type.
    /// In such cases use [Id::new] instead.
    #[must_use]
    pub const fn from_raw(uuid: Uuid) -> Self {
        Self(uuid, PhantomData)
    }

    /// Generate a [UUID version 5] based on the supplied namespace and byte string.
    ///
    /// [UUID version 5]: https://datatracker.ietf.org/doc/html/rfc9562#section-5.5
    #[must_use]
    pub fn new_v5(namespace: Uuid, tag: impl AsRef<[u8]>) -> Self {
        Self(Uuid::new_v5(&namespace, tag.as_ref()), PhantomData)
    }

    /// Generate a compile time "typed" UUID version 5.
    ///
    /// This value will not change between compiler runs if `tag` does not.
    /// This value will be unique per tag (neglecting SHA1 hash collisions).
    pub fn new_static(tag: impl AsRef<str>) -> Self {
        Self::new_v5(Self::NAMESPACE_UUID, tag.as_ref().as_bytes())
    }
}

impl<T> From<Id<T>> for Uuid {
    fn from(value: Id<T>) -> Self {
        value.0
    }
}

impl<T, U> From<U> for Id<T, U> {
    /// You generally should not use this method.
    /// See the docs for [`Id::<T>::from_raw`]
    fn from(value: U) -> Self {
        Self(value, PhantomData)
    }
}

#[cfg(any(test, feature = "bolero"))]
mod contract {
    use crate::Id;
    use bolero::{Driver, TypeGenerator, ValueGenerator};
    use std::marker::PhantomData;

    pub struct UuidIdGenerator;

    impl ValueGenerator for UuidIdGenerator {
        type Output = Id<()>;

        fn generate<D: Driver>(&self, driver: &mut D) -> Option<Self::Output> {
            Some(Id(
                uuid::Builder::from_random_bytes(driver.produce::<[u8; 16]>()?).into_uuid(),
                PhantomData,
            ))
        }
    }

    impl<T: 'static, U> TypeGenerator for Id<T, U>
    where
        U: TypeGenerator,
    {
        fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
            Some(Id(driver.produce()?, PhantomData))
        }
    }
}

#[cfg(test)]
mod test {
    use crate::{Id, UuidIdGenerator};
    use uuid::Uuid;

    #[test]
    fn new_generates_unique() {
        bolero::check!()
            .with_generator(UuidIdGenerator)
            .for_each(|x: &Id<()>| {
                let y = Id::<()>::new();
                assert_ne!(*x, y);
            });
    }

    #[test]
    fn test_v5() {
        bolero::check!()
            .with_type()
            .for_each(|(namespace, val): &([u8; 16], [u8; 16])| {
                let namespace = Uuid::from_slice(namespace).unwrap();
                let raw = Id::<()>::new_v5(namespace, val.as_slice()).into_raw();
                let reference = Uuid::new_v5(&namespace, val);
                assert_eq!(raw, reference);
            });
    }

    #[test]
    fn test_static() {
        bolero::check!().with_type().for_each(|x: &String| {
            let raw = Id::<()>::new_static(x.as_str()).into_raw();
            let reference = Uuid::new_v5(&Id::<()>::NAMESPACE_UUID, x.as_bytes());
            assert_eq!(raw, reference);
        });
    }
}
