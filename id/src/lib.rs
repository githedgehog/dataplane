// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! A "typed" [UUID] crate.
//!
//! [UUID]: https://en.wikipedia.org/wiki/Universally_unique_identifier

use core::fmt::{Debug, Formatter};
use std::borrow::Borrow;
use std::fmt::Display;
use std::marker::PhantomData;
use uuid::Uuid;

#[allow(unused_imports)] // re-export
#[cfg(any(test, feature = "bolero"))]
pub use contract::*;

/// A typed [UUID].
///
/// The goal of this crate is to create compile-time associations between UUIDs and types.
///
/// This association helps prevent us from conflating id types while avoiding the need to write a
/// different `FooId` type for each type which needs an id.
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
/// # type DbConnection = (); // stub for example
/// # type User = (); // stub for example
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
/// # type DbConnection = (); // stub for example
/// # type User = (); // stub for example
/// fn list(connection: &mut DbConnection) -> Vec<Id<User>> {
///     // ...
///     # todo!()
/// }
/// ```
///
/// Further, consider this method.
///
/// ```compile_fail
/// fn simple_example(mut user_id: Id<User>, mut order_id: Id<Order>) {
///     user_id = order_id; // <- this won't compile, and that's a good thing
/// }
/// ```
///
/// The fact that this does not compile is very useful; it has prevented us from conflating our ids.
///
/// [UUID]: https://en.wikipedia.org/wiki/Universally_unique_identifier
pub type Id<T> = AbstractIdType<*const T, Uuid>;

/// An abstract, typed ID.
///
/// <div class="warning">
///
/// Unless you need something besides UUID, use the [Id] type alias instead.
///
/// If you use this type directly, you will need to write `AbstractIdType<*const X>` instead of
/// `Id<X>` or you will expose yourself to derive, lifetime, and co/contravariance concerns which
/// have nothing to do with this type.
///
/// If you need something besides UUID as your ID type, I recommend making a `type` alias such as
///
/// ```
/// # use dataplane_id::AbstractIdType;
/// # type MySpecialType = (); // stub for example
/// type MySpecialId<T> = AbstractIdType<*const T, MySpecialType>;
/// ```
///
/// if you need to use `MySpecialType` instead of [`Uuid`] for your special type of tagged type.
///
/// </div>
///
/// [UUID]: https://en.wikipedia.org/wiki/Universally_unique_identifier
#[cfg_attr(feature = "serde", allow(clippy::unsafe_derive_deserialize))] // not used in deserialize method
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(transparent)]
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AbstractIdType<T, U = Uuid>(U, PhantomData<T>);

impl<T> AsRef<Uuid> for Id<T> {
    fn as_ref(&self) -> &Uuid {
        &self.0
    }
}

impl<T> Display for Id<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        <_ as Display>::fmt(self.0.as_hyphenated(), f)
    }
}

impl<T> Debug for Id<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        <_ as Debug>::fmt(self.0.as_hyphenated(), f)
    }
}

impl<T> Default for Id<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> Id<T> {
    /// Generate a new `Id<T>`.
    /// Namespace UUID used for generating namespaced [UUIDv5] identifiers
    ///
    /// [UUIDv5]: https://datatracker.ietf.org/doc/html/rfc9562#section-5.5
    pub const NAMESPACE_UUID: Uuid = Uuid::from_u128(0x8178d539_96b8_40fd_8fbf_402503aa204a);

    /// Generate a new `Id<U>`.
    /// This method returns a transparently wrapped [Uuid] which is compile-time tagged with the
    /// type parameter `T`.
    /// The annotation consumes no space and has no runtime overhead whatsoever.
    /// The only function of `T` is to distinguish this type from other [Id] types.
    #[inline(always)]
    #[must_use]
    pub fn new() -> Id<T> {
        AbstractIdType(Uuid::new_v4(), PhantomData)
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
    pub fn new_v5<N: Borrow<[u8]>>(namespace: Uuid, name: N) -> Self {
        Self(Uuid::new_v5(&namespace, name.borrow()), PhantomData)
    }

    /// Generate a compile time "typed" UUID version 5.
    ///
    /// This value will not change between compiler runs if `tag` does not.
    /// This value will be unique per tag (neglecting SHA1 hash collisions).
    pub fn new_static(tag: &str) -> Self {
        Self::new_v5(Self::NAMESPACE_UUID, tag.as_bytes())
    }
}

impl<T> From<Id<T>> for Uuid {
    fn from(value: Id<T>) -> Self {
        value.0
    }
}

impl<T> From<Uuid> for Id<T> {
    /// You generally should not use this method.
    /// See the docs for [`Id::<T>::from_raw`]
    fn from(value: Uuid) -> Self {
        Self::from_raw(value)
    }
}

#[cfg(any(test, feature = "bolero"))]
mod contract {
    use crate::{AbstractIdType, Id};
    use bolero::{Driver, TypeGenerator};
    use std::marker::PhantomData;

    impl<T: 'static> TypeGenerator for Id<T> {
        fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
            Some(AbstractIdType(
                uuid::Builder::from_random_bytes(driver.produce::<[u8; 16]>()?).into_uuid(),
                PhantomData,
            ))
        }
    }
}

#[cfg(test)]
mod test {
    use crate::Id;
    use uuid::Uuid;

    fn parse_back_test<T: 'static>() {
        bolero::check!()
            .with_type()
            .for_each(|x: &Id<T>| assert_eq!(*x, Id::from_raw(x.into_raw())));
    }

    #[test]
    fn parse_back_unit() {
        parse_back_test::<()>()
    }

    #[test]
    fn parse_back_u32() {
        parse_back_test::<u32>()
    }

    #[test]
    fn parse_back_string() {
        parse_back_test::<String>()
    }

    #[test]
    fn parse_back_recursive() {
        parse_back_test::<Id<String>>()
    }

    #[test]
    fn new_generates_unique() {
        bolero::check!().with_type().for_each(|x: &Id<()>| {
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
