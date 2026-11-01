// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Synchronous counterparts of the reconciliation traits, for external systems driven from one
//! thread with blocking calls (for instance a NIC's flow rules, programmed through a queue the
//! thread waits on).
//!
//! They mirror [`Observe`](crate::Observe), [`Create`](crate::Create), [`Update`](crate::Update),
//! [`Remove`](crate::Remove) and [`Reconcile`](crate::Reconcile), with the same contracts. One
//! difference: the methods that act on the external system take `&mut self`. The asynchronous
//! traits take `&self` so their futures can be shared and sent; a synchronous reconciler usually
//! owns the handles of what it created, and acting on them is what changes them.

/// Observe the state of an external system; see [`Observe`](crate::Observe).
pub trait SyncObserve {
    /// The returned data type of the observation.
    type Observation<'a>
    where
        Self: 'a;

    /// Observe the state of the system. The observation may borrow from `self`, for instance the
    /// handles of what a reconciler created.
    ///
    /// # Contract
    ///
    /// Implementations should strive not to mutate the state of the external system.
    fn observe<'a>(&'a self) -> Self::Observation<'a>;
}

/// Create an external resource in service of a requirement; see [`Create`](crate::Create).
pub trait SyncCreate {
    /// The data required to create the resource.
    type Requirement<'a>
    where
        Self: 'a;

    /// Any data returned by the `create` operation, often `Result<(), SomeErrorType>`.
    type Outcome<'a>
    where
        Self: 'a;

    /// Create a resource in service of a requirement.
    fn create<'a>(&mut self, requirement: Self::Requirement<'a>) -> Self::Outcome<'a>
    where
        Self: 'a;
}

/// Drive an extant resource closer to a requirement; see [`Update`](crate::Update).
pub trait SyncUpdate {
    /// The data required of the resource.
    type Requirement<'a>
    where
        Self: 'a;

    /// The observed resource.
    type Observation<'a>
    where
        Self: 'a;

    /// Any data returned by the `update` operation.
    type Outcome<'a>
    where
        Self: 'a;

    /// Attempt to drive an extant (observed) resource closer to the state described by a
    /// requirement.
    ///
    /// # Contract
    ///
    /// As for [`Update`](crate::Update): there is no assurance that the observed state meets the
    /// requirement afterwards, only that it moved closer to it.
    fn update<'a>(
        &mut self,
        requirement: Self::Requirement<'a>,
        observation: Self::Observation<'a>,
    ) -> Self::Outcome<'a>
    where
        Self: 'a;
}

/// Remove an observed external resource; see [`Remove`](crate::Remove).
pub trait SyncRemove {
    /// The observed resource.
    type Observation<'a>
    where
        Self: 'a;

    /// Any data returned by the `remove` operation.
    type Outcome<'a>
    where
        Self: 'a;

    /// Remove an observed external resource.
    fn remove<'a>(&mut self, observation: Self::Observation<'a>) -> Self::Outcome<'a>
    where
        Self: 'a;
}

/// Drive an external resource into its required condition; see [`Reconcile`](crate::Reconcile).
pub trait SyncReconcile {
    /// The required state.
    type Requirement<'a>
    where
        Self: 'a;

    /// The observed state.
    type Observation<'a>
    where
        Self: 'a;

    /// Any data returned by the `reconcile` operation.
    type Outcome<'a>
    where
        Self: 'a;

    /// Attempt to drive the observed state closer to the requirement, creating, updating or
    /// removing resources as needed.
    ///
    /// # Contract
    ///
    /// As for [`Reconcile`](crate::Reconcile): convergence is not promised by one call, only
    /// progress towards it, so that further calls converge.
    fn reconcile<'a>(
        &mut self,
        requirement: Self::Requirement<'a>,
        observation: Self::Observation<'a>,
    ) -> Self::Outcome<'a>
    where
        Self: 'a;
}

/// A helper often useful as the `Outcome` of [`SyncReconcile`]; see [`Op`](crate::Op).
pub enum SyncOp<'a, H: 'a + SyncCreate + SyncUpdate + SyncRemove> {
    /// A resource was created.
    Create(<H as SyncCreate>::Outcome<'a>),
    /// A resource was updated.
    Update(<H as SyncUpdate>::Outcome<'a>),
    /// A resource was removed.
    Remove(<H as SyncRemove>::Outcome<'a>),
}
