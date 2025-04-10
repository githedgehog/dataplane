// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

/// `Observe` is a trait that can be implemented for whatever struct is intended to collect or
/// measure data present in an external system.
///
/// The motivation use case here is to observe the state of a virtual network.
/// That said, observations from discs or sensors or whatever apply here.
pub trait Observe {
    /// The returned data type of the observation.
    ///
    /// This is a [GAT] parameterized over a lifetime `'a where Self: 'a`.
    /// Thus, it is fair game to use simple references, or `Option<&'a Whatever>` or something more
    /// complex here.
    ///
    /// [GAT]: https://rust-lang.github.io/generic-associated-types-initiative/explainer/motivation.html
    type Observation<'a>
    where
        Self: 'a;

    /// Observe the state of the system.
    ///
    /// # Contract
    ///
    /// Implementations should strive not to mutate the state of the external system.
    fn observe<'a>(&self) -> impl Future<Output = Self::Observation<'a>>
    where
        Self: 'a;
}

/// `Create` is a trait that can be implemented on an object able to create an external resource in
/// service of an associated `Requirement`.
pub trait Create {
    /// The data required to create the resource.
    ///
    /// For example, if the goal were to reconcile the IP addresses associated with a network
    /// interface, then the `Requirement` would include the desired ip addresses and some reference
    /// to the network interface to which those addresses should be assigned.
    ///
    /// This is a [GAT] parameterized over a lifetime `'a where Self: 'a`.
    /// Thus, it is fair game to use simple references, or `Option<&'a Whatever>` or something more
    /// complex here.
    ///
    /// [GAT]: https://rust-lang.github.io/generic-associated-types-initiative/explainer/motivation.html
    type Requirement<'a>
    where
        Self: 'a;

    /// `Outcome` includes any data returned by the `create` operation.
    /// Often this is `Result<(), SomeErrorType>`, but may be more complex if needed.
    type Outcome<'a>
    where
        Self: 'a;

    /// Create a resource in service of a requirement.
    fn create<'a>(
        &self,
        requirement: Self::Requirement<'a>,
    ) -> impl Future<Output = Self::Outcome<'a>> + Send
    where
        Self: 'a;
}

/// `Update` attempts to drive an extant resource closer to the state described by a requirement.
pub trait Update {
    /// The data required to create the resource.
    ///
    /// For example, if the goal were to reconcile the IP addresses associated with a network
    /// interface, then the `Requirement` would include the desired ip addresses and some reference
    /// to the network interface to which those addresses should be assigned.
    ///
    /// This is a [GAT] parameterized over a lifetime `'a where Self: 'a`.
    /// Thus, it is fair game to use simple references, or `Option<&'a Whatever>` or something more
    /// complex here.
    ///
    /// [GAT]: https://rust-lang.github.io/generic-associated-types-initiative/explainer/motivation.html
    type Requirement<'a>
    where
        Self: 'a;

    /// The returned data type of the observation.
    ///
    /// This is a [GAT] parameterized over a lifetime `'a where Self: 'a`.
    /// Thus, it is fair game to use simple references, or `Option<&'a Whatever>` or something more
    /// complex here.
    ///
    /// [GAT]: https://rust-lang.github.io/generic-associated-types-initiative/explainer/motivation.html
    type Observation<'a>
    where
        Self: 'a;

    /// `Outcome` includes any data returned by the `create` operation.
    /// Often this is `Result<(), SomeErrorType>`, but may be more complex if needed.
    type Outcome<'a>
    where
        Self: 'a;

    /// Attempt to drive an extant (observed) resource closer to the state described by a
    /// requirement.
    ///
    /// # Contract
    ///
    /// Note that driving the observed state _all the way_ to the requirement is _not_ required by
    /// the contract of this trait.
    /// Specifically, there is no assurance whatsoever that the observed state will meet the
    /// supplied requirements after calling this method.
    /// The goal is only to move the system closer to the desired state so that further calls to
    /// `update` might converge to the required condition.
    fn update<'a>(
        &self,
        requirement: Self::Requirement<'a>,
        observation: Self::Observation<'a>,
    ) -> impl Future<Output = Self::Outcome<'a>> + Send
    where
        Self: 'a;
}

/// `Remove` is a trait that can be implemented on an object able to remove an externaly observed
/// resource.
///
/// For example, you could implement `Remove` to delete a virtual network interface.
pub trait Remove {
    /// The returned data type of the observation.
    ///
    /// This is a [GAT] parameterized over a lifetime `'a where Self: 'a`.
    /// Thus, it is fair game to use simple references, or `Option<&'a Whatever>` or something more
    /// complex here.
    ///
    /// [GAT]: https://rust-lang.github.io/generic-associated-types-initiative/explainer/motivation.html
    type Observation<'a>
    where
        Self: 'a;

    /// `Outcome` includes any data returned by the `remove` operation.
    /// Often this is `Result<(), SomeErrorType>`, but may be more complex if needed.
    type Outcome<'a>
    where
        Self: 'a;

    /// Remove an observed external resource.
    ///
    /// You might call this method to reflect that an previously created resource is no longer
    /// needed, or because the requirements require that this resource not be allocated.
    ///
    /// For instance, removing an ip address from a network interface.
    fn remove<'a>(
        &self,
        observation: Self::Observation<'a>,
    ) -> impl Future<Output = Self::Outcome<'a>> + Send
    where
        Self: 'a;
}

/// Map an observation back to the requirement which would be satisfied by the observation.
///
/// The point is to allow the observed current state of the system to be compared with the required
/// state of the system.
pub trait AsRequirement<Observation> {
    type Requirement<'a>
    where
        Self: 'a;
    fn as_requirement<'a>(&self) -> Self::Requirement<'a>
    where
        Self: 'a;
}

/// Attempt to drive an external resource into its required condition.
pub trait Reconcile {
    /// The data required to create the resource.
    ///
    /// For example, if the goal were to reconcile the IP addresses associated with a network
    /// interface, then the `Requirement` would include the desired ip addresses and some reference
    /// to the network interface to which those addresses should be assigned.
    ///
    /// This is a [GAT] parameterized over a lifetime `'a where Self: 'a`.
    /// Thus, it is fair game to use simple references, or `Option<&'a Whatever>` or something more
    /// complex here.
    ///
    /// [GAT]: https://rust-lang.github.io/generic-associated-types-initiative/explainer/motivation.html
    type Requirement<'a>
    where
        Self: 'a;
    /// The returned data type of the observation.
    ///
    /// This is a [GAT] parameterized over a lifetime `'a where Self: 'a`.
    /// Thus, it is fair game to use simple references, or `Option<&'a Whatever>` or something more
    /// complex here.
    ///
    /// [GAT]: https://rust-lang.github.io/generic-associated-types-initiative/explainer/motivation.html
    type Observation<'a>
    where
        Self: 'a;

    /// `Outcome` includes any data returned by the `reconcile` operation.
    /// Often this is `Result<(), SomeErrorType>`, but may be more complex if needed.
    type Outcome<'a>
    where
        Self: 'a;

    /// Attempt to drive an extant (observed) resource closer to the state described by a
    /// requirement.
    ///
    /// Implementations of `Reconcile` principally differ from those of `Update` in that it is
    /// common for `Reconcile` to create or remove resources entirely while `Update` mostly mutates
    /// those resources.
    ///
    /// # Contract
    ///
    /// Note that driving the observed state _all the way_ to the requirement is _not_ required by
    /// the contract of this trait.
    /// Specifically, there is no assurance whatsoever that the observed state will meet the
    /// supplied requirements after calling this method.
    /// The goal is only to move the system closer to the desired state so that further calls to
    /// `reconcile` might converge to the required condition.
    fn reconcile<'a>(
        &self,
        requirement: Self::Requirement<'a>,
        observation: Self::Observation<'a>,
    ) -> impl Future<Output = Self::Outcome<'a>> + Send
    where
        Self: 'a;
}

/// Op is a helper struct that is often useful as the `Outcome` type of `Reconcile`.
pub enum Op<'a, H: 'a + Create + Update + Remove> {
    Create(<H as Create>::Outcome<'a>),
    Update(<H as Update>::Outcome<'a>),
    Remove(<H as Remove>::Outcome<'a>),
}
