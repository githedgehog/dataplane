// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

pub trait AsRequirement<Observation> {
    type Requirement<'a>
    where
        Self: 'a;
    fn as_requirement<'a>(&self) -> Self::Requirement<'a>
    where
        Self: 'a;
}

pub trait Observe {
    type Observation<'a>
    where
        Self: 'a;

    fn observe<'a>(&self) -> impl Future<Output = Self::Observation<'a>>
    where
        Self: 'a;
}

pub trait Create {
    type Requirement<'a>
    where
        Self: 'a;
    type Outcome<'a>
    where
        Self: 'a;
    fn create<'a>(
        &self,
        requirement: Self::Requirement<'a>,
    ) -> impl Future<Output = Self::Outcome<'a>> + Send
    where
        Self: 'a;
}

pub trait Update {
    type Requirement<'a>
    where
        Self: 'a;
    type Observation<'a>
    where
        Self: 'a;
    type Outcome<'a>
    where
        Self: 'a;
    fn update<'a>(
        &self,
        requirement: Self::Requirement<'a>,
        observation: Self::Observation<'a>,
    ) -> impl Future<Output = Self::Outcome<'a>> + Send
    where
        Self: 'a;
}

pub trait Remove {
    type Observation<'a>
    where
        Self: 'a;

    type Outcome<'a>
    where
        Self: 'a;

    fn remove<'a>(
        &self,
        observation: Self::Observation<'a>,
    ) -> impl Future<Output = Self::Outcome<'a>> + Send
    where
        Self: 'a;
}

pub trait Reconcile {
    type Requirement<'a>
    where
        Self: 'a;
    type Observation<'a>
    where
        Self: 'a;
    type Outcome<'a>
    where
        Self: 'a;
    fn reconcile<'a>(
        &self,
        requirement: Self::Requirement<'a>,
        observation: Self::Observation<'a>,
    ) -> impl Future<Output = Self::Outcome<'a>> + Send
    where
        Self: 'a;
}

pub enum Op<'a, H: 'a + Create + Update + Remove> {
    Create(<H as Create>::Outcome<'a>),
    Update(<H as Update>::Outcome<'a>),
    Remove(<H as Remove>::Outcome<'a>),
}
