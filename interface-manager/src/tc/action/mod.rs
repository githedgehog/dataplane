// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Display, Formatter};
use std::marker::PhantomData;
use std::num::NonZero;

pub mod gact;
pub mod mirred;
pub mod tunnel_key;

use crate::Manager;
use crate::tc::action::gact::{
    GenericAction, GenericActionSpec, MultiIndexGenericActionMap, MultiIndexGenericActionSpecMap,
};
use crate::tc::action::mirred::{Mirred, MirredSpec, MultiIndexMirredMap, MultiIndexMirredSpecMap};
use crate::tc::action::tunnel_key::{
    MultiIndexTunnelKeyMap, MultiIndexTunnelKeySpecMap, TunnelKey, TunnelKeySpec,
};
use derive_builder::Builder;
use rekon::{AsRequirement, Create, Observe, Reconcile, Remove, Update};
use rtnetlink::packet_route::tc::TcAction;
use tracing::trace;

pub trait ActionKind {
    const KIND: &'static str;
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ActionSpec {
    pub details: ActionDetailsSpec,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Action {
    pub details: ActionDetails,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ActionDetailsSpec {
    Mirred(MirredSpec),
    Generic(GenericActionSpec),
    TunnelKey(TunnelKeySpec),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ActionDetails {
    Mirred(Mirred),
    Generic(GenericAction),
    TunnelKey(TunnelKey),
}

#[derive(Builder, Clone, Debug, Default)]
pub struct ActionBase {
    pub gact: MultiIndexGenericActionMap,
    pub mirred: MultiIndexMirredMap,
    pub tunnel_key: MultiIndexTunnelKeyMap,
}

impl ActionBase {
    // NOTE: I would normally just implement Iterator here, but the type returned by this method
    // is quite complex and impl Trait in associated types is not yet stable.
    /// Iterate over all actions in the [`ActionBase`].
    pub fn iter(&self) -> impl Iterator<Item = Action> {
        self.gact
            .iter()
            .map(|(_, y)| ActionDetails::Generic(*y))
            .chain(self.mirred.iter().map(|(_, y)| ActionDetails::Mirred(*y)))
            .chain(
                self.tunnel_key
                    .iter()
                    .map(|(_, y)| ActionDetails::TunnelKey(*y)),
            )
            .map(|details| Action { details })
    }
}

#[derive(Builder, Clone, Debug, Default)]
pub struct ActionBaseSpec {
    pub gact: MultiIndexGenericActionSpecMap,
    pub mirred: MultiIndexMirredSpecMap,
    pub tunnel_key: MultiIndexTunnelKeySpecMap,
}

impl ActionBaseSpec {
    // NOTE: I would normally just implement Iterator here, but the type returned by this method
    // is quite complex and impl Trait in associated types is not yet stable.
    /// Iterate over all action specifications in the [`ActionBaseSpec`].
    pub fn iter(&self) -> impl Iterator<Item = ActionSpec> {
        self.gact
            .iter()
            .map(|(_, y)| ActionDetailsSpec::Generic(*y))
            .chain(
                self.mirred
                    .iter()
                    .map(|(_, y)| ActionDetailsSpec::Mirred(*y)),
            )
            .chain(
                self.tunnel_key
                    .iter()
                    .map(|(_, y)| ActionDetailsSpec::TunnelKey(*y)),
            )
            .map(|details| ActionSpec { details })
    }
}

impl AsRequirement<ActionBaseSpec> for ActionBase {
    type Requirement<'a>
        = ActionBaseSpec
    where
        Self: 'a;

    fn as_requirement<'a>(&self) -> Self::Requirement<'a>
    where
        Self: 'a,
    {
        ActionBaseSpec {
            gact: self.gact.as_requirement(),
            mirred: self.mirred.as_requirement(),
            tunnel_key: self.tunnel_key.as_requirement(),
        }
    }
}

impl AsRequirement<MultiIndexGenericActionSpecMap> for MultiIndexGenericActionMap {
    type Requirement<'a>
        = MultiIndexGenericActionSpecMap
    where
        Self: 'a;

    fn as_requirement<'a>(&self) -> Self::Requirement<'a>
    where
        Self: 'a,
    {
        let mut map = MultiIndexGenericActionSpecMap::default();
        for (_, action) in self.iter() {
            map.insert(action.as_requirement());
        }
        map
    }
}

#[derive(Copy, Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(transparent)]
pub struct ActionIndex<T: ?Sized>(NonZero<u32>, PhantomData<T>);

impl<T: ActionKind> Display for ActionIndex<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "({}, {})", T::KIND, self.0.get())
    }
}

impl<T: ActionKind> Debug for ActionIndex<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self}")
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ActionIndexError {
    #[error("invalid action index: zero is reserved")]
    Zero,
}

impl<T> ActionIndex<T> {
    /// Create a new action index.
    #[must_use]
    pub fn new(index: NonZero<u32>) -> Self {
        Self(index, PhantomData)
    }

    /// Create a new action index.
    ///
    /// # Errors
    ///
    /// Returns an error if the index is zero.
    pub fn try_new(index: u32) -> Result<Self, ActionIndexError> {
        match NonZero::new(index) {
            Some(index) => Ok(Self(index, PhantomData)),
            None => Err(ActionIndexError::Zero),
        }
    }
}

impl<T> TryFrom<u32> for ActionIndex<T> {
    type Error = ActionIndexError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        Self::try_new(value)
    }
}

impl<T> From<ActionIndex<T>> for u32 {
    fn from(value: ActionIndex<T>) -> Self {
        value.0.get()
    }
}

impl<T> From<ActionIndex<T>> for NonZero<u32> {
    fn from(value: ActionIndex<T>) -> Self {
        value.0
    }
}

impl AsRequirement<ActionSpec> for Action {
    type Requirement<'a>
        = Option<ActionSpec>
    where
        Self: 'a;

    fn as_requirement<'a>(&self) -> Self::Requirement<'a>
    where
        Self: 'a,
    {
        Some(ActionSpec {
            details: match self.details {
                ActionDetails::Mirred(details) => match details.as_requirement() {
                    None => None?,
                    Some(as_req) => ActionDetailsSpec::Mirred(as_req),
                },
                ActionDetails::Generic(details) => {
                    ActionDetailsSpec::Generic(details.as_requirement())
                }
                ActionDetails::TunnelKey(details) => {
                    ActionDetailsSpec::TunnelKey(details.as_requirement())
                }
            },
        })
    }
}

impl<'a> From<&'a ActionSpec> for TcAction {
    fn from(value: &'a ActionSpec) -> Self {
        match value.details {
            ActionDetailsSpec::Generic(details) => TcAction::from(&details),
            ActionDetailsSpec::Mirred(details) => TcAction::from(&details),
            ActionDetailsSpec::TunnelKey(details) => TcAction::from(details),
        }
    }
}

impl Create for Manager<Action> {
    type Requirement<'a>
        = &'a ActionSpec
    where
        Self: 'a;
    type Outcome<'a>
        = Result<(), rtnetlink::Error>
    where
        Self: 'a;

    async fn create<'a>(&self, requirement: Self::Requirement<'a>) -> Self::Outcome<'a> {
        match requirement.details {
            ActionDetailsSpec::TunnelKey(action) => {
                Manager::<TunnelKey>::new(self.handle.clone())
                    .create(&action)
                    .await
            }
            ActionDetailsSpec::Mirred(action) => {
                Manager::<Mirred>::new(self.handle.clone())
                    .create(&action)
                    .await
            }
            ActionDetailsSpec::Generic(action) => {
                Manager::<GenericAction>::new(self.handle.clone())
                    .create(&action)
                    .await
            }
        }
    }
}

impl Remove for Manager<Action> {
    type Observation<'a>
        = &'a Action
    where
        Self: 'a;
    type Outcome<'a>
        = Result<(), rtnetlink::Error>
    where
        Self: 'a;

    async fn remove<'a>(&self, observation: Self::Observation<'a>) -> Self::Outcome<'a> {
        match observation.details {
            ActionDetails::Mirred(mirred) => {
                Manager::<Mirred>::new(self.handle.clone())
                    .remove(&mirred)
                    .await
            }
            ActionDetails::Generic(generic) => {
                Manager::<GenericAction>::new(self.handle.clone())
                    .remove(&generic)
                    .await
            }
            ActionDetails::TunnelKey(tunnel_key) => {
                Manager::<TunnelKey>::new(self.handle.clone())
                    .remove(tunnel_key.index)
                    .await
            }
        }
    }
}

impl Update for Manager<Action> {
    type Requirement<'a>
        = &'a ActionSpec
    where
        Self: 'a;
    type Observation<'a>
        = &'a Action
    where
        Self: 'a;
    type Outcome<'a>
        = Result<(), rtnetlink::Error>
    where
        Self: 'a;

    async fn update<'a>(
        &self,
        requirement: Self::Requirement<'a>,
        observation: Self::Observation<'a>,
    ) -> Self::Outcome<'a>
    where
        Self: 'a,
    {
        // TODO: update action in place
        self.remove(observation).await?;
        self.create(requirement).await
    }
}

impl Reconcile for Manager<Action> {
    type Requirement<'a>
        = Option<&'a ActionSpec>
    where
        Self: 'a;
    type Observation<'a>
        = Option<&'a Action>
    where
        Self: 'a;
    type Outcome<'a>
        = Result<(), rtnetlink::Error>
    where
        Self: 'a;

    async fn reconcile<'a>(
        &self,
        requirement: Self::Requirement<'a>,
        observation: Self::Observation<'a>,
    ) -> Self::Outcome<'a> {
        match (requirement, observation) {
            (Some(requirement), Some(observation)) => {
                match observation.as_requirement() {
                    None => {}
                    Some(as_req) => {
                        if *requirement == as_req {
                            trace!("already reconciled: {requirement:#?} with {observation:#?}");
                            return Ok(());
                        }
                    }
                }
                self.update(requirement, observation).await
            }
            (Some(requirement), None) => self.create(requirement).await,
            (None, Some(observation)) => self.remove(observation).await,
            (None, None) => Ok(()),
        }
    }
}

impl Observe for Manager<Action> {
    type Observation<'a>
        = Result<ActionBase, ()>
    where
        Self: 'a;

    async fn observe<'a>(&self) -> Self::Observation<'a> {
        struct Managers {
            pub gact: Manager<GenericAction>,
            pub mirred: Manager<Mirred>,
            pub tunnel_key: Manager<TunnelKey>,
        }
        let managers = Managers {
            gact: Manager::<GenericAction>::new(self.handle.clone()),
            mirred: Manager::<Mirred>::new(self.handle.clone()),
            tunnel_key: Manager::<TunnelKey>::new(self.handle.clone()),
        };
        let mut actions = ActionBase::default();
        for action in managers.gact.observe().await {
            match actions.gact.try_insert(action) {
                Ok(_) => {}
                Err(err) => {
                    trace!("failed to insert action: {err:#?}");
                }
            }
        }
        for action in managers.mirred.observe().await {
            match actions.mirred.try_insert(action) {
                Ok(_) => {}
                Err(err) => {
                    trace!("failed to insert action: {err:#?}");
                }
            }
        }
        for action in managers.tunnel_key.observe().await {
            match actions.tunnel_key.try_insert(action) {
                Ok(_) => {}
                Err(err) => {
                    trace!("failed to insert action: {err:#?}");
                }
            }
        }
        Ok(actions)
    }
}
