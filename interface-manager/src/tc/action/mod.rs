// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

pub mod gact;
pub mod mirred;
pub mod tunnel_key;

use crate::Manager;
use crate::tc::action::gact::{GenericAction, GenericActionSpec};
use crate::tc::action::mirred::{Mirred, MirredSpec};
use crate::tc::action::tunnel_key::{TunnelKey, TunnelKeySpec};
use net::vxlan::Vxlan;
use rekon::{AsRequirement, Create, Remove};
use rtnetlink::packet_route::tc::TcAction;
use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Display, Formatter};
use std::marker::PhantomData;
use std::num::NonZero;

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
    Redirect(MirredSpec),
    Generic(GenericActionSpec),
    TunnelKey(TunnelKeySpec),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ActionDetails {
    Mirred(Mirred),
    Generic(GenericAction),
    TunnelKey(TunnelKey),
}

#[derive(Copy, Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
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
        = ActionSpec
    where
        Self: 'a;

    fn as_requirement<'a>(&self) -> Self::Requirement<'a>
    where
        Self: 'a,
    {
        ActionSpec {
            details: match self.details {
                ActionDetails::Mirred(details) => {
                    ActionDetailsSpec::Redirect(details.as_requirement())
                }
                ActionDetails::Generic(details) => {
                    ActionDetailsSpec::Generic(details.as_requirement())
                }
                ActionDetails::TunnelKey(details) => {
                    ActionDetailsSpec::TunnelKey(details.as_requirement())
                }
            },
        }
    }
}

impl<'a> From<&'a ActionSpec> for TcAction {
    fn from(value: &'a ActionSpec) -> Self {
        match value.details {
            ActionDetailsSpec::Generic(details) => TcAction::from(&details),
            ActionDetailsSpec::Redirect(details) => TcAction::from(details),
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
            ActionDetailsSpec::Redirect(action) => {
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
