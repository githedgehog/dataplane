// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Display, Formatter};
use std::marker::PhantomData;
use std::num::NonZero;

pub mod gact;
pub mod mirred;

pub trait ActionKind {
    const KIND: &'static str;
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
