// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::Manager;
use crate::tc::action::{Action, ActionSpec};
use crate::tc::block::BlockIndex;
use crate::tc::chain::ChainIndex;
use derive_builder::Builder;
use rekon::{AsRequirement, Create};
use rtnetlink::packet_route::tc::TcFilterFlowerOption;
use std::num::NonZero;

#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FilterIndex(NonZero<u32>);

#[derive(Debug, thiserror::Error)]
pub enum FilterIndexError {
    #[error("invalid filter index: zero is not a legal filter index")]
    Zero,
}

impl From<NonZero<u32>> for FilterIndex {
    fn from(index: NonZero<u32>) -> Self {
        Self(index)
    }
}

impl TryFrom<u32> for FilterIndex {
    type Error = FilterIndexError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match NonZero::new(value) {
            None => Err(FilterIndexError::Zero),
            Some(idx) => Ok(FilterIndex(idx)),
        }
    }
}

impl From<FilterIndex> for NonZero<u32> {
    fn from(value: FilterIndex) -> Self {
        value.0
    }
}

impl From<FilterIndex> for u32 {
    fn from(value: FilterIndex) -> u32 {
        value.0.get()
    }
}

pub struct Filter {
    handle: FilterIndex,
    priority: u16,
    block: BlockIndex,
    chain: ChainIndex,
    criteria: Vec<TcFilterFlowerOption>,
    actions: Vec<Action>, // stats go here
}

#[derive(Debug, PartialEq, Eq, Clone, Builder)]
pub struct FilterSpec {
    handle: FilterIndex,
    priority: u16,
    block: BlockIndex,
    chain: ChainIndex,
    pub criteria: Vec<TcFilterFlowerOption>,
    pub actions: Vec<ActionSpec>,
}

impl AsRequirement<FilterSpec> for Filter {
    type Requirement<'a>
        = FilterSpec
    where
        Self: 'a;

    fn as_requirement<'a>(&self) -> Self::Requirement<'a> {
        FilterSpec {
            handle: self.handle,
            priority: self.priority,
            block: self.block,
            chain: self.chain,
            criteria: self.criteria.clone(),
            actions: self.actions.iter().map(Action::as_requirement).collect(),
        }
    }
}

impl Create for Manager<Filter> {
    type Requirement<'a>
        = &'a FilterSpec
    where
        Self: 'a;
    type Outcome<'a>
        = Result<(), rtnetlink::Error>
    where
        Self: 'a;

    async fn create<'a>(&self, requirement: Self::Requirement<'a>) -> Self::Outcome<'a> {
        let mut protocol = 0x0003u16.to_be(); // default to "all" reserved protocol flag
        for filter in &requirement.criteria {
            if let TcFilterFlowerOption::EthType(eth_type) = filter {
                // if the user wants to match on ethtype, we need to set the protocol flag to
                // the ethtype value as well as submit the EthType filter option
                protocol = eth_type.to_be();
            }
        }
        self.handle
            .traffic_filter(0) // TODO: support non block filters
            .add()
            .block(requirement.block.into())
            .chain(requirement.chain)
            .handle(requirement.handle.into())
            .protocol(protocol) // TODO: update if mathing on ethtype
            // .parent()  // TODO: tolerate multiple qdiscs
            .priority(requirement.priority)
            .flower(requirement.criteria.as_slice())?
            .execute()
            .await
    }
}
