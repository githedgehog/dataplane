// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::Manager;
use crate::tc::action::{ActionIndex, ActionKind};
use derive_builder::Builder;
use futures::TryStreamExt;
use multi_index_map::MultiIndexMap;
use rekon::{AsRequirement, Create, Observe, Reconcile, Remove, Update};
use rtnetlink::packet_route::tc::{
    TcAction, TcActionAttribute, TcActionGeneric, TcActionGenericOption, TcActionMessageAttribute,
    TcActionOption, TcActionType,
};
use tracing::{debug, warn};

#[derive(Builder, Clone, Copy, Debug, PartialEq, Eq, MultiIndexMap)]
#[builder(derive(Debug, PartialEq, Eq, Copy))]
#[multi_index_derive(Clone, Debug)]
pub struct GenericAction {
    #[multi_index(ordered_unique)]
    pub index: ActionIndex<GenericAction>,
    pub action_type: TcActionType,
}

impl PartialOrd for GenericAction {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for GenericAction {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.index.cmp(&other.index)
    }
}

#[derive(Builder, Clone, Copy, Debug, PartialEq, Eq, MultiIndexMap)]
#[builder(derive(Debug, PartialEq, Eq, Copy))]
#[multi_index_derive(Clone, Debug)]
pub struct GenericActionSpec {
    pub index: ActionIndex<GenericAction>,
    pub action_type: TcActionType,
}

impl ActionKind for GenericAction {
    const KIND: &'static str = "gact";
}

impl AsRequirement<GenericActionSpec> for GenericAction {
    type Requirement<'a>
        = GenericActionSpec
    where
        Self: 'a;

    fn as_requirement<'a>(&self) -> Self::Requirement<'a>
    where
        Self: 'a,
    {
        GenericActionSpec {
            index: self.index,
            action_type: self.action_type,
        }
    }
}

impl<'a> From<&'a GenericActionSpec> for TcAction {
    fn from(value: &'a GenericActionSpec) -> Self {
        let mut action = TcAction::default();
        action.tab = 1;
        action.attributes.extend([
            TcActionAttribute::Kind(GenericAction::KIND.to_string()),
            TcActionAttribute::Options(vec![TcActionOption::Generic(
                TcActionGenericOption::Parms({
                    let mut parms = TcActionGeneric::default();
                    parms.index = value.index.into();
                    parms.refcnt = 1; // set to 1 or linux will auto remove this up
                    parms.action = value.action_type;
                    parms
                }),
            )]),
        ]);
        action
    }
}

impl Create for Manager<GenericAction> {
    type Requirement<'a>
        = &'a GenericActionSpec
    where
        Self: 'a;
    type Outcome<'a>
        = Result<(), rtnetlink::Error>
    where
        Self: 'a;

    async fn create<'a>(&self, requirement: Self::Requirement<'a>) -> Self::Outcome<'a> {
        let mut resp = self
            .handle
            .traffic_action()
            .add()
            .action(requirement.into())
            .execute();
        loop {
            match resp.try_next().await {
                Ok(Some(_)) => {}
                Ok(None) => break,
                Err(err) => {
                    warn!("Error while adding action: {err:?}");
                    return Err(err);
                }
            }
        }
        Ok(())
    }
}

impl Remove for Manager<GenericAction> {
    type Observation<'a>
        = &'a GenericAction
    where
        Self: 'a;
    type Outcome<'a>
        = Result<(), rtnetlink::Error>
    where
        Self: 'a;

    async fn remove<'a>(&self, observation: Self::Observation<'a>) -> Self::Outcome<'a> {
        self.handle
            .traffic_action()
            .del()
            .action(TcAction::from(&observation.as_requirement()))
            .execute()
            .await
    }
}

impl Update for Manager<GenericAction> {
    type Requirement<'a>
        = &'a GenericActionSpec
    where
        Self: 'a;
    type Observation<'a>
        = &'a GenericAction
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
    ) -> Self::Outcome<'a> {
        self.remove(observation).await?;
        self.create(requirement).await
    }
}

impl Reconcile for Manager<GenericAction> {
    type Requirement<'a>
        = Option<&'a GenericActionSpec>
    where
        Self: 'a;
    type Observation<'a>
        = Option<&'a GenericAction>
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
                if observation.as_requirement() != *requirement {
                    return self.update(requirement, observation).await;
                }
                Ok(())
            }
            (Some(requirement), None) => self.create(requirement).await,
            (None, Some(observation)) => self.remove(observation).await,
            (None, None) => Ok(()),
        }
    }
}

impl Observe for Manager<GenericAction> {
    type Observation<'a>
        = Vec<GenericAction>
    where
        Self: 'a;

    async fn observe<'a>(&self) -> Self::Observation<'a> {
        let mut resp = self
            .handle
            .traffic_action()
            .get()
            .kind(GenericAction::KIND)
            .execute();
        let mut ret = vec![];
        match resp.try_next().await {
            Ok(Some(r)) => {
                for attr in &r.attributes {
                    if let TcActionMessageAttribute::Actions(actions) = attr {
                        ret.extend(
                            actions
                                .iter()
                                .filter_map(|x| GenericAction::try_from(x).ok()),
                        );
                    }
                }
            }
            Ok(None) => {
                println!("all done");
            }
            Err(err) => {
                eprintln!("Error while getting actions: {err:?}");
            }
        }
        ret
    }
}

impl<'a> TryFrom<&'a TcAction> for GenericAction {
    type Error = ();

    fn try_from(value: &'a TcAction) -> Result<Self, Self::Error> {
        let mut builder = GenericActionBuilder::create_empty();
        for attr in &value.attributes {
            match attr {
                TcActionAttribute::Kind(kind) => {
                    if kind != GenericAction::KIND {
                        return Err(());
                    }
                }
                TcActionAttribute::Options(options) => {
                    for option in options {
                        if let TcActionOption::Generic(option) = option {
                            if let TcActionGenericOption::Parms(params) = option {
                                match ActionIndex::<GenericAction>::try_from(params.index) {
                                    Ok(idx) => {
                                        builder.index(idx);
                                    }
                                    Err(err) => {
                                        warn!("{err}");
                                        return Err(());
                                    }
                                }
                                builder.action_type(params.action);
                            }
                        } else {
                            warn!("misaligned action query");
                            return Err(());
                        }
                    }
                }
                TcActionAttribute::Index(index) => {
                    match ActionIndex::<GenericAction>::try_from(*index) {
                        Ok(idx) => {
                            builder.index(idx);
                        }
                        Err(err) => {
                            warn!("{err}");
                            return Err(());
                        }
                    }
                }
                _ => {}
            }
        }
        match builder.build() {
            Ok(gact) => Ok(gact),
            Err(err) => {
                debug!("{err}");
                Err(())
            }
        }
    }
}
