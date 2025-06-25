// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::Manager;
use crate::tc::action::{ActionIndex, ActionKind};
use derive_builder::Builder;
use futures::TryStreamExt;
use multi_index_map::MultiIndexMap;
use net::interface::InterfaceIndex;
use rekon::{AsRequirement, Create, Observe, Reconcile, Remove, Update};
use rtnetlink::packet_route::tc::{
    TcAction, TcActionAttribute, TcActionMessageAttribute, TcActionMirrorOption, TcActionOption,
    TcMirrorActionType,
};
use serde::{Deserialize, Serialize};
use tracing::warn;

#[derive(
    Builder,
    Clone,
    Copy,
    Debug,
    Eq,
    Hash,
    MultiIndexMap,
    Ord,
    PartialEq,
    PartialOrd,
    Deserialize,
    Serialize,
)]
#[builder(derive(Debug, PartialEq, Eq, Hash, Ord, PartialOrd, Copy))]
pub struct MirredSpec {
    #[multi_index(hashed_unique)]
    pub index: ActionIndex<Mirred>,
    #[multi_index(ordered_non_unique)]
    pub to: InterfaceIndex,
}

#[derive(
    Builder,
    Clone,
    Copy,
    Debug,
    Eq,
    Hash,
    MultiIndexMap,
    Ord,
    PartialEq,
    PartialOrd,
    Deserialize,
    Serialize,
)]
#[builder(derive(Debug, PartialEq, Eq, Hash, Ord, PartialOrd, Copy))]
pub struct Mirred {
    #[multi_index(hashed_unique)]
    index: ActionIndex<Mirred>,
    #[multi_index(ordered_non_unique)]
    to: InterfaceIndex,
}

impl ActionKind for Mirred {
    const KIND: &'static str = "mirred";
}

impl AsRequirement<MirredSpec> for Mirred {
    type Requirement<'a>
        = MirredSpec
    where
        Self: 'a;

    fn as_requirement<'a>(&self) -> Self::Requirement<'a> {
        MirredSpec {
            index: self.index,
            to: self.to,
        }
    }
}

impl Create for Manager<Mirred> {
    type Requirement<'a>
        = &'a MirredSpec
    where
        Self: 'a;
    type Outcome<'a>
        = Result<(), rtnetlink::Error>
    where
        Self: 'a;

    async fn create<'a>(&self, requirement: Self::Requirement<'a>) -> Self::Outcome<'a> {
        let action = TcAction::from(*requirement);
        let mut resp = self.handle.traffic_action().add().action(action).execute();
        loop {
            match resp.try_next().await {
                Ok(Some(_)) => {}
                Ok(None) => {
                    break;
                }
                Err(err) => {
                    return Err(err);
                }
            }
        }
        Ok(())
    }
}

mod helper {
    use crate::tc::action::ActionKind;
    use crate::tc::action::mirred::{Mirred, MirredSpec};
    use rtnetlink::packet_route::tc::{
        TcAction, TcActionAttribute, TcActionMirrorOption, TcActionOption, TcActionType, TcMirror,
        TcMirrorActionType,
    };

    impl From<MirredSpec> for TcAction {
        fn from(value: MirredSpec) -> Self {
            let mut action = TcAction::default();
            action.attributes = Vec::from(value);
            action.tab = 1;
            action
        }
    }

    impl From<MirredSpec> for Vec<TcActionAttribute> {
        fn from(value: MirredSpec) -> Self {
            vec![
                TcActionAttribute::Kind(Mirred::KIND.to_string()),
                TcActionAttribute::Options(vec![TcActionOption::Mirror(
                    TcActionMirrorOption::Parms({
                        let mut mirror = TcMirror::default();
                        mirror.eaction = TcMirrorActionType::EgressRedir;
                        mirror.ifindex = value.to.into();
                        mirror.generic.action = TcActionType::Stolen;
                        mirror.generic.refcnt = 1; // set or the kernel will auto clean it up
                        mirror.generic.index = value.index.into();
                        mirror
                    }),
                )]),
            ]
        }
    }
}

impl Remove for Manager<Mirred> {
    type Observation<'a>
        = &'a Mirred
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
            .action(TcAction::from(observation.as_requirement()))
            .execute()
            .await
    }
}

impl Update for Manager<Mirred> {
    type Requirement<'a>
        = &'a MirredSpec
    where
        Self: 'a;
    type Observation<'a>
        = &'a Mirred
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

impl Reconcile for Manager<Mirred> {
    type Requirement<'a>
        = Option<&'a MirredSpec>
    where
        Self: 'a;
    type Observation<'a>
        = Option<&'a Mirred>
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

impl<'a> TryFrom<&'a TcAction> for Mirred {
    type Error = rtnetlink::Error;

    fn try_from(value: &'a TcAction) -> Result<Self, Self::Error> {
        let mut builder = MirredBuilder::create_empty();
        for attr in &value.attributes {
            match attr {
                TcActionAttribute::Kind(kind) => {
                    if kind != Mirred::KIND {
                        return Err(rtnetlink::Error::InvalidNla(
                            "expected mirred kind".to_string(),
                        ));
                    }
                }
                TcActionAttribute::Options(options) => {
                    for option in options {
                        if let TcActionOption::Mirror(TcActionMirrorOption::Parms(params)) = option
                        {
                            let ifindex: InterfaceIndex = match params.ifindex.try_into() {
                                Ok(ifindx) => ifindx,
                                Err(err) => {
                                    return Err(rtnetlink::Error::InvalidNla(format!(
                                        "invalid interface index: {err}"
                                    )));
                                }
                            };
                            builder.to(ifindex);
                            match ActionIndex::<Mirred>::try_from(params.generic.index) {
                                Ok(actindex) => {
                                    builder.index(actindex);
                                }
                                Err(err) => {
                                    return Err(rtnetlink::Error::InvalidNla(format!(
                                        "invalid action index: {err}"
                                    )));
                                }
                            }
                            match params.eaction {
                                TcMirrorActionType::EgressRedir => {
                                    // ok
                                }
                                eaction => {
                                    // TODO: support other eaction types in this data type
                                    return Err(rtnetlink::Error::InvalidNla(format!(
                                        "unsupported eaction: {eaction:?}"
                                    )));
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        match builder.build() {
            Ok(mirred) => Ok(mirred),
            Err(err) => Err(rtnetlink::Error::InvalidNla(format!(
                "invalid mirred action: {err}"
            ))),
        }
    }
}

impl Observe for Manager<Mirred> {
    type Observation<'a>
        = Vec<Mirred>
    where
        Self: 'a;

    async fn observe<'a>(&self) -> Self::Observation<'a> {
        let mut resp = self
            .handle
            .traffic_action()
            .get()
            .kind(Mirred::KIND)
            .execute();
        let mut observations = Vec::new();
        loop {
            match resp.try_next().await {
                Ok(Some(message)) => {
                    for attr in &message.attributes {
                        if let TcActionMessageAttribute::Actions(actions) = attr {
                            observations.extend(
                                actions.iter().filter_map(|act| Mirred::try_from(act).ok()),
                            );
                        }
                    }
                }
                Ok(None) => {
                    break;
                }
                Err(err) => {
                    warn!("{err}");
                    break;
                }
            }
        }
        observations
    }
}
