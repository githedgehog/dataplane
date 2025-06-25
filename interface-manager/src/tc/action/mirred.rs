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
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::warn;

const TCA_EGRESS_REDIR: i32 = 1;
const TCA_EGRESS_MIRROR: i32 = 2;
const TCA_INGRESS_REDIR: i32 = 3;
const TCA_INGRESS_MIRROR: i32 = 4;

#[derive(
    Clone, Copy, Debug, Default, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize,
)]
#[repr(i32)]
#[non_exhaustive]
pub enum SupportedMirredAction {
    /// Redirect to the egress pipeline.
    #[default]
    EgressRedir = TCA_EGRESS_REDIR,
    /// Mirror to the egress pipeline.
    EgressMirror = TCA_EGRESS_MIRROR,
    /// Redirect to the ingress pipeline.
    IngressRedir = TCA_INGRESS_REDIR,
    /// Mirror to the ingress pipeline.
    IngressMirror = TCA_INGRESS_MIRROR,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[repr(i32)]
#[non_exhaustive]
pub enum MirredAction {
    Supported(SupportedMirredAction),
    Unknown(i32),
}

impl From<SupportedMirredAction> for MirredAction {
    fn from(value: SupportedMirredAction) -> Self {
        MirredAction::Supported(value)
    }
}

#[derive(Debug, Error)]
pub enum UnsupportedMirredActionError {
    #[error("unknown mirred action: {0}")]
    UnknownAction(i32),
}

impl TryFrom<i32> for SupportedMirredAction {
    type Error = UnsupportedMirredActionError;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            TCA_EGRESS_REDIR => Ok(SupportedMirredAction::EgressRedir),
            TCA_EGRESS_MIRROR => Ok(SupportedMirredAction::EgressMirror),
            TCA_INGRESS_REDIR => Ok(SupportedMirredAction::IngressRedir),
            TCA_INGRESS_MIRROR => Ok(SupportedMirredAction::IngressMirror),
            _ => Err(UnsupportedMirredActionError::UnknownAction(value)),
        }
    }
}

impl From<SupportedMirredAction> for i32 {
    fn from(value: SupportedMirredAction) -> Self {
        value as i32
    }
}

impl From<i32> for MirredAction {
    fn from(value: i32) -> Self {
        match SupportedMirredAction::try_from(value) {
            Ok(action) => MirredAction::Supported(action),
            Err(err) => {
                warn!("{err}");
                MirredAction::Unknown(value)
            }
        }
    }
}

impl TryFrom<MirredAction> for SupportedMirredAction {
    type Error = UnsupportedMirredActionError;

    fn try_from(value: MirredAction) -> Result<Self, Self::Error> {
        match value {
            MirredAction::Supported(action) => Ok(action),
            MirredAction::Unknown(action) => {
                Err(UnsupportedMirredActionError::UnknownAction(action))
            }
        }
    }
}

impl From<MirredAction> for i32 {
    fn from(value: MirredAction) -> Self {
        match value {
            MirredAction::Supported(x) => x.into(),
            MirredAction::Unknown(x) => x,
        }
    }
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
#[multi_index_derive(Clone, Debug)]
pub struct MirredSpec {
    #[multi_index(hashed_unique)]
    index: ActionIndex<Mirred>,
    #[multi_index(ordered_non_unique)]
    to: InterfaceIndex,
    action: SupportedMirredAction,
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
#[multi_index_derive(Clone, Debug, Serialize, Deserialize)]
pub struct Mirred {
    #[multi_index(hashed_unique)]
    index: ActionIndex<Mirred>,
    #[multi_index(ordered_non_unique)]
    to: InterfaceIndex,
    action: MirredAction,
}

impl ActionKind for Mirred {
    const KIND: &'static str = "mirred";
}

impl AsRequirement<MirredSpec> for Mirred {
    type Requirement<'a>
        = Option<MirredSpec>
    where
        Self: 'a;

    fn as_requirement<'a>(&self) -> Self::Requirement<'a> {
        Some(MirredSpec {
            index: self.index,
            to: self.to,
            action: self.action.try_into().ok()?,
        })
    }
}

impl AsRequirement<MultiIndexMirredSpecMap> for MultiIndexMirredMap {
    type Requirement<'a>
        = MultiIndexMirredSpecMap
    where
        Self: 'a;

    fn as_requirement<'a>(&self) -> Self::Requirement<'a> {
        let mut db = MultiIndexMirredSpecMap::default();
        for (_, mirred) in self.iter() {
            match mirred.as_requirement() {
                None => {}
                Some(spec) => {
                    db.insert(spec);
                }
            }
        }
        db
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
        let action = TcAction::from(requirement);
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
    use crate::tc::action::mirred::{Mirred, MirredAction, MirredSpec, SupportedMirredAction};
    use rtnetlink::packet_route::tc::{
        TcAction, TcActionAttribute, TcActionMirrorOption, TcActionOption, TcActionType, TcMirror,
    };
    use tracing::warn;

    // NOTE: it is annoying that this code needs to be duplicated in the `From<Mirred>` case below
    //       I don't see a great way of avoiding this duplication without adding more complexity
    //       than is justified to remove it.
    impl<'a> From<&'a MirredSpec> for TcAction {
        fn from(value: &'a MirredSpec) -> Self {
            let mut action = TcAction::default();
            action.attributes = Vec::from(*value);
            action.tab = 1;
            action
        }
    }

    // NOTE: if you change this method, change the method above symmetrically
    impl<'a> From<&'a Mirred> for TcAction {
        fn from(value: &'a Mirred) -> Self {
            let mut action = TcAction::default();
            action.attributes = Vec::from(*value);
            action.tab = 1;
            action
        }
    }

    // NOTE: it is annoying that this code needs to be duplicated in the `From<Mirred>` case below
    //       I don't see a great way of avoiding this duplication without adding more complexity
    //       than is justified to remove it.
    impl From<MirredSpec> for Vec<TcActionAttribute> {
        fn from(value: MirredSpec) -> Self {
            vec![
                TcActionAttribute::Kind(Mirred::KIND.to_string()),
                TcActionAttribute::Options(vec![TcActionOption::Mirror(
                    TcActionMirrorOption::Parms({
                        let mut mirror = TcMirror::default();
                        mirror.eaction = i32::from(value.action).into();
                        mirror.ifindex = value.to.into();
                        mirror.generic.action = match value.action {
                            SupportedMirredAction::EgressMirror
                            | SupportedMirredAction::IngressMirror => TcActionType::Pipe,
                            SupportedMirredAction::IngressRedir
                            | SupportedMirredAction::EgressRedir => TcActionType::Stolen,
                        };
                        mirror.generic.refcnt = 1; // set or the kernel will auto clean it up
                        mirror.generic.index = value.index.into();
                        mirror
                    }),
                )]),
            ]
        }
    }

    impl From<Mirred> for Vec<TcActionAttribute> {
        fn from(value: Mirred) -> Self {
            vec![
                TcActionAttribute::Kind(Mirred::KIND.to_string()),
                TcActionAttribute::Options(vec![TcActionOption::Mirror(
                    TcActionMirrorOption::Parms({
                        let mut mirror = TcMirror::default();
                        mirror.eaction = i32::from(value.action).into();
                        mirror.ifindex = value.to.into();
                        mirror.generic.action = match value.action {
                            MirredAction::Supported(
                                SupportedMirredAction::EgressMirror
                                | SupportedMirredAction::IngressMirror,
                            ) => TcActionType::Pipe,
                            MirredAction::Supported(
                                SupportedMirredAction::IngressRedir
                                | SupportedMirredAction::EgressRedir,
                            ) => TcActionType::Stolen,
                            MirredAction::Unknown(x) => {
                                warn!("unknown mirred action: {x}");
                                TcActionType::Pipe
                            }
                        };
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
            .action(TcAction::from(observation))
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
            (Some(requirement), Some(observation)) => match observation.as_requirement() {
                None => {
                    warn!("observed alien mirred action: {observation:#?}");
                    self.remove(observation).await
                }
                Some(as_req) => {
                    if as_req != *requirement {
                        return self.update(requirement, observation).await;
                    }
                    Ok(())
                }
            },
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
                            match SupportedMirredAction::try_from(i32::from(params.generic.action))
                            {
                                Ok(action) => {
                                    builder.action(MirredAction::Supported(action));
                                }
                                Err(err) => {
                                    warn!("{err}");
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
