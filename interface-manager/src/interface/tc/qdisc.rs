// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::Manager;
use net::interface::InterfaceIndex;
use rekon::Create;

#[repr(transparent)]
pub struct BlockIndex(u32);
pub struct IngressBlock(BlockIndex);
pub struct EgressBlock(BlockIndex);

impl BlockIndex {
    // TODO: this shouldn't be public
    #[must_use]
    pub fn new(index: u32) -> Self {
        Self(index)
    }
}

impl IngressBlock {
    #[must_use]
    pub fn new(index: BlockIndex) -> Self {
        Self(index)
    }
}

impl EgressBlock {
    #[must_use]
    pub fn new(index: BlockIndex) -> Self {
        Self(index)
    }
}

pub enum Qdisc {
    ClsAct(ClsAct),
}

pub struct ClsAct {
    interface_index: InterfaceIndex,
    ingress_block: Option<IngressBlock>,
    egress_block: Option<EgressBlock>,
}

impl ClsAct {
    #[must_use]
    pub fn new(interface_index: InterfaceIndex) -> Self {
        Self {
            interface_index,
            ingress_block: None,
            egress_block: None,
        }
    }

    pub fn ingress_block(&mut self, block: IngressBlock) -> &mut Self {
        self.ingress_block = Some(block);
        self
    }

    pub fn egress_block(&mut self, block: EgressBlock) -> &mut Self {
        self.egress_block = Some(block);
        self
    }
}

impl From<ClsAct> for Qdisc {
    fn from(value: ClsAct) -> Self {
        Qdisc::ClsAct(value)
    }
}

impl Create for Manager<ClsAct> {
    type Requirement<'a>
        = &'a ClsAct
    where
        Self: 'a;
    type Outcome<'a>
        = Result<(), rtnetlink::Error>
    where
        Self: 'a;

    async fn create<'a>(&self, requirement: Self::Requirement<'a>) -> Self::Outcome<'a>
    where
        Self: 'a,
    {
        let mut request = self
            .handle
            .qdisc()
            .add(
                #[allow(clippy::cast_possible_wrap)]
                {
                    requirement.interface_index.to_u32() as i32
                },
            )
            .clsact();

        match &requirement.ingress_block {
            None => {}
            Some(block) => {
                request.ingress_block(block.0.0);
            }
        }

        match &requirement.egress_block {
            None => {}
            Some(block) => {
                request.egress_block(block.0.0);
            }
        }

        request.execute().await
    }
}
