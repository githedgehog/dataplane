use dpdk::lcore::LCoreId;
use std::num::NonZero;

#[repr(transparent)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Id(pub NonZero<u64>);

pub(crate) struct Tag {
    pub id: Id,
    pub sender: LCoreId,
    pub regarding: Option<Id>,
}

pub(crate) struct Message<D> {
    pub tag: Tag,
    pub data: D,
}
