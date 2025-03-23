// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors
//

use rtnetlink::packet_route::link::{InfoKind, LinkAttribute, LinkInfo, LinkMessage};
use std::fmt::Debug;
use tracing::error;

#[derive(Debug, thiserror::Error, serde::Serialize, serde::Deserialize)]
enum HighlanderError<T: Iterator> {
    #[error("no items in iterator")]
    None,
    #[error("uniqueness violation in iterator")]
    MoreThanOne {
        first: T::Item,
        second: T::Item,
        rest: T,
    },
}

#[tracing::instrument(level = "trace", skip(iterator))]
fn there_can_be_only_one<I: Iterator>(mut iterator: I) -> Result<I::Item, HighlanderError<I>> {
    if let Some(first) = iterator.next() {
        if let Some(second) = iterator.next() {
            let err = HighlanderError::MoreThanOne {
                first,
                second,
                rest: iterator,
            };
            Err(err)
        } else {
            Ok(first)
        }
    } else {
        Err(HighlanderError::None)
    }
}

#[tracing::instrument(level = "trace")]
pub fn message_is_of_kind(message: &LinkMessage, kind: InfoKind) -> bool {
    let filter = message.attributes.iter().filter(|attr| match attr {
        LinkAttribute::LinkInfo(infos) => {
            let filter = infos.iter().filter(|info| match info {
                LinkInfo::Kind(k) => *k == kind,
                _ => false,
            });
            match there_can_be_only_one(filter) {
                Ok(_) => true,
                Err(HighlanderError::None) => {
                    let index = message.header.index;
                    error!(index, "no kind attribute found: {message:?}");
                    false
                }
                Err(e) => {
                    let index = message.header.index;
                    error!(
                        index,
                        "there can be only one kind attribute: {e:?} (message: {message:?})"
                    );
                    false
                }
            }
        }
        _ => false,
    });
    match there_can_be_only_one(filter) {
        Ok(_) => true,
        Err(e) => {
            error!("there can be only one kind link info attribute: {e:?}");
            false
        }
    }
}

pub trait MessageContains<Quality> {
    fn message_contains(&self, quality: Quality) -> bool;
}

impl MessageContains<InfoKind> for LinkMessage {
    #[tracing::instrument(level = "trace")]
    fn message_contains(&self, quality: InfoKind) -> bool {
        message_is_of_kind(self, quality)
    }
}
