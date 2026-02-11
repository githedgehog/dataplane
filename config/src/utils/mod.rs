// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use lpm::prefix::Prefix;

mod collapse;
mod overlap;

pub use collapse::collapse_prefixes_peering;
pub(crate) use overlap::{check_private_prefixes_dont_overlap, check_public_prefixes_dont_overlap};

#[derive(thiserror::Error, Debug, Clone)]
pub enum ConfigUtilError {
    #[error("failed to split prefix {0}")]
    SplitPrefixError(Prefix),
}
