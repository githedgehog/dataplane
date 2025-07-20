// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use lpm::prefix::Prefix;

mod collapse;

pub use collapse::collapse_prefixes_peering;

#[derive(thiserror::Error, Debug, Clone)]
pub enum ConfigUtilError {
    #[error("failed to split prefix {0}")]
    SplitPrefixError(Prefix),
}
