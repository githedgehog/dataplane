// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Configuration models for dataplane. The external model is the model assumed by the RPC.
//! The internal model is the model assumed internally. For an external configuration, the
//! dataplane process builds an internal, developed configuration, which is the configuration
//! that gets distributed and applied in the system. Type `GwConfig` is the main object tpo hold
//! both the `ExternalConfig` and `InternalConfig` for a given config generation.

#![deny(
    unsafe_code,
    clippy::all,
    clippy::pedantic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]
#![allow(clippy::redundant_closure_for_method_calls)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::struct_excessive_bools)]

pub mod converters;
pub mod display;
pub mod errors;
pub mod external;
pub mod gwconfig;
pub mod internal;
pub mod utils;

pub use errors::{ConfigError, ConfigResult, stringify}; // re-export
pub use external::{ExternalConfig, GenId}; // re-export
pub use gwconfig::{GwConfig, GwConfigMeta}; // re-export
pub use internal::InternalConfig; // re-export
pub use internal::device::DeviceConfig; // re-export

use tracectl::trace_target;
trace_target!("mgmt", LevelFilter::DEBUG, &["management"]);
