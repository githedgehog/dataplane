// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Dataplane configuration models. The external model is the model assumed by the RPC
//! The internal model is the model assumed internal. For an external configuration, the
//! dataplane process builds an internal, developed configuration, which is the configuration
//! that gets applied on the system.

pub mod external;
pub mod internal;
