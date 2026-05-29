// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

pub mod dyn_table;
pub mod table;

pub use dyn_table::{DynReferenceTable, DynShapeError};
pub use match_action::{Erased, FieldPredicate};
pub use table::{RefRule, ReferenceTable};
