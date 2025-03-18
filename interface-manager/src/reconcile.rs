// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::InterfaceName;
use crate::resource::RouteTableId;
use derive_builder::Builder;
use diff::Diff;
use multi_index_map::MultiIndexMap;
use serde::{Deserialize, Serialize};

trait Reconcile {
    type Required: Diff;
    type Observed: Into<Self::Required>;

    fn reconcile(&self, required: Self::Required, observed: Self::Observed) {
        // required.diff(observed.into())
        todo!()
    }
}

type Required<T> = <T as Reconcile>::Required;
type Observed<T> = <T as Reconcile>::Observed;
