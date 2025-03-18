// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use crate::resource::{ImpliedBridge, ObservedBridge, ObservedVrf, ObservedVtep};
use crate::{IfIndex, InterfaceName};
use derive_builder::Builder;
use id::Id;
use std::collections::{HashMap, HashSet};
use tokio::select;

type Watch<T> = tokio::sync::watch::Receiver<T>;
type Notify<T> = tokio::sync::watch::Sender<T>;

#[derive(Builder, Clone, Debug)]
pub struct Topic<T> {
    id: Id<T>,
    subscribers: HashSet<T>,
    notify: Notify<T>,
    watch: Watch<T>,
}

pub struct BridgeNotify {
    required: Notify<ImpliedBridge>,
    observed: Notify<ObservedBridge>,
}

pub enum Convergence {
    Waiting,
    InProgress,
    Converged,
    Error,
}

pub struct BridgeWatch {
    required: Watch<ImpliedBridge>,
    observed: Watch<ObservedBridge>,
    converged: Notify<Convergence>,
}

pub struct ConvergenceWatch {
    converged: Watch<Convergence>,
}

struct NotificationHub {
    bridges: HashMap<InterfaceName, Notify<ObservedBridge>>,
}

struct Watch2<T> {
    id: Id<Watch2<T>>,
    watch: Watch<T>,
}

struct InterfaceJanitor {
    expected: Watch<HashSet<InterfaceName>>,
    converged: Notify<bool>,
}

struct VrfMembership {
    vrf: Watch<Option<ObservedVrf>>,
    bridge: Watch<Option<ObservedBridge>>,
}

struct BridgeMembership {
    bridge: Watch<Option<ObservedBridge>>,
    vtep: Watch<Option<ObservedVtep>>,
}
