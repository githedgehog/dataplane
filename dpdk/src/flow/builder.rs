// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Building and installing flow rules.
//!
//! This is the one place that touches the `rte_flow` FFI and the pattern/action arrays. The builder
//! owns the action configuration structs, so the pointers handed to `rte_flow_create`/`validate`
//! stay valid for the duration of the call (the PMD copies them before returning).

use alloc::vec::Vec;
use core::ffi::c_void;
use core::marker::PhantomData;
use core::ptr::{NonNull, null};

use dpdk_sys::{
    rte_flow_action, rte_flow_action_jump, rte_flow_action_mark, rte_flow_action_queue,
    rte_flow_action_type as at, rte_flow_attr, rte_flow_create, rte_flow_error, rte_flow_item,
    rte_flow_item_type as it, rte_flow_validate,
};

use crate::dev::{Dev, Started};
use crate::flow::error::FlowError;
use crate::flow::rule::FlowRule;
use crate::flow::{Direction, Domain, FlowGroup, Mark, Priority};
use crate::queue::rx::RxQueueIndex;

/// An action plus the owned configuration struct the PMD reads through a pointer.
///
/// Keeping the config inline here is what makes the `conf` pointers passed to `rte_flow_create`
/// outlive the call.
enum Action {
    Jump(rte_flow_action_jump),
    Mark(rte_flow_action_mark),
    Queue(rte_flow_action_queue),
    Drop,
}

impl Action {
    fn type_(&self) -> at::Type {
        match self {
            Action::Jump(_) => at::RTE_FLOW_ACTION_TYPE_JUMP,
            Action::Mark(_) => at::RTE_FLOW_ACTION_TYPE_MARK,
            Action::Queue(_) => at::RTE_FLOW_ACTION_TYPE_QUEUE,
            Action::Drop => at::RTE_FLOW_ACTION_TYPE_DROP,
        }
    }

    /// Pointer to the configuration struct (or null for actions that take none).
    ///
    /// Valid only while `self` is alive and not moved.
    fn conf(&self) -> *const c_void {
        match self {
            Action::Jump(j) => core::ptr::from_ref(j).cast(),
            Action::Mark(m) => core::ptr::from_ref(m).cast(),
            Action::Queue(q) => core::ptr::from_ref(q).cast(),
            Action::Drop => null(),
        }
    }
}

/// Builds one flow rule and installs (or validates) it.
///
/// Construct via [`Flow::ingress`](crate::flow::Flow::ingress) /
/// [`egress`](crate::flow::Flow::egress) / [`transfer`](crate::flow::Flow::transfer). The domain
/// `D` fixes the `ingress`/`egress`/`transfer` attribute (which are mutually exclusive in the API).
///
/// This first iteration matches header *presence* only (e.g. "an IPv4 packet"); per-field spec/mask
/// matching is a follow-up.
#[must_use = "a FlowBuilder does nothing until create() or validate() is called"]
pub struct FlowBuilder<'dev, D: Domain> {
    dev: &'dev Dev<Started>,
    group: u32,
    priority: u32,
    items: Vec<it::Type>,
    actions: Vec<Action>,
    domain: PhantomData<D>,
}

impl<'dev, D: Domain> FlowBuilder<'dev, D> {
    pub(crate) fn start(dev: &'dev Dev<Started>) -> FlowBuilder<'dev, D> {
        FlowBuilder {
            dev,
            group: 0,
            priority: 0,
            items: Vec::new(),
            actions: Vec::new(),
            domain: PhantomData,
        }
    }

    /// Set the group (table) this rule lives in. Group 0 is the root; reach other groups via a
    /// [`jump`](Self::jump). Defaults to 0.
    pub fn group(mut self, group: FlowGroup) -> Self {
        self.group = group.0;
        self
    }

    /// Set the rule priority within its group (lower value is higher priority). Defaults to 0.
    pub fn priority(mut self, priority: Priority) -> Self {
        self.priority = priority.0;
        self
    }

    /// Match the presence of an Ethernet header.
    pub fn match_eth(mut self) -> Self {
        self.items.push(it::RTE_FLOW_ITEM_TYPE_ETH);
        self
    }

    /// Match the presence of an IPv4 header.
    pub fn match_ipv4(mut self) -> Self {
        self.items.push(it::RTE_FLOW_ITEM_TYPE_IPV4);
        self
    }

    /// Match the presence of a UDP header.
    pub fn match_udp(mut self) -> Self {
        self.items.push(it::RTE_FLOW_ITEM_TYPE_UDP);
        self
    }

    /// Redirect matching packets to another group (a JUMP action).
    pub fn jump(mut self, group: FlowGroup) -> Self {
        self.actions
            .push(Action::Jump(rte_flow_action_jump { group: group.0 }));
        self
    }

    /// Attach a MARK to matching packets, delivered to software in the mbuf
    /// ([`Mbuf::rx_mark`](crate::mem::Mbuf::rx_mark)).
    pub fn mark(mut self, mark: Mark) -> Self {
        self.actions
            .push(Action::Mark(rte_flow_action_mark { id: mark.0 }));
        self
    }

    /// Steer matching packets to a receive queue.
    pub fn queue(mut self, queue: RxQueueIndex) -> Self {
        self.actions.push(Action::Queue(rte_flow_action_queue {
            index: queue.as_u16(),
        }));
        self
    }

    /// Drop matching packets.
    pub fn drop(mut self) -> Self {
        self.actions.push(Action::Drop);
        self
    }

    /// Lower the accumulated attributes, pattern, and actions into the `rte_flow` C arrays.
    ///
    /// The returned `items`/`actions` `Vec`s carry pointers into `self.actions`, so `self` must
    /// outlive their use (it does in [`create`](Self::create)/[`validate`](Self::validate)).
    fn lower(&self) -> (rte_flow_attr, Vec<rte_flow_item>, Vec<rte_flow_action>) {
        // SAFETY: `rte_flow_attr` is plain old data; an all-zero value is a valid empty attribute.
        let mut attr: rte_flow_attr = unsafe { core::mem::zeroed() };
        attr.group = self.group;
        attr.priority = self.priority;
        match D::DIRECTION {
            Direction::Ingress => attr.set_ingress(1),
            Direction::Egress => attr.set_egress(1),
            Direction::Transfer => attr.set_transfer(1),
        }

        let mut items: Vec<rte_flow_item> = Vec::with_capacity(self.items.len() + 1);
        for &type_ in &self.items {
            items.push(rte_flow_item {
                type_,
                spec: null(),
                last: null(),
                mask: null(),
            });
        }
        items.push(rte_flow_item {
            type_: it::RTE_FLOW_ITEM_TYPE_END,
            spec: null(),
            last: null(),
            mask: null(),
        });

        let mut actions: Vec<rte_flow_action> = Vec::with_capacity(self.actions.len() + 1);
        for action in &self.actions {
            actions.push(rte_flow_action {
                type_: action.type_(),
                conf: action.conf(),
            });
        }
        actions.push(rte_flow_action {
            type_: at::RTE_FLOW_ACTION_TYPE_END,
            conf: null(),
        });

        (attr, items, actions)
    }

    /// Ask the PMD whether this rule *could* be created, without installing it.
    ///
    /// Validation is a hint, not a guarantee: a NIC may pass validate yet fail create (resource
    /// exhaustion), and behavior is only truly confirmed by observing packets. Use it as a cheap
    /// capability probe, not as proof.
    pub fn validate(&self) -> Result<(), FlowError> {
        let (attr, items, actions) = self.lower();
        let mut error: rte_flow_error = unsafe { core::mem::zeroed() };
        // SAFETY: `attr`, `items`, `actions` (and the action configs in `self`) all outlive this
        // call; the arrays are END-terminated and the pointers are non-dangling.
        let ret = unsafe {
            rte_flow_validate(
                self.port(),
                &attr,
                items.as_ptr(),
                actions.as_ptr(),
                &mut error,
            )
        };
        if ret == 0 {
            Ok(())
        } else {
            Err(FlowError::from_raw(&error))
        }
    }

    /// Install the rule, returning an RAII [`FlowRule`] handle bound to the device.
    pub fn create(self) -> Result<FlowRule<'dev>, FlowError> {
        let port = self.dev.info.index();
        let (attr, items, actions) = self.lower();
        let mut error: rte_flow_error = unsafe { core::mem::zeroed() };
        // SAFETY: `attr`, `items`, `actions`, and the action configs owned by `self` all outlive
        // this call; the arrays are END-terminated and the pointers are non-dangling. The PMD
        // copies what it needs before returning.
        let flow = unsafe {
            rte_flow_create(
                port.as_u16(),
                &attr,
                items.as_ptr(),
                actions.as_ptr(),
                &mut error,
            )
        };
        match NonNull::new(flow) {
            Some(flow) => Ok(FlowRule::new(port, flow)),
            None => Err(FlowError::from_raw(&error)),
        }
    }

    fn port(&self) -> u16 {
        self.dev.info.index().as_u16()
    }
}
