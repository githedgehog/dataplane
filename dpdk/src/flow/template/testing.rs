// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Fault injection for template operations, without EAL or a NIC.
//!
//! Available only in tests or with `template-test`. Calls outside an active fixture use DPDK.

#![allow(clippy::unwrap_used)] // Misconfigured fixtures are test failures.

use super::{PortTemplates, TemplateFlows};
use crate::dev::DevIndex;
use alloc::rc::Rc;
use core::cell::RefCell;
use core::ffi::c_void;
use core::marker::PhantomData;
use std::collections::VecDeque;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Outcome {
    Success,
    Reject,
    PushError,
    PullError,
    Timeout,
    FailedCompletion,
}

#[derive(Default)]
struct Pmd {
    next_id: usize,
    failures: VecDeque<(&'static str, usize, Outcome)>,
    pending: VecDeque<(*mut c_void, Outcome)>,
    calls: Vec<&'static str>,
}

impl Pmd {
    fn pointer<T>(&mut self) -> *mut T {
        self.next_id += 1;
        core::ptr::without_provenance_mut(self.next_id)
    }

    fn call(&mut self, name: &'static str) -> Outcome {
        self.calls.push(name);
        if let Some((operation, skip, _)) = self.failures.front_mut()
            && *operation == name
        {
            if *skip == 0 {
                return self.failures.pop_front().unwrap().2;
            }
            *skip -= 1;
        }
        Outcome::Success
    }

    fn enqueue(&mut self, name: &'static str, tag: *mut c_void) -> bool {
        let outcome = self.call(name);
        if outcome == Outcome::Reject {
            return false;
        }
        self.pending.push_back((tag, outcome));
        true
    }
}

thread_local! {
    static PMD: RefCell<Option<Pmd>> = const { RefCell::new(None) };
}

pub struct Fixture {
    templates: PortTemplates,
    _thread: PhantomData<Rc<()>>,
}

impl Fixture {
    /// Intercept template operations on this thread until the fixture is dropped.
    ///
    /// # Panics
    ///
    /// Panics if another fixture is active on this thread.
    #[must_use]
    pub fn new() -> Self {
        PMD.with(|pmd| assert!(pmd.replace(Some(Pmd::default())).is_none()));
        Fixture {
            templates: PortTemplates::default(),
            _thread: PhantomData,
        }
    }

    /// A template context using the simulated port.
    pub fn flows(&self) -> TemplateFlows<'_> {
        TemplateFlows {
            port: DevIndex(0),
            live_rules: &self.templates.live_rules,
            in_use: &self.templates.in_use,
            // Missing completions are reported once spinning finds nothing, without sleeping.
            timeout: core::time::Duration::ZERO,
            last_op: &self.templates.last_op,
            _thread: PhantomData,
        }
    }

    /// Queue an outcome for the next call to `name`. Faults are consumed in order.
    pub fn fail(&self, name: &'static str, outcome: Outcome) {
        self.fail_after(name, 0, outcome);
    }

    /// Queue an outcome after `skip` matching calls have succeeded.
    pub fn fail_after(&self, name: &'static str, skip: usize, outcome: Outcome) {
        PMD.with(|pmd| {
            pmd.borrow_mut()
                .as_mut()
                .unwrap()
                .failures
                .push_back((name, skip, outcome))
        });
    }

    /// Change the oldest uncollected completion, for tests of late completions.
    ///
    /// # Panics
    ///
    /// Panics if no operation is pending.
    pub fn complete_next(&self, outcome: Outcome) {
        PMD.with(|pmd| {
            pmd.borrow_mut()
                .as_mut()
                .unwrap()
                .pending
                .front_mut()
                .unwrap()
                .1 = outcome
        });
    }

    /// The number of rules whose native removal has not been confirmed.
    #[must_use]
    pub fn live_rules(&self) -> usize {
        self.templates.live_rules()
    }

    /// The number of calls made to `name`.
    #[must_use]
    pub fn calls(&self, name: &str) -> usize {
        PMD.with(|pmd| {
            pmd.borrow()
                .as_ref()
                .unwrap()
                .calls
                .iter()
                .filter(|&&n| n == name)
                .count()
        })
    }
}

impl Default for Fixture {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        PMD.with(|pmd| pmd.replace(None));
    }
}

/// Only calls on a test thread with an active fixture are intercepted. Other tests use DPDK.
pub(crate) mod ffi {
    use super::{Outcome, PMD};
    use core::ffi::c_void;
    pub use dpdk_sys::*;

    macro_rules! intercept {
        ($name:ident($($arg:ident: $ty:ty),* $(,)?) -> $ret:ty, |$pmd:ident| $body:expr) => {
            #[allow(clippy::too_many_arguments)] // Match the DPDK ABI.
            pub(crate) unsafe fn $name($($arg: $ty),*) -> $ret {
                if let Some(result) = PMD.with(|state| state.borrow_mut().as_mut().map(|$pmd| $body)) {
                    return result;
                }
                // SAFETY: the caller supplies the same arguments and preconditions as DPDK.
                unsafe { dpdk_sys::$name($($arg),*) }
            }
        }
    }

    intercept!(
        rte_flow_pattern_template_create(
            port: u16,
            attr: *const rte_flow_pattern_template_attr,
            items: *const rte_flow_item,
            error: *mut rte_flow_error,
        ) -> *mut rte_flow_pattern_template,
        |pmd| pmd.pointer()
    );
    intercept!(
        rte_flow_actions_template_create(
            port: u16,
            attr: *const rte_flow_actions_template_attr,
            actions: *const rte_flow_action,
            masks: *const rte_flow_action,
            error: *mut rte_flow_error,
        ) -> *mut rte_flow_actions_template,
        |pmd| pmd.pointer()
    );
    intercept!(
        rte_flow_template_table_create(
            port: u16,
            attr: *const rte_flow_template_table_attr,
            patterns: *mut *mut rte_flow_pattern_template,
            np: u8,
            actions: *mut *mut rte_flow_actions_template,
            na: u8,
            error: *mut rte_flow_error,
        ) -> *mut rte_flow_template_table,
        |pmd| pmd.pointer()
    );
    intercept!(
        rte_mtr_meter_profile_add(
            port: u16,
            id: u32,
            profile: *mut rte_mtr_meter_profile,
            error: *mut rte_mtr_error,
        ) -> i32,
        |pmd| {
            pmd.call("profile_add");
            0
        }
    );
    intercept!(
        rte_mtr_meter_profile_get(
            port: u16,
            id: u32,
            error: *mut rte_mtr_error,
        ) -> *mut rte_flow_meter_profile,
        |pmd| pmd.pointer()
    );
    intercept!(
        rte_mtr_meter_profile_delete(port: u16, id: u32, error: *mut rte_mtr_error) -> i32,
        |pmd| {
            pmd.call("profile_delete");
            0
        }
    );
    intercept!(
        rte_flow_pattern_template_destroy(
            port: u16,
            pattern: *mut rte_flow_pattern_template,
            error: *mut rte_flow_error,
        ) -> i32,
        |pmd| {
            pmd.call("pattern_destroy");
            0
        }
    );
    intercept!(
        rte_flow_actions_template_destroy(
            port: u16,
            actions: *mut rte_flow_actions_template,
            error: *mut rte_flow_error,
        ) -> i32,
        |pmd| {
            pmd.call("actions_destroy");
            0
        }
    );
    intercept!(
        rte_flow_template_table_destroy(
            port: u16,
            table: *mut rte_flow_template_table,
            error: *mut rte_flow_error,
        ) -> i32,
        |pmd| if pmd.call("table_destroy") == Outcome::Reject {
            -1
        } else {
            0
        }
    );
    intercept!(
        rte_flow_async_create(
            port: u16,
            queue: u32,
            attr: *const rte_flow_op_attr,
            table: *mut rte_flow_template_table,
            items: *const rte_flow_item,
            pi: u8,
            actions: *const rte_flow_action,
            ai: u8,
            tag: *mut c_void,
            error: *mut rte_flow_error,
        ) -> *mut rte_flow,
        |pmd| if pmd.enqueue("create", tag) {
            pmd.pointer()
        } else {
            core::ptr::null_mut()
        }
    );
    intercept!(
        rte_flow_async_actions_update(
            port: u16,
            queue: u32,
            attr: *const rte_flow_op_attr,
            flow: *mut rte_flow,
            actions: *const rte_flow_action,
            ai: u8,
            tag: *mut c_void,
            error: *mut rte_flow_error,
        ) -> i32,
        |pmd| if pmd.enqueue("update", tag) { 0 } else { -1 }
    );
    intercept!(
        rte_flow_async_destroy(
            port: u16,
            queue: u32,
            attr: *const rte_flow_op_attr,
            flow: *mut rte_flow,
            tag: *mut c_void,
            error: *mut rte_flow_error,
        ) -> i32,
        |pmd| if pmd.enqueue("destroy", tag) { 0 } else { -1 }
    );
    intercept!(
        rte_flow_async_action_handle_create(
            port: u16,
            queue: u32,
            attr: *const rte_flow_op_attr,
            conf: *const rte_flow_indir_action_conf,
            action: *const rte_flow_action,
            tag: *mut c_void,
            error: *mut rte_flow_error,
        ) -> *mut rte_flow_action_handle,
        |pmd| if pmd.enqueue("meter_create", tag) {
            pmd.pointer()
        } else {
            core::ptr::null_mut()
        }
    );
    intercept!(
        rte_flow_async_action_handle_destroy(
            port: u16,
            queue: u32,
            attr: *const rte_flow_op_attr,
            handle: *mut rte_flow_action_handle,
            tag: *mut c_void,
            error: *mut rte_flow_error,
        ) -> i32,
        |pmd| if pmd.enqueue("meter_destroy", tag) {
            0
        } else {
            -1
        }
    );
    intercept!(
        rte_flow_query(
            port: u16,
            flow: *mut rte_flow,
            actions: *const rte_flow_action,
            data: *mut c_void,
            error: *mut rte_flow_error,
        ) -> i32,
        |pmd| {
            pmd.call("query");
            0
        }
    );
    intercept!(
        rte_flow_push(port: u16, queue: u32, error: *mut rte_flow_error) -> i32,
        |pmd| if pmd
            .pending
            .front()
            .is_some_and(|(_, outcome)| *outcome == Outcome::PushError)
        {
            pmd.pending.front_mut().unwrap().1 = Outcome::Success;
            -1
        } else {
            0
        }
    );
    intercept!(
        rte_flow_pull(
            port: u16,
            queue: u32,
            result: *mut rte_flow_op_result,
            n: u16,
            error: *mut rte_flow_error,
        ) -> i32,
        |pmd| {
            match pmd.pending.front() {
                Some((_, Outcome::PullError)) => {
                    pmd.pending.front_mut().unwrap().1 = Outcome::Success;
                    -1
                }
                Some((_, Outcome::Timeout)) | None => 0,
                Some(_) => {
                    let (tag, outcome) = pmd.pending.pop_front().unwrap();
                    // SAFETY: the production caller supplies room for one result.
                    unsafe {
                        result.write(rte_flow_op_result {
                            user_data: tag,
                            status: if outcome == Outcome::FailedCompletion {
                                rte_flow_op_status::RTE_FLOW_OP_ERROR
                            } else {
                                rte_flow_op_status::RTE_FLOW_OP_SUCCESS
                            },
                        });
                    }
                    1
                }
            }
        }
    );
}
