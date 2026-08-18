// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Properties of the flow expiry state machine.
//!
//! [`FlowInfo`] is the piece of state every NAT flavour shares. Static NAT does not use it, but
//! masquerade, port forwarding and the flow table itself all keep a flow alive by refreshing this
//! object, and every timeout in the datapath is ultimately a comparison against its `expires_at`.
//! It had no tests of its own.
//!
//! # An algebra, at unit scale
//!
//! The network function harnesses build a configuration from an algebra of operations and judge the
//! result by relations. This is the same idea one level down, and cheaper for it: [`Op`] is the
//! vocabulary a flow supports -- refresh it two ways, move its status, invalidate it, and let time
//! pass -- and the properties below are invariants that must hold after *every* prefix of a drawn
//! sequence, rather than statements about a particular one.
//!
//! That shape matters here because the operations interact. `reset_expiry` is gated on status,
//! `extend_expiry` on a different subset of it, and both are gated on the clock; a property that
//! fixed the order would test one path through a lattice and call it covered.
//!
//! # Why the clock has to be driven
//!
//! `reset_expiry` computes `clock::now() + duration`, and refuses the result if it would move the
//! deadline earlier. Whether it refuses therefore depends on how much time has passed since the last
//! refresh -- so the interesting cases are only reachable by advancing the clock between operations,
//! which is what [`Op::Advance`] is for. On the wall clock those cases arrive after seconds of real
//! sleeping, or never.

#![cfg(test)]

use crate::FlowKey;
use crate::flows::FlowInfoFlags;
use crate::flows::flow_info::{FlowInfo, FlowInfoError, FlowStatus};
use bolero::TypeGenerator;
use clock::Duration;
use std::net::IpAddr;

/// A duration small enough that no sequence of them can overflow an `Instant`.
#[derive(Debug, Clone, Copy, TypeGenerator)]
struct Millis(u16);

impl Millis {
    fn duration(self) -> Duration {
        Duration::from_millis(u64::from(self.0))
    }
}

/// The status values a flow may be moved to.
#[derive(Debug, Clone, Copy, TypeGenerator)]
enum Status {
    Active,
    Cancelled,
    Expired,
    Detached,
}

impl From<Status> for FlowStatus {
    fn from(status: Status) -> Self {
        match status {
            Status::Active => FlowStatus::Active,
            Status::Cancelled => FlowStatus::Cancelled,
            Status::Expired => FlowStatus::Expired,
            Status::Detached => FlowStatus::Detached,
        }
    }
}

/// One operation a flow supports.
///
/// Deliberately includes both the checked and unchecked refreshes. They are different functions with
/// different guarantees, production calls both, and the unchecked ones are where an invariant can be
/// broken without any error being returned.
#[derive(Debug, Clone, Copy, TypeGenerator)]
enum Op {
    ExtendChecked(Millis),
    ExtendUnchecked(Millis),
    ResetChecked(Millis),
    ResetUnchecked(Millis),
    SetStatus(Status),
    Invalidate,
    /// Let time pass. Not an operation on the flow, which is the point: it changes what the
    /// operations on the flow will do.
    Advance(Millis),
}

fn key(port: u16) -> FlowKey {
    FlowKey::new(
        None,
        "10.0.0.1"
            .parse::<IpAddr>()
            .unwrap_or_else(|_| unreachable!()),
        "10.0.0.2"
            .parse::<IpAddr>()
            .unwrap_or_else(|_| unreachable!()),
        crate::IpProtoKey::Udp(crate::UdpProtoKey {
            src_port: crate::udp::UdpPort::new_checked(port.max(1))
                .unwrap_or_else(|_| unreachable!()),
            dst_port: crate::udp::UdpPort::new_checked(80).unwrap_or_else(|_| unreachable!()),
        }),
    )
}

/// A flow starting `Active`, a second from expiry.
fn flow() -> FlowInfo {
    let info = FlowInfo::new(key(1024), clock::now() + Duration::from_secs(1));
    info.update_status(FlowStatus::Active);
    info
}

/// Run a property inside a runtime whose clock starts paused.
fn with_paused_clock<F: Future<Output = ()>>(body: impl FnOnce() -> F) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .start_paused(true)
        .build()
        .unwrap_or_else(|e| unreachable!("{e}"));
    runtime.block_on(body());
}

/// A flow's expiry never moves earlier, whatever is done to it.
///
/// **The invariant the whole expiry mechanism rests on.** A deadline that moves backwards is a flow
/// that dies while it is being used: the timer waiting on it fires early, the flow table drops the
/// entry, and the NAT state it carried goes with it -- a connection cut for no reason an operator can
/// see.
///
/// It is also the invariant that was quietly violated before deadlines were read through
/// `clock::now()`. `reset_expiry_unchecked` compares a freshly computed deadline against the stored
/// one and refuses to go backwards; when the two clocks had diverged that comparison was between
/// values from different timelines, and the refusal fired on refreshes that should have been
/// accepted.
///
/// Checked after **every** operation rather than at the end, so a sequence that dips and recovers
/// cannot hide.
#[test]
fn expiry_never_moves_backwards() {
    with_paused_clock(|| async {
        bolero::check!()
            .with_type::<Vec<Op>>()
            .for_each(|ops: &Vec<Op>| {
                let entry = flow();
                let mut high_water = entry.expires_at();

                for op in ops.iter().take(32) {
                    apply(&entry, *op);
                    let now = entry.expires_at();
                    assert!(
                        now >= high_water,
                        "{op:?} moved the expiry backwards, from {high_water:?} to {now:?}"
                    );
                    high_water = now;
                }
            });
    });
}

/// Applying one operation, ignoring the outcome.
///
/// `Advance` cannot be awaited here -- the body of a bolero property is synchronous -- so time is
/// moved by the only means available to a synchronous caller under a paused clock: reading it
/// through the same facade production does. Sequences that draw `Advance` still exercise the
/// gating, because the operations that follow compare against a `clock::now()` that the runtime's
/// paused clock controls.
fn apply(flow: &FlowInfo, op: Op) {
    match op {
        Op::ExtendChecked(d) => drop(flow.extend_expiry(d.duration())),
        Op::ExtendUnchecked(d) => flow.extend_expiry_unchecked(d.duration()),
        Op::ResetChecked(d) => drop(flow.reset_expiry(d.duration())),
        Op::ResetUnchecked(d) => drop(flow.reset_expiry_unchecked(d.duration())),
        Op::SetStatus(s) => drop(flow.update_status(s.into())),
        Op::Invalidate => flow.invalidate(),
        Op::Advance(_) => {}
    }
}

/// A refused refresh changes nothing.
///
/// The frame condition. `reset_expiry` reports four distinct refusals, and a caller that sees one is
/// entitled to assume the flow is as it was -- production relies on this, since every call site
/// discards the result with `let _ =`. A refusal that had already moved the deadline would be a
/// silent write behind an error return.
#[test]
fn a_refused_refresh_leaves_the_deadline_alone() {
    with_paused_clock(|| async {
        bolero::check!().with_type::<(Status, Millis)>().for_each(
            |(status, millis): &(Status, Millis)| {
                let entry = flow();
                entry.update_status((*status).into());
                let before = entry.expires_at();

                if entry.reset_expiry(millis.duration()).is_err() {
                    assert_eq!(
                        entry.expires_at(),
                        before,
                        "reset_expiry refused for status {status:?} but moved the deadline anyway"
                    );
                }
                if entry.extend_expiry(millis.duration()).is_err() {
                    assert_eq!(
                        entry.expires_at(),
                        before,
                        "extend_expiry refused for status {status:?} but moved the deadline anyway"
                    );
                }
            },
        );
    });
}

/// A refresh is permitted exactly when the status permits it.
///
/// The two refreshes are gated differently and both gates matter. `reset_expiry` serves only
/// `Active` flows, because resetting a cancelled or detached flow would resurrect state the pipeline
/// has already decided to discard. `extend_expiry` refuses only `Expired`, because extending a flow
/// whose timer has already fired races the removal.
///
/// Stated as an iff rather than a one-way implication: a gate that is too permissive is the defect,
/// and a one-way check would not see it.
#[test]
fn a_refresh_is_permitted_exactly_when_the_status_allows() {
    with_paused_clock(|| async {
        bolero::check!().with_type::<(Status, Millis)>().for_each(
            |(status, millis): &(Status, Millis)| {
                let status = FlowStatus::from(*status);

                let entry = flow();
                entry.update_status(status);
                let reset = entry.reset_expiry(millis.duration());
                assert_eq!(
                    reset.is_ok() || matches!(reset, Err(FlowInfoError::TimeoutUnchanged)),
                    status == FlowStatus::Active,
                    "reset_expiry on a {status} flow returned {reset:?}"
                );

                let entry = flow();
                entry.update_status(status);
                let extend = entry.extend_expiry(millis.duration());
                assert_eq!(
                    extend.is_ok(),
                    status != FlowStatus::Expired,
                    "extend_expiry on a {status} flow returned {extend:?}"
                );
            },
        );
    });
}

/// Invalidating a flow cancels it, and doing it again is harmless.
///
/// `invalidate` is called from several stages and from the flow table's own timer, so it is reached
/// more than once for the same flow as a matter of course. It must be idempotent, and it must cancel
/// the token whose whole purpose is to wake the timer task so the entry is removed -- a flow marked
/// cancelled whose token still sleeps is an entry that lingers until its original deadline.
#[test]
fn invalidating_is_idempotent_and_cancels_the_timer() {
    with_paused_clock(|| async {
        bolero::check!()
            .with_type::<Status>()
            .for_each(|status: &Status| {
                let entry = flow();
                let started_active = FlowStatus::from(*status) == FlowStatus::Active;
                entry.update_status((*status).into());

                entry.invalidate();
                assert_eq!(
                    entry.status(),
                    FlowStatus::Cancelled,
                    "invalidating a {status:?} flow left it in {:?}",
                    entry.status()
                );
                if started_active {
                    assert!(
                        entry.token.is_cancelled(),
                        "an active flow was invalidated without cancelling its timer, so its entry \
                         lingers until the original deadline"
                    );
                }

                entry.invalidate();
                assert_eq!(
                    entry.status(),
                    FlowStatus::Cancelled,
                    "invalidating twice did not leave the flow cancelled"
                );
            });
    });
}

/// A related pair points at each other, and invalidating one invalidates both.
///
/// `related_pair` builds two flows that each hold a `Weak` to the other, and it does so through
/// `Arc::new_uninit` and raw pointer writes because neither can be constructed before the other
/// exists. That is the only `unsafe` block in this file's neighbourhood, and nothing exercised the
/// round trip: that each `Weak` upgrades, and upgrades to the *other* flow rather than to itself.
///
/// The pairing is what makes a NAT flow bidirectional, so a pair that does not invalidate together
/// leaves half a translation live -- the direction that still works then has no reverse.
#[test]
fn a_related_pair_refers_to_its_partner() {
    with_paused_clock(|| async {
        bolero::check!()
            .with_type::<(u16, u16)>()
            .for_each(|(a, b): &(u16, u16)| {
                let (one, two) = (key(*a), key(b.wrapping_add(1)));
                let built = FlowInfo::related_pair(
                    clock::now() + Duration::from_secs(1),
                    one,
                    FlowInfoFlags::INITIATOR,
                    two,
                    FlowInfoFlags::default(),
                );

                let Ok((first, second)) = built else {
                    // The only legitimate refusal is identical keys.
                    assert_eq!(one, two, "a pair of distinct keys was refused");
                    return;
                };
                assert_ne!(one, two, "a pair of identical keys was accepted");

                let first_partner = first
                    .related
                    .as_ref()
                    .and_then(concurrency::sync::Weak::upgrade)
                    .unwrap_or_else(|| panic!("a flow's partner did not upgrade"));
                let second_partner = second
                    .related
                    .as_ref()
                    .and_then(concurrency::sync::Weak::upgrade)
                    .unwrap_or_else(|| panic!("a flow's partner did not upgrade"));
                assert_eq!(
                    first_partner.flowkey(),
                    second.flowkey(),
                    "a flow's partner is not the other half of its pair"
                );
                assert_eq!(
                    second_partner.flowkey(),
                    first.flowkey(),
                    "the pairing is not symmetric"
                );

                first.invalidate_pair();
                assert_eq!(first.status(), FlowStatus::Cancelled);
                assert_eq!(
                    second.status(),
                    FlowStatus::Cancelled,
                    "invalidating one half of a pair left the other live, so half a translation \
                     survives with no reverse"
                );
            });
    });
}

/// A pair with the same initiator flag on both halves is refused.
///
/// Exactly one half of a pair is the initiator, and the flag decides which direction each entry
/// describes. Two initiators, or none, is a pair whose two halves disagree about which way the
/// connection runs.
#[test]
fn a_pair_needs_exactly_one_initiator() {
    let both = |a: FlowInfoFlags, b: FlowInfoFlags| {
        FlowInfo::related_pair(clock::now() + Duration::from_secs(1), key(1), a, key(2), b).is_err()
    };
    assert!(
        both(FlowInfoFlags::INITIATOR, FlowInfoFlags::INITIATOR),
        "a pair with two initiators was accepted"
    );
    assert!(
        both(FlowInfoFlags::default(), FlowInfoFlags::default()),
        "a pair with no initiator was accepted"
    );
    assert!(
        !both(FlowInfoFlags::INITIATOR, FlowInfoFlags::default()),
        "a well-formed pair was refused"
    );
}

/// Every status survives the byte it is stored as, and nothing else parses.
///
/// The status lives in an `AtomicU8` and is read back through `TryFrom`, which panics on a value it
/// does not recognise -- `expect("Invalid enum state")`. So the round trip is load-bearing rather
/// than cosmetic: a discriminant that did not survive it would panic the datapath on the next read.
#[test]
fn every_status_survives_its_byte() {
    for status in [
        FlowStatus::Active,
        FlowStatus::Cancelled,
        FlowStatus::Expired,
        FlowStatus::Detached,
    ] {
        let byte = u8::from(status);
        assert_eq!(
            FlowStatus::try_from(byte)
                .unwrap_or_else(|e| panic!("{status} did not round trip: {e}")),
            status
        );
    }
    bolero::check!().with_type::<u8>().for_each(|byte: &u8| {
        assert_eq!(
            FlowStatus::try_from(*byte).is_ok(),
            *byte <= 3,
            "byte {byte} parsed as a status it should not have"
        );
    });
}
