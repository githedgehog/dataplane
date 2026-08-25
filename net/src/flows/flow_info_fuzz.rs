// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![cfg(test)]

use crate::FlowKey;
use crate::flows::FlowInfoFlags;
use crate::flows::flow_info::{FlowInfo, FlowInfoError, FlowStatus};
use bolero::TypeGenerator;
use clock::Duration;

#[derive(Debug, Clone, Copy, TypeGenerator)]
struct Millis(u16);

impl Millis {
    fn duration(self) -> Duration {
        Duration::from_millis(u64::from(self.0))
    }
}

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

#[derive(Debug, Clone, Copy, TypeGenerator)]
enum Op {
    ExtendChecked(Millis),
    ExtendUnchecked(Millis),
    ResetChecked(Millis),
    ResetUnchecked(Millis),
    SetStatus(Status),
    Invalidate,
    Advance(Millis),
}

fn key(port: u16) -> FlowKey {
    FlowKey::new(
        None,
        crate::flows::flow_key::FlowAddrs::V4 {
            src: crate::ipv4::UnicastIpv4Addr::new(
                "10.0.0.1".parse().unwrap_or_else(|_| unreachable!()),
            )
            .unwrap_or_else(|_| unreachable!()),
            dst: "10.0.0.2".parse().unwrap_or_else(|_| unreachable!()),
        },
        crate::IpProtoKey::Udp(crate::UdpProtoKey {
            src_port: crate::udp::UdpPort::new_checked(port.max(1))
                .unwrap_or_else(|_| unreachable!()),
            dst_port: crate::udp::UdpPort::new_checked(80).unwrap_or_else(|_| unreachable!()),
        }),
    )
}

fn flow() -> FlowInfo {
    let info = FlowInfo::new(key(1024), clock::now() + Duration::from_secs(1));
    info.update_status(FlowStatus::Active);
    info
}

fn paused(body: impl FnOnce()) {
    // nosemgrep: rust-no-direct-std-sync-import
    static CLOCK: std::sync::LazyLock<clock::virtual_time::Paused> =
        std::sync::LazyLock::new(clock::virtual_time::Paused::new); // nosemgrep: rust-no-direct-std-sync-import
    CLOCK.block_on(async { body() });
}

#[test]
fn expiry_never_moves_backwards() {
    bolero::check!()
        .with_type::<Vec<Op>>()
        .for_each(|ops: &Vec<Op>| {
            paused(|| {
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

#[test]
fn a_refused_refresh_leaves_the_deadline_alone() {
    bolero::check!().with_type::<(Status, Millis)>().for_each(
        |(status, millis): &(Status, Millis)| {
            paused(|| {
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
            });
        },
    );
}

#[test]
fn a_refresh_is_permitted_exactly_when_the_status_allows() {
    bolero::check!().with_type::<(Status, Millis)>().for_each(
        |(status, millis): &(Status, Millis)| {
            paused(|| {
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
            });
        },
    );
}

#[test]
fn invalidating_is_idempotent_and_cancels_the_timer() {
    bolero::check!()
        .with_type::<Status>()
        .for_each(|status: &Status| {
            paused(|| {
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

#[test]
fn a_related_pair_refers_to_its_partner() {
    bolero::check!()
        .with_type::<(u16, u16)>()
        .for_each(|(a, b): &(u16, u16)| {
            paused(|| {
                let (one, two) = (key(*a), key(b.wrapping_add(1)));
                let built = FlowInfo::related_pair(
                    clock::now() + Duration::from_secs(1),
                    one,
                    FlowInfoFlags::INITIATOR,
                    two,
                    FlowInfoFlags::default(),
                );

                let Ok((first, second)) = built else {
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

#[test]
fn the_unchecked_refreshes_move_the_deadline_exactly() {
    bolero::check!()
        .with_type::<(Millis, Millis)>()
        .for_each(|(a, b): &(Millis, Millis)| {
            paused(|| {
                let (extend, reset) = (a.duration(), b.duration());

                let subject = flow();
                let before = subject.expires_at();
                subject.extend_expiry_unchecked(extend);
                assert_eq!(
                    subject.expires_at(),
                    before + extend,
                    "an unchecked extension must add exactly its duration"
                );

                let subject = flow();
                let target = clock::now() + reset;
                if target < subject.expires_at() {
                    assert!(
                        matches!(
                            subject.reset_expiry_unchecked(reset),
                            Err(FlowInfoError::TimeoutUnchanged)
                        ),
                        "a reset that moves the deadline earlier must be refused"
                    );
                } else {
                    assert!(subject.reset_expiry_unchecked(reset).is_ok());
                    assert_eq!(
                        subject.expires_at(),
                        target,
                        "an accepted reset must land on now + duration, exactly"
                    );
                }

                let subject = flow();
                let long = reset + Duration::from_secs(1);
                assert!(subject.reset_expiry_unchecked(long).is_ok());
                let held = subject.expires_at();
                assert!(
                    subject.reset_expiry_unchecked(long).is_ok(),
                    "resetting to the deadline already held must be accepted, not refused"
                );
                assert_eq!(subject.expires_at(), held, "and must leave it where it was");
            });
        });
}

#[test]
fn a_flow_is_active_exactly_when_its_status_says_so() {
    bolero::check!()
        .with_type::<Status>()
        .for_each(|status: &Status| {
            paused(|| {
                let want = FlowStatus::from(*status);
                let flow = flow();
                flow.update_status(want);
                assert_eq!(
                    flow.is_active(),
                    want == FlowStatus::Active,
                    "is_active disagreed with the status it was asked about"
                );
            });
        });
}

#[test]
fn a_flow_built_with_a_status_has_it() {
    bolero::check!()
        .with_type::<(u16, Status)>()
        .for_each(|(port, status): &(u16, Status)| {
            paused(|| {
                let want = FlowStatus::from(*status);
                let flow = FlowInfo::new_with_status(
                    key(*port),
                    clock::now() + Duration::from_secs(1),
                    want,
                );
                assert_eq!(
                    flow.status(),
                    want,
                    "the status asked for was not the one built"
                );
            });
        });
}

#[test]
fn a_genid_is_remembered_and_reaches_the_partner() {
    bolero::check!()
        .with_type::<(u16, u16, i64)>()
        .for_each(|(a, b, genid): &(u16, u16, i64)| {
            paused(|| {
                let (one, two) = (key(*a), key(b.wrapping_add(1)));
                let Ok((first, second)) = FlowInfo::related_pair(
                    clock::now() + Duration::from_secs(1),
                    one,
                    FlowInfoFlags::INITIATOR,
                    two,
                    FlowInfoFlags::default(),
                ) else {
                    return;
                };

                first.set_genid(*genid);
                assert_eq!(
                    first.genid(),
                    *genid,
                    "a genid must read back as it was set"
                );
                assert_ne!(
                    second.genid(),
                    *genid,
                    "setting one half's genid must not reach the other"
                );

                let paired = genid.wrapping_add(1);
                first.set_genid_pair(paired);
                assert_eq!(first.genid(), paired);
                assert_eq!(
                    second.genid(),
                    paired,
                    "set_genid_pair must reach the partner, or the halves disagree about which \
                     configuration they belong to"
                );
            });
        });
}

#[test]
fn each_flag_predicate_answers_for_its_own_bit() {
    bolero::check!()
        .with_type::<(u16, u16, u8)>()
        .for_each(|(a, b, bits): &(u16, u16, u8)| {
            paused(|| {
                let flags = FlowInfoFlags::from_bits_truncate(*bits);
                let (one, two) = (key(*a), key(b.wrapping_add(1)));
                let Ok((first, _second)) = FlowInfo::related_pair(
                    clock::now() + Duration::from_secs(1),
                    one,
                    flags,
                    two,
                    FlowInfoFlags::default(),
                ) else {
                    return;
                };

                let got = first.get_flags();
                assert_eq!(got, flags, "the flags read back must be the ones set");
                assert_eq!(
                    got.requires_static_nat_src(),
                    flags.contains(FlowInfoFlags::REQ_STATIC_NAT_SRC),
                    "the source predicate answered for the wrong bit"
                );
                assert_eq!(
                    got.requires_static_nat_dst(),
                    flags.contains(FlowInfoFlags::REQ_STATIC_NAT_DST),
                    "the destination predicate answered for the wrong bit"
                );
                assert_eq!(
                    got.is_initiator(),
                    flags.contains(FlowInfoFlags::INITIATOR),
                    "the initiator predicate answered for the wrong bit"
                );
            });
        });
}

#[test]
fn the_destination_vpc_is_remembered() {
    bolero::check!()
        .with_type::<Option<u32>>()
        .for_each(|vni: &Option<u32>| {
            paused(|| {
                let want = vni
                    .and_then(|v| crate::vxlan::Vni::new_checked(v % 0x00FF_FFFF).ok())
                    .map(crate::packet::VpcDiscriminant::from_vni);
                let flow = flow();
                flow.locked.write().dst_vpcd = want;
                assert_eq!(
                    flow.get_dst_vpcd(),
                    want,
                    "the destination vpc read back must be the one stamped"
                );
            });
        });
}
