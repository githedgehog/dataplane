// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use std::collections::HashMap;
use std::net::IpAddr;

use netgauze_bgp_pkt::{
    nlri::{MPReachNLRI, MPUnreachNLRI},
    wire::deserializer::nlri::RouteType,
    BgpMessage,
};
use netgauze_bmp_pkt::{
    peer::{PeerHeader, PeerType},
    v3::BmpMessageValue as V3,
    BmpMessage,
};

use crate::config::internal::status::{
    BgpMessageCounters, BgpMessages, BgpNeighborPrefixes, BgpNeighborSessionState,
    BgpNeighborStatus, BgpStatus, BgpVrfStatus, DataplaneStatus,
};

pub fn hande_bmp_message(status: &mut DataplaneStatus, msg: &BmpMessage) {
    // smatov: frr bmp v3 only for now
    // but we maybe will extend it later
    if let BmpMessage::V3(v) = msg {
        handle(status, v);
    }
}


fn handle(status: &mut DataplaneStatus, m: &V3) {
    match m {
        V3::PeerUp(n) => {
            let (vrf, key) = peer_keys(&n.common_header.peer_header);
            let st = ensure_neighbor(status, &vrf, &key);
            st.enabled = true;
            st.session_state = BgpNeighborSessionState::Established;
            st.established_transitions = st.established_transitions.saturating_add(1);
            st.peer_as = n.common_header.peer_as().into();
            st.local_as = n.common_header.local_as().into();
            st.remote_router_id = n.common_header.router_id().to_string();
            st.peer_port = n.local_port as u32;

            // PeerUp carries both Open messages (rx+tx) so count both.
            bump_msg(&mut st.messages, true, BgpMsgKind::Open);
            bump_msg(&mut st.messages, false, BgpMsgKind::Open);
        }
        V3::PeerDown(n) => {
            let (vrf, key) = peer_keys(&n.common_header.peer_header);
            let st = ensure_neighbor(status, &vrf, &key);
            st.session_state = BgpNeighborSessionState::Idle;
            st.last_reset_reason = peer_down_reason_v3(n);
            st.connections_dropped = st.connections_dropped.saturating_add(1);
        }
        V3::RouteMonitoring(rm) => {
            let (vrf, key) = peer_keys(&rm.common_header.peer_header);
            let st = ensure_neighbor(status, &vrf, &key);
            let post_policy = is_post_policy(&rm.common_header.peer_header);

            apply_bgp_pdu(
                &mut st.messages,
                &mut st.ipv4_unicast_prefixes,
                &mut st.ipv6_unicast_prefixes,
                &rm.bgp_message,
                post_policy,
            );
        }
        V3::StatisticsReport(_sr) => {
            // noop for status for now
        }
        V3::Initiation(_) | V3::Termination(_) | V3::RouteMirroring(_) => {
            // no-op for status
        }
    }
}

fn peer_keys(ph: &PeerHeader) -> (String, String) {
    let vrf = match ph.peer_type() {
        PeerType::GlobalInstance | PeerType::L3vpn => {
            if let Some(d) = ph.peer_distinguisher() {
                format!("pdx:{d}") // smatov: later add translation from VNI to VRF name here
            } else {
                "default".to_string()
            }
        }
        _ => "default".to_string(),
    };
    let key = match ph.peer_address() {
        IpAddr::V4(a) => a.to_string(),
        IpAddr::V6(a) => a.to_string(),
    };
    (vrf, key)
}

fn ensure_neighbor<'a>(
    status: &'a mut DataplaneStatus,
    vrf: &str,
    key: &str,
) -> &'a mut BgpNeighborStatus {
    if status.bgp.is_none() {
        status.set_bgp(BgpStatus { vrfs: HashMap::new() });
    }
    let bgp = status.bgp.as_mut().unwrap();
    let vrf_entry = bgp
        .vrfs
        .entry(vrf.to_string())
        .or_insert_with(|| BgpVrfStatus { neighbors: HashMap::new() });
    vrf_entry.neighbors.entry(key.to_string()).or_insert_with(|| BgpNeighborStatus {
        enabled: true,
        local_as: 0,
        peer_as: 0,
        peer_port: 0,
        peer_group: String::new(),
        remote_router_id: String::new(),
        session_state: BgpNeighborSessionState::Idle,
        connections_dropped: 0,
        established_transitions: 0,
        last_reset_reason: String::new(),
        messages: Some(BgpMessages {
            received: Some(BgpMessageCounters::new()),
            sent: Some(BgpMessageCounters::new()),
        }),
        ipv4_unicast_prefixes: Some(BgpNeighborPrefixes::default()),
        ipv6_unicast_prefixes: Some(BgpNeighborPrefixes::default()),
        l2vpn_evpn_prefixes: None,
    })
}

fn is_post_policy(ph: &PeerHeader) -> bool {
    ph.is_post_policy()
}

#[derive(Clone, Copy)]
enum BgpMsgKind {
    Open,
    Keepalive,
    Notification,
    Update,
    RouteRefresh,
    Capability,
}

fn bump_msg(messages: &mut Option<BgpMessages>, received: bool, kind: BgpMsgKind) {
    let m = messages.get_or_insert(BgpMessages { received: None, sent: None });
    let ctrs = if received {
        m.received.get_or_insert(BgpMessageCounters::new())
    } else {
        m.sent.get_or_insert(BgpMessageCounters::new())
    };
    match kind {
        BgpMsgKind::Open => ctrs.open = ctrs.open.saturating_add(1),
        BgpMsgKind::Keepalive => ctrs.keepalive = ctrs.keepalive.saturating_add(1),
        BgpMsgKind::Notification => ctrs.notification = ctrs.notification.saturating_add(1),
        BgpMsgKind::Update => ctrs.update = ctrs.update.saturating_add(1),
        BgpMsgKind::RouteRefresh => ctrs.route_refresh = ctrs.route_refresh.saturating_add(1),
        BgpMsgKind::Capability => ctrs.capability = ctrs.capability.saturating_add(1),
    }
}

fn apply_bgp_pdu(
    messages: &mut Option<BgpMessages>,
    v4pfx: &mut Option<BgpNeighborPrefixes>,
    v6pfx: &mut Option<BgpNeighborPrefixes>,
    pdu: &BgpMessage,
    post_policy: bool,
) {
    match pdu {
        BgpMessage::Open(_) => bump_msg(messages, true, BgpMsgKind::Open),
        BgpMessage::KeepAlive => bump_msg(messages, true, BgpMsgKind::Keepalive),
        BgpMessage::Notification(_) => bump_msg(messages, true, BgpMsgKind::Notification),
        BgpMessage::RouteRefresh(_) => bump_msg(messages, true, BgpMsgKind::RouteRefresh),
        BgpMessage::Update(upd) => {
            bump_msg(messages, true, BgpMsgKind::Update);

            // default nlri v4
            let a4 = upd.nlri.len() as u32;
            if a4 > 0 {
                let v = v4pfx.get_or_insert_with(Default::default);
                if post_policy {
                    v.sent = v.sent.saturating_add(a4);
                } else {
                    v.received = v.received.saturating_add(a4);
                    v.received_pre_policy = v.received_pre_policy.saturating_add(a4);
                }
            }

            // unreach nlri v4
            for attr in &upd.path_attributes {
                if let Some(mp) = attr.get_mp_reach_nlri() {
                    account_mp_reach(mp, post_policy, v4pfx, v6pfx);
                }
                if let Some(mpu) = attr.get_mp_unreach_nlri() {
                    account_mp_unreach(mpu, post_policy, v4pfx, v6pfx);
                }
            }
        }
        BgpMessage::Unknown(_) => { /* todo: what should we do here? */ }
    }
}

fn account_mp_reach(
    mp: &MPReachNLRI,
    post_policy: bool,
    v4pfx: &mut Option<BgpNeighborPrefixes>,
    v6pfx: &mut Option<BgpNeighborPrefixes>,
) {
    let cnt = mp.nlri().len() as u32;
    if cnt == 0 { return; }
    match mp.route_type() {
        RouteType::Ipv4Unicast => {
            let v = v4pfx.get_or_insert_with(Default::default);
            if post_policy { v.sent = v.sent.saturating_add(cnt); }
            else {
                v.received = v.received.saturating_add(cnt);
                v.received_pre_policy = v.received_pre_policy.saturating_add(cnt);
            }
        }
        RouteType::Ipv6Unicast => {
            let v = v6pfx.get_or_insert_with(Default::default);
            if post_policy { v.sent = v.sent.saturating_add(cnt); }
            else {
                v.received = v.received.saturating_add(cnt);
                v.received_pre_policy = v.received_pre_policy.saturating_add(cnt);
            }
        }
        _ => { /* todo: evpn */ }
    }
}

fn account_mp_unreach(
    mpu: &MPUnreachNLRI,
    _post_policy: bool,
    v4pfx: &mut Option<BgpNeighborPrefixes>,
    v6pfx: &mut Option<BgpNeighborPrefixes>,
) {
    let cnt = mpu.nlri().len() as u32;
    if cnt == 0 { return; }
    match mpu.route_type() {
        RouteType::Ipv4Unicast => {
            let _v = v4pfx.get_or_insert_with(Default::default);
            let _ = cnt; // smatov: add explicit counters later
        }
        RouteType::Ipv6Unicast => {
            let _v = v6pfx.get_or_insert_with(Default::default);
            let _ = cnt;
        }
        _ => {}
    }
}

fn peer_down_reason_v3(n: &netgauze_bmp_pkt::v3::PeerDownNotification) -> String {
    use netgauze_bmp_pkt::v3::PeerDownReason as R;
    match n.reason {
        R::LocalSystemNotification => "local-notification".into(),
        R::LocalSystemNoNotification => "local-no-notification".into(),
        R::RemoteSystemNotification => "remote-notification".into(),
        R::RemoteSystemNoNotification => "remote-no-notification".into(),
        R::PeerDeconfigured => "peer-deconfigured".into(),
        R::CommunicationLost => "communication-lost".into(),
        R::Unknown(v) => format!("unknown({v})"),
    }
}
