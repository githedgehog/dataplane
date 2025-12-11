// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! BMP message handlers to update internal DataplaneStatus model.

use netgauze_bgp_pkt::BgpMessage;
use netgauze_bmp_pkt::v3::{
    BmpMessageValue, PeerDownNotificationMessage, PeerUpNotificationMessage,
    RouteMonitoringMessage, StatisticsReportMessage,
};
use netgauze_bmp_pkt::{BmpMessage, BmpPeerType};

use config::internal::status::{
    BgpMessageCounters, BgpMessages, BgpNeighborPrefixes, BgpNeighborSessionState,
    BgpNeighborStatus, BgpStatus, BgpVrfStatus, DataplaneStatus,
};

/// Update `DataplaneStatus` from a single BMP message.
pub fn handle_bmp_message(status: &mut DataplaneStatus, msg: &BmpMessage) {
    match msg {
        BmpMessage::V3(v) => match v {
            BmpMessageValue::PeerUpNotification(pu) => on_peer_up(status, pu),
            BmpMessageValue::PeerDownNotification(pd) => on_peer_down(status, pd),
            BmpMessageValue::RouteMonitoring(rm) => on_route_monitoring(status, rm),
            BmpMessageValue::StatisticsReport(sr) => on_statistics(status, sr),
            // The rest are currently ignored
            _ => {}
        },
        // V4 not handled yet
        BmpMessage::V4(_) => {}
    }
}
fn key_from_peer_header(peer: &netgauze_bmp_pkt::PeerHeader) -> String {
    // Build a stable-ish key: "<bgp_id>-<peer_as>-<ip|-none>-<rd?>"
    let id = peer.bgp_id();
    let asn = peer.peer_as();
    let ip = peer
        .address()
        .map(|a| a.to_string())
        .unwrap_or_else(|| "none".to_string());
    let rd = peer
        .rd()
        .map(|rd| format!("{rd:?}"))
        .unwrap_or_else(|| "no-rd".to_string());
    format!("{id}-{asn}-{ip}-{rd}")
}

fn get_vrf_from_peer_header(peer: &netgauze_bmp_pkt::PeerHeader) -> String {
    // If peer has an RD, use it as VRF view name; else "default"
    match peer.rd() {
        Some(rd) => format!("{rd:?}"),
        None => "default".to_string(),
    }
}

fn set_neighbor_session_state(n: &mut BgpNeighborStatus, st: BgpNeighborSessionState) {
    n.session_state = st;
}

fn ensure_bgp(status: &mut DataplaneStatus) -> &mut BgpStatus {
    if status.bgp.is_none() {
        status.bgp = Some(BgpStatus::default());
    }
    status.bgp.as_mut().unwrap()
}

fn ensure_vrf<'a>(bgp: &'a mut BgpStatus, vrf: &str) -> &'a mut BgpVrfStatus {
    bgp.vrfs.entry(vrf.to_string()).or_default()
}

fn ensure_neighbor<'a>(vrf: &'a mut BgpVrfStatus, neigh_key: &str) -> &'a mut BgpNeighborStatus {
    vrf.neighbors
        .entry(neigh_key.to_string())
        .or_insert_with(|| BgpNeighborStatus {
            enabled: true,
            ..BgpNeighborStatus::default()
        })
}

fn post_policy_from_peer_type(pt: BmpPeerType) -> bool {
    match pt {
        BmpPeerType::GlobalInstancePeer { post_policy, .. } => post_policy,
        BmpPeerType::RdInstancePeer { post_policy, .. } => post_policy,
        BmpPeerType::LocalInstancePeer { post_policy, .. } => post_policy,
        BmpPeerType::LocRibInstancePeer { .. } => false,
        BmpPeerType::Experimental251 { .. }
        | BmpPeerType::Experimental252 { .. }
        | BmpPeerType::Experimental253 { .. }
        | BmpPeerType::Experimental254 { .. } => false,
    }
}

fn on_peer_up(status: &mut DataplaneStatus, pu: &PeerUpNotificationMessage) {
    let peer = pu.peer_header();
    let vrf = get_vrf_from_peer_header(peer);
    let key = key_from_peer_header(peer);

    let bgp = ensure_bgp(status);
    let vrf_s = ensure_vrf(bgp, &vrf);
    let neigh = ensure_neighbor(vrf_s, &key);

    // Update some basic fields we know now
    neigh.peer_as = peer.peer_as();
    neigh.remote_router_id = peer.bgp_id().to_string();
    neigh.peer_port = pu.remote_port().unwrap_or_default() as u32;
    set_neighbor_session_state(neigh, BgpNeighborSessionState::Established);
    if let BgpMessage::Open(open) = pu.sent_message() {
        neigh.local_as = open.my_as() as u32;
    }

    if neigh.messages.is_none() {
        neigh.messages = Some(BgpMessages {
            received: Some(BgpMessageCounters::new()),
            sent: Some(BgpMessageCounters::new()),
        });
    }
}

fn on_peer_down(status: &mut DataplaneStatus, pd: &PeerDownNotificationMessage) {
    let peer = pd.peer_header();
    let vrf = get_vrf_from_peer_header(peer);
    let key = key_from_peer_header(peer);

    if let Some(bgp) = status.bgp.as_mut() {
        if let Some(vrf_s) = bgp.vrfs.get_mut(&vrf) {
            if let Some(neigh) = vrf_s.neighbors.get_mut(&key) {
                set_neighbor_session_state(neigh, BgpNeighborSessionState::Idle);
                neigh.connections_dropped = neigh.connections_dropped.saturating_add(1);
            }
        }
    }
}

fn on_route_monitoring(status: &mut DataplaneStatus, rm: &RouteMonitoringMessage) {
    let peer = rm.peer_header();
    let vrf = get_vrf_from_peer_header(peer);
    let key = key_from_peer_header(peer);

    let bgp = ensure_bgp(status);
    let vrf_s = ensure_vrf(bgp, &vrf);
    let neigh = ensure_neighbor(vrf_s, &key);

    // Ensure message counters exist
    let msgs = neigh.messages.get_or_insert_with(|| BgpMessages {
        received: Some(BgpMessageCounters::new()),
        sent: Some(BgpMessageCounters::new()),
    });

    // Count UPDATE messages received
    if let BgpMessage::Update(_) = rm.update_message() {
        if let Some(rcv) = msgs.received.as_mut() {
            rcv.update = rcv.update.saturating_add(1);
        }
    }

    // Very rough pre/post-policy NLRI accounting example
    let post = post_policy_from_peer_type(peer.peer_type());
    let pref = neigh
        .ipv4_unicast_prefixes
        .get_or_insert_with(BgpNeighborPrefixes::default);

    // We don't parse NLRI depth here; increment by 1 as a placeholder per RM message
    if post {
        pref.received_pre_policy = pref.received_pre_policy.saturating_add(0); // post-policy => don't bump pre
        pref.received = pref.received.saturating_add(1);
    } else {
        pref.received_pre_policy = pref.received_pre_policy.saturating_add(1);
        pref.received = pref.received.saturating_add(1);
    }
}

fn on_statistics(status: &mut DataplaneStatus, sr: &StatisticsReportMessage) {
    let peer = sr.peer_header();
    let vrf = get_vrf_from_peer_header(peer);
    let key = key_from_peer_header(peer);

    let bgp = ensure_bgp(status);
    let vrf_s = ensure_vrf(bgp, &vrf);
    let neigh = ensure_neighbor(vrf_s, &key);

    // Make sure we have message counters present
    let _ = neigh.messages.get_or_insert_with(|| BgpMessages {
        received: Some(BgpMessageCounters::new()),
        sent: Some(BgpMessageCounters::new()),
    });

    //TODO: smatov: add more later
}
