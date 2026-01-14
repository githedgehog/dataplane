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

use tracing::debug;

/// Update `DataplaneStatus` from a single BMP message.
pub fn handle_bmp_message(status: &mut DataplaneStatus, msg: &BmpMessage) {
    match msg {
        BmpMessage::V3(v) => match v {
            // NOTE: NetGauze uses `Initiation`, not `InitiationMessage`
            BmpMessageValue::Initiation(init) => {
                debug!("BMP: initiation: {:?}", init);
            }
            BmpMessageValue::Termination(term) => {
                debug!("BMP: termination: {:?}", term);
            }
            BmpMessageValue::PeerUpNotification(pu) => on_peer_up(status, pu),
            BmpMessageValue::PeerDownNotification(pd) => on_peer_down(status, pd),
            BmpMessageValue::RouteMonitoring(rm) => on_route_monitoring(status, rm),
            BmpMessageValue::StatisticsReport(sr) => on_statistics(status, sr),
            _ => {}
        },
        // V4 not handled yet
        BmpMessage::V4(_) => {}
    }
}

/// A stable-ish neighbor key.
/// Keep this stable across sessions so counters accumulate reasonably.
///
/// Format:
/// `<peer_type>-<bgp_id>-<peer_as>-<addr|-none>-<rd|-no-rd>`
fn key_from_peer_header(peer: &netgauze_bmp_pkt::PeerHeader) -> String {
    let pt = peer.peer_type();
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

    format!("{pt:?}-{id}-{asn}-{ip}-{rd}")
}

/// VRF bucket key. Warning: Not working with FRR BMP Update Messages with per-vrf
/// routing dump. Wireshark also can't decode it, seems it's not convenient to do so.
///
/// - If PeerHeader has an RD, that is the best discriminator for “per-VRF” in BMP.
/// - If RD is absent, fall back to a key based on the peer type so you don’t collapse
///   Local/Global/LocRIB streams into one bucket.
///
fn vrf_from_peer_header(peer: &netgauze_bmp_pkt::PeerHeader) -> String {
    if let Some(rd) = peer.rd() {
        return format!("rd:{rd:?}");
    }

    match peer.peer_type() {
        BmpPeerType::GlobalInstancePeer { .. } => "default".to_string(),
        BmpPeerType::LocalInstancePeer { .. } => "local-instance".to_string(),
        BmpPeerType::LocRibInstancePeer { .. } => "loc-rib".to_string(),
        BmpPeerType::RdInstancePeer { .. } => "rd:missing".to_string(),
        BmpPeerType::Experimental251 { .. } => "exp-251".to_string(),
        BmpPeerType::Experimental252 { .. } => "exp-252".to_string(),
        BmpPeerType::Experimental253 { .. } => "exp-253".to_string(),
        BmpPeerType::Experimental254 { .. } => "exp-254".to_string(),
    }
}

fn set_neighbor_session_state(n: &mut BgpNeighborStatus, st: BgpNeighborSessionState) {
    n.session_state = st;
}

fn ensure_bgp(status: &mut DataplaneStatus) -> &mut BgpStatus {
    if status.bgp.is_none() {
        status.bgp = Some(BgpStatus::default());
        debug!("BMP: initialized DataplaneStatus.bgp");
    }
    status.bgp.as_mut().unwrap()
}

fn ensure_vrf<'a>(bgp: &'a mut BgpStatus, vrf: &str) -> &'a mut BgpVrfStatus {
    if !bgp.vrfs.contains_key(vrf) {
        debug!("BMP: creating VRF status entry: vrf={vrf}");
    }
    bgp.vrfs.entry(vrf.to_string()).or_default()
}

fn ensure_neighbor<'a>(vrf: &'a mut BgpVrfStatus, neigh_key: &str) -> &'a mut BgpNeighborStatus {
    if !vrf.neighbors.contains_key(neigh_key) {
        debug!("BMP: creating neighbor status entry: key={neigh_key}");
    }
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
    let vrf = vrf_from_peer_header(peer);
    let key = key_from_peer_header(peer);

    let peer_as = peer.peer_as();
    let bgp_id = peer.bgp_id().to_string();
    let peer_addr = peer
        .address()
        .map(|a| a.to_string())
        .unwrap_or_else(|| "none".to_string());
    let peer_port = pu.remote_port().unwrap_or_default() as u32;

    let bgp = ensure_bgp(status);
    let vrf_s = ensure_vrf(bgp, &vrf);
    let neigh = ensure_neighbor(vrf_s, &key);

    let prev_state = neigh.session_state;

    neigh.peer_as = peer_as;
    neigh.remote_router_id = bgp_id.clone();
    neigh.peer_port = peer_port;

    // PeerUp implies Established for the monitored session.
    set_neighbor_session_state(neigh, BgpNeighborSessionState::Established);

    // Local AS: try to read from the OPEN we sent, if present.
    // NOTE: don’t depend on router-id helpers here; peer header already provides bgp_id.
    if let BgpMessage::Open(open) = pu.sent_message() {
        neigh.local_as = open.my_as() as u32;
    }

    if neigh.messages.is_none() {
        neigh.messages = Some(BgpMessages {
            received: Some(BgpMessageCounters::new()),
            sent: Some(BgpMessageCounters::new()),
        });
    }

    debug!(
        "BMP: peer-up vrf={} key={} peer_addr={} prev_state={:?} new_state={:?} peer_as={} local_as={} peer_port={} remote_id={}",
        vrf,
        key,
        peer_addr,
        prev_state,
        neigh.session_state,
        neigh.peer_as,
        neigh.local_as,
        neigh.peer_port,
        neigh.remote_router_id,
    );
}

fn on_peer_down(status: &mut DataplaneStatus, pd: &PeerDownNotificationMessage) {
    let peer = pd.peer_header();
    let vrf = vrf_from_peer_header(peer);
    let key = key_from_peer_header(peer);

    if let Some(bgp) = status.bgp.as_mut() {
        if let Some(vrf_s) = bgp.vrfs.get_mut(&vrf) {
            if let Some(neigh) = vrf_s.neighbors.get_mut(&key) {
                let prev_state = neigh.session_state;
                let prev_dropped = neigh.connections_dropped;

                set_neighbor_session_state(neigh, BgpNeighborSessionState::Idle);
                neigh.connections_dropped = neigh.connections_dropped.saturating_add(1);

                debug!(
                    "BMP: peer-down vrf={} key={} prev_state={:?} new_state={:?} prev_connections_dropped={} new_connections_dropped={}",
                    vrf,
                    key,
                    prev_state,
                    neigh.session_state,
                    prev_dropped,
                    neigh.connections_dropped
                );
            } else {
                debug!(
                    "BMP: peer-down for unknown neighbor: vrf={} key={}",
                    vrf, key
                );
            }
        } else {
            debug!("BMP: peer-down for unknown vrf: vrf={} key={}", vrf, key);
        }
    } else {
        debug!(
            "BMP: peer-down but DataplaneStatus.bgp is None (vrf={} key={})",
            vrf, key
        );
    }
}

fn on_route_monitoring(status: &mut DataplaneStatus, rm: &RouteMonitoringMessage) {
    let peer = rm.peer_header();
    let vrf = vrf_from_peer_header(peer);
    let key = key_from_peer_header(peer);

    let post = post_policy_from_peer_type(peer.peer_type());

    let bgp = ensure_bgp(status);
    let vrf_s = ensure_vrf(bgp, &vrf);
    let neigh = ensure_neighbor(vrf_s, &key);

    let msgs = neigh.messages.get_or_insert_with(|| BgpMessages {
        received: Some(BgpMessageCounters::new()),
        sent: Some(BgpMessageCounters::new()),
    });

    // Count UPDATE messages received (best-effort)
    if let BgpMessage::Update(_) = rm.update_message() {
        if let Some(rcv) = msgs.received.as_mut() {
            rcv.update = rcv.update.saturating_add(1);
        }
    }

    // Minimal prefix counters placeholder (per RM message) — can be upgraded later to real NLRI counting.
    let pref = neigh
        .ipv4_unicast_prefixes
        .get_or_insert_with(BgpNeighborPrefixes::default);

    if post {
        // post-policy: we count "received" only
        pref.received = pref.received.saturating_add(1);
    } else {
        // pre-policy view: bump both
        pref.received_pre_policy = pref.received_pre_policy.saturating_add(1);
        pref.received = pref.received.saturating_add(1);
    }

    debug!(
        "BMP: route-monitoring vrf={} key={} post_policy={} ipv4_received={} ipv4_received_pre={}",
        vrf, key, post, pref.received, pref.received_pre_policy,
    );
}

fn on_statistics(status: &mut DataplaneStatus, sr: &StatisticsReportMessage) {
    let peer = sr.peer_header();
    let vrf = vrf_from_peer_header(peer);
    let key = key_from_peer_header(peer);

    let bgp = ensure_bgp(status);
    let vrf_s = ensure_vrf(bgp, &vrf);
    let neigh = ensure_neighbor(vrf_s, &key);

    let _ = neigh.messages.get_or_insert_with(|| BgpMessages {
        received: Some(BgpMessageCounters::new()),
        sent: Some(BgpMessageCounters::new()),
    });

    debug!(
        "BMP: statistics-report vrf={} key={} (TODO: decode stats later)",
        vrf, key
    );
}
