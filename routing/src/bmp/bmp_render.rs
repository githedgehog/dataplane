// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Minimal & safe renderer for NetGauze 0.8.0 BMP messages.
//! This is intentionally conservative to avoid API mismatches. You can
//! extend it to count prefixes/messages per neighbor/VRF once the exact
//! status schema is settled.

use netgauze_bmp_pkt::BmpMessage;

// Bring in your status type (the module path below matches your earlier usage)
use config::internal::status::DataplaneStatus;

/// Backward-compat shim for older callers (typo in earlier drafts).
#[inline]
pub fn hande_bmp_message(status: &mut DataplaneStatus, msg: &BmpMessage) {
    handle_bmp_message(status, msg)
}

/// Primary entry point: update `DataplaneStatus` from a single BMP message.
///
/// For now, we keep this a no-op body that compiles cleanly with NetGauze 0.8.0,
/// so the server can be integrated first. You can expand this to:
/// - track per-neighbor session state on PeerUp/PeerDown
/// - count UPDATEs / KEEPALIVEs per direction
/// - count v4/v6 NLRI using `BgpMessage::Update { .. }` + `path_attributes()`
/// - derive pre/post-policy from PeerHeader flags (v3)
pub fn handle_bmp_message(_status: &mut DataplaneStatus, _msg: &BmpMessage) {
    // Intentionally left as a no-op to keep the build green while
    // we align on exact NetGauze accessors across all message types.
    // Safe expansion path (sketch):
    //
    // match msg {
    //     BmpMessage::V3(v) => match v {
    //         netgauze_bmp_pkt::v3::BmpMessageValue::PeerUpNotification(n) => { ... }
    //         netgauze_bmp_pkt::v3::BmpMessageValue::PeerDownNotification(n) => { ... }
    //         netgauze_bmp_pkt::v3::BmpMessageValue::RouteMonitoring(rm) => {
    //             let pdu = rm.bgp_message();
    //             if let netgauze_bgp_pkt::BgpMessage::Update(upd) = pdu { ... }
    //         }
    //         _ => {}
    //     },
    //     BmpMessage::V4(_v) => { /* optional later */ }
    // }
}
