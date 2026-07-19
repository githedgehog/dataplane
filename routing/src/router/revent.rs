// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Router events and eventlog

use crate::IfState;
use crate::bmp::bmp_render::BgpNeighEvent;
use crate::cli::display::PrettyDuration;
use crate::event::EventLog;
use crate::router::cpi::CpiStatus;

use config::GenId;
use config::internal::status::BgpNeighborSessionState;
use interface_manager::monitor::EthEvent;
use std::cell::RefCell;
use std::fmt::Display;

pub enum RouterEvent {
    Started,
    CpiStatusChange(CpiStatus),
    CpiRefreshRequested,

    GotConfigRequest(GenId),
    ConfigSuceeded(GenId),
    ConfigFailed(GenId),

    FrrmiConnectSucceeded,
    FrrmiDisconnected,
    FrrmiPeerLeft,

    FrrConfigApplyRequested(GenId),
    FrrConfigApplySuccess(GenId),
    FrrConfigApplyFailure(GenId),

    IfAdmChange(EthEvent, IfState, IfState),
    IfOperChange(EthEvent, IfState, IfState),

    BgpNeighStateChange(BgpNeighEvent),
}

impl Display for RouterEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RouterEvent::Started => write!(f, "Started!")?,
            RouterEvent::CpiStatusChange(status) => write!(f, "CPI status changed to {status}")?,
            RouterEvent::CpiRefreshRequested => write!(f, "Requested refresh to FRR")?,

            RouterEvent::GotConfigRequest(genid) => {
                write!(f, "Router config request received for generation {genid}")?;
            }
            RouterEvent::ConfigSuceeded(genid) => {
                write!(f, "Router config request for generation {genid} SUCCEEDED")?;
            }
            RouterEvent::ConfigFailed(genid) => {
                write!(f, "Router config request for generation {genid} FAILED")?;
            }

            RouterEvent::FrrmiConnectSucceeded => write!(f, "Connected to frr-agent")?,
            RouterEvent::FrrmiDisconnected => write!(f, "Disconnected from frr-agent")?,
            RouterEvent::FrrmiPeerLeft => write!(f, "Frr-agent left!")?,

            RouterEvent::FrrConfigApplyRequested(genid) => {
                write!(f, "Requested FRR configuration for generation {genid}")?;
            }
            RouterEvent::FrrConfigApplySuccess(genid) => {
                write!(f, "FRR configuration for generation {genid} SUCCEEDED")?;
            }
            RouterEvent::FrrConfigApplyFailure(genid) => {
                write!(f, "FRR configuration for generation {genid} FAILED")?;
            }
            RouterEvent::IfOperChange(ev, old, new) => {
                let ifc = &ev.name;
                write!(
                    f,
                    "{ifc}: oper state changed {old} -> {new} (carrier:{:#?}, carrier-up:{} carrier-down:{})",
                    ev.carrier, ev.carrierup, ev.carrierdown
                )?;
            }
            RouterEvent::IfAdmChange(ev, old, new) => {
                let ifc = &ev.name;
                write!(
                    f,
                    "{ifc}: admin state changed {old} -> {new} (carrier:{:#?}, carrier-up:{} carrier-down:{})",
                    ev.carrier, ev.carrierup, ev.carrierdown
                )?;
            }
            RouterEvent::BgpNeighStateChange(bgp_ev) => {
                let peer_key = &bgp_ev.peer_key;
                let peer_router_id = &bgp_ev.peer_router_id;
                let peer_asn = bgp_ev.peer_asn;
                let prev = bgp_ev.prev;
                let new = bgp_ev.new;

                write!(
                    f,
                    "Status of BGP peer {peer_key} (id:{peer_router_id} ASN:{peer_asn}) changed: {prev} -> {new}"
                )?;
                if new != BgpNeighborSessionState::Established {
                    let last_reset_reason = bgp_ev.last_reset_reason.as_deref().unwrap_or("none");
                    write!(f, " reason: {last_reset_reason}")?;
                } else if let Some(downtime) = &bgp_ev.last_downtime {
                    let downtime = PrettyDuration::new(*downtime);
                    write!(f, " (downtime of {downtime})")?;
                }
            }
        }
        Ok(())
    }
}

make_event_log!(ROUTER_EVENTS, RouterEvent, 2000);

macro_rules! revent {
    ($item:expr) => {
        ROUTER_EVENTS.with(|evlog| evlog.borrow_mut().add($item))
    };
}

pub(crate) use revent;
