// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Router events and eventlog

use crate::IfState;
use crate::event::EventLog;
use crate::router::cpi::CpiStatus;
use config::GenId;
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
        }
        Ok(())
    }
}

make_event_log!(ROUTER_EVENTS, RouterEvent, 1000);

macro_rules! revent {
    ($item:expr) => {
        ROUTER_EVENTS.with(|evlog| evlog.borrow_mut().add($item))
    };
}

pub(crate) use revent;
