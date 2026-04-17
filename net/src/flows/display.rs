// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Flow keys

use super::flow_info::{FlowInfo, FlowInfoLocked};
use super::flow_key::{FlowKey, FlowKeyData};

use std::fmt::Display;
use std::time::Instant;

impl Display for FlowKeyData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(vpcd) = self.src_vpcd() {
            write!(f, "from: {vpcd},")?;
        }
        let ports = self.ports();
        let proto = self.proto();
        let src_ip = self.src_ip();
        let dst_ip = self.dst_ip();
        if let Some((src_port, dst_port)) = ports {
            write!(f, "{src_ip}:{src_port} -> {dst_ip}:{dst_port} {proto}")?;
        } else {
            write!(f, "{src_ip} -> {dst_ip} {proto}")?;
        }
        if let Some(id) = self.icmp_id() {
            write!(f, " id:{id}")?;
        }
        Ok(())
    }
}

impl Display for FlowKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FlowKey::Unidirectional(data) => write!(f, "{data}"),
        }
    }
}

impl Display for FlowInfoLocked {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(data) = &self.dst_vpcd {
            writeln!(f, "      dst-vpcd:{data}")?;
        }
        if let Some(data) = &self.port_fw_state {
            writeln!(f, "      port-forwarding:{data}")?;
        }
        if let Some(data) = &self.nat_state {
            writeln!(f, "      masquerading:{data}")?;
        }
        Ok(())
    }
}

impl Display for FlowInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let expires_at = self.expires_at();
        let expires_in = expires_at.saturating_duration_since(Instant::now());
        let genid = self.genid();

        if let Ok(info) = self.locked.read() {
            write!(f, "{info}")?;
        } else {
            write!(f, "could not lock!")?;
        }
        let has_related = self
            .related
            .as_ref()
            .and_then(std::sync::Weak::upgrade)
            .map_or("no", |_| "yes");

        writeln!(
            f,
            "      status: {:?}, expires in {}s, related: {has_related}, genid: {genid}",
            self.status(),
            expires_in.as_secs(),
        )
    }
}

pub struct FlowInfoOneLiner<'a>(&'a FlowInfo);
struct FlowInfoLockedOneLiner<'a>(&'a FlowInfoLocked);

impl Display for FlowInfoLockedOneLiner<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let locked = self.0;
        if let Some(data) = &locked.dst_vpcd {
            write!(f, "dst-vpcd:{data} ")?;
        }
        if let Some(data) = &locked.port_fw_state {
            write!(f, "port-forwarding:{data} ")?;
        }
        if let Some(data) = &locked.nat_state {
            write!(f, "masquerading:{data} ")?;
        }
        Ok(())
    }
}

impl Display for FlowInfoOneLiner<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let flow_info = self.0;
        let genid = flow_info.genid();
        let key = flow_info
            .flowkey()
            .map_or_else(|| "none".to_string(), ToString::to_string);

        let r = flow_info
            .related
            .as_ref()
            .and_then(std::sync::Weak::upgrade)
            .map_or("no", |_| "yes");

        if let Ok(info) = flow_info.locked.read() {
            write!(
                f,
                "{key} info:{} related:{r} genid:{genid}",
                FlowInfoLockedOneLiner(&info)
            )
        } else {
            write!(f, "{key} info:inaccessible! related:{r} genid:{genid}")
        }
    }
}

impl FlowInfo {
    pub fn logfmt(&self) -> FlowInfoOneLiner<'_> {
        FlowInfoOneLiner(self)
    }
}
