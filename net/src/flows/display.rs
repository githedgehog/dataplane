// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Flow keys

use super::flow_info::{FlowInfo, FlowInfoLocked};
use super::flow_key::FlowKey;

use concurrency::sync::Weak;
use std::fmt::Display;

impl Display for FlowKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(vpcd) = self.src_vpcd() {
            write!(f, "from {vpcd},")?;
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

impl Display for FlowInfoLocked {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(data) = &self.dst_vpcd {
            writeln!(f, "      dst-vpcd:{data}")?;
        }
        if let Some(data) = &self.port_fw_info {
            writeln!(f, "      port-forwarding:{data}")?;
        }
        if let Some(data) = &self.masquerade_info {
            writeln!(f, "      masquerading:{data}")?;
        }
        if let Some(_data) = &self.tracked_info {
            // TODO: Print _data if it ever becomes non-empty in the case of no NAT
            writeln!(f, "      no-nat")?;
        }
        Ok(())
    }
}

impl Display for FlowInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let expires_at = self.expires_at();
        let expires_in = expires_at.saturating_duration_since(clock::now());
        let genid = self.genid();
        let info = self.locked.read();
        let has_related = self
            .related
            .as_ref()
            .and_then(Weak::upgrade)
            .map_or("no", |_| "yes");
        write!(
            f,
            "{info}      status: {:?}, expires in {}s, related: {has_related}, genid: {genid}",
            self.status(),
            expires_in.as_secs(),
        )?;
        if let Some(conn_state) = self.conn_state() {
            write!(f, ", connection: {}", conn_state.load())?;
        }
        writeln!(f)
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
        if let Some(data) = &locked.port_fw_info {
            write!(f, "port-forwarding:{data} ")?;
        }
        if let Some(data) = &locked.masquerade_info {
            write!(f, "masquerading:{data} ")?;
        }
        if let Some(_data) = &locked.tracked_info {
            // TODO: Print _data if it ever becomes non-empty in the case of no NAT
            write!(f, "no-nat ")?;
        }
        Ok(())
    }
}

impl Display for FlowInfoOneLiner<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let flow_info = self.0;
        let genid = flow_info.genid();
        let key = flow_info.flowkey();
        let r = flow_info
            .related
            .as_ref()
            .and_then(Weak::upgrade)
            .map_or("no", |_| "yes");

        let info = flow_info.locked.read();
        write!(
            f,
            "{key} {} related:{r} genid:{genid}",
            FlowInfoLockedOneLiner(&info)
        )?;
        if let Some(conn_state) = flow_info.conn_state() {
            write!(f, " connection:{}", conn_state.load())?;
        }
        Ok(())
    }
}

impl FlowInfo {
    pub fn logfmt(&self) -> FlowInfoOneLiner<'_> {
        FlowInfoOneLiner(self)
    }
}
