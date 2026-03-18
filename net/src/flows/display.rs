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
            writeln!(f, "      nat-state:{data}")?;
        }
        Ok(())
    }
}

impl Display for FlowInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let expires_at = self.expires_at();
        let expires_in = expires_at.saturating_duration_since(Instant::now());
        let genid = self.genid();

        if let Ok(info) = self.locked.try_read() {
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
