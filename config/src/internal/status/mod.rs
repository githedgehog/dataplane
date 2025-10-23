// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Dataplane runtime/status model (internal)

#![allow(clippy::module_name_repetitions)]

use std::collections::HashMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum InterfaceOperStatusType {
    #[default]
    Unknown,
    OperUp,
    OperDown,
    Error,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum InterfaceAdminStatusType {
    #[default]
    Unknown,
    Up,
    Down,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum ZebraStatusType {
    #[default]
    NotConnected,
    Connected,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum FrrAgentStatusType {
    #[default]
    NotConnected,
    Connected,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum DataplaneStatusType {
    #[default]
    Unknown,
    Healthy,
    Init,
    Error,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum BgpNeighborSessionState {
    #[default]
    Unset,
    Idle,
    Connect,
    Active,
    Open,
    Established,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct InterfaceStatus {
    pub ifname: String,
    pub oper_status: InterfaceOperStatusType,
    pub admin_status: InterfaceAdminStatusType,
}

impl InterfaceStatus {
    #[must_use]
    pub fn new(ifname: impl Into<String>) -> Self {
        Self {
            ifname: ifname.into(),
            ..Self::default()
        }
    }
    #[must_use]
    pub fn set_oper_status(mut self, s: InterfaceOperStatusType) -> Self {
        self.oper_status = s;
        self
    }
    #[must_use]
    pub fn set_admin_status(mut self, s: InterfaceAdminStatusType) -> Self {
        self.admin_status = s;
        self
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct InterfaceCounters {
    pub tx_bits: u64,
    pub tx_bps: f64,
    pub tx_errors: u64,
    pub rx_bits: u64,
    pub rx_bps: f64,
    pub rx_errors: u64,
}

impl InterfaceCounters {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    #[must_use]
    pub fn set_tx_bits(mut self, v: u64) -> Self {
        self.tx_bits = v;
        self
    }
    #[must_use]
    pub fn set_tx_bps(mut self, v: f64) -> Self {
        self.tx_bps = v;
        self
    }
    #[must_use]
    pub fn set_tx_errors(mut self, v: u64) -> Self {
        self.tx_errors = v;
        self
    }
    #[must_use]
    pub fn set_rx_bits(mut self, v: u64) -> Self {
        self.rx_bits = v;
        self
    }
    #[must_use]
    pub fn set_rx_bps(mut self, v: f64) -> Self {
        self.rx_bps = v;
        self
    }
    #[must_use]
    pub fn set_rx_errors(mut self, v: u64) -> Self {
        self.rx_errors = v;
        self
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct InterfaceRuntimeStatus {
    pub admin_status: InterfaceAdminStatusType,
    pub oper_status: InterfaceOperStatusType,
    pub mac: String,
    pub mtu: u32,
    pub counters: Option<InterfaceCounters>,
}

impl InterfaceRuntimeStatus {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    #[must_use]
    pub fn set_admin_status(mut self, s: InterfaceAdminStatusType) -> Self {
        self.admin_status = s;
        self
    }
    #[must_use]
    pub fn set_oper_status(mut self, s: InterfaceOperStatusType) -> Self {
        self.oper_status = s;
        self
    }
    #[must_use]
    pub fn set_mac(mut self, mac: impl Into<String>) -> Self {
        self.mac = mac.into();
        self
    }
    #[must_use]
    pub fn set_mtu(mut self, mtu: u32) -> Self {
        self.mtu = mtu;
        self
    }
    #[must_use]
    pub fn set_counters(mut self, c: InterfaceCounters) -> Self {
        self.counters = Some(c);
        self
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FrrStatus {
    pub zebra_status: ZebraStatusType,
    pub frr_agent_status: FrrAgentStatusType,
    pub applied_config_gen: i64,
    pub restarts: u32,
    pub applied_configs: u32,
    pub failed_configs: u32,
}

impl FrrStatus {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    #[must_use]
    pub fn set_zebra_status(mut self, s: ZebraStatusType) -> Self {
        self.zebra_status = s;
        self
    }
    #[must_use]
    pub fn set_agent_status(mut self, s: FrrAgentStatusType) -> Self {
        self.frr_agent_status = s;
        self
    }
    #[must_use]
    pub fn set_applied_config_gen(mut self, v: i64) -> Self {
        self.applied_config_gen = v;
        self
    }
    #[must_use]
    pub fn set_restarts(mut self, v: u32) -> Self {
        self.restarts = v;
        self
    }
    #[must_use]
    pub fn set_applied_configs(mut self, v: u32) -> Self {
        self.applied_configs = v;
        self
    }
    #[must_use]
    pub fn set_failed_configs(mut self, v: u32) -> Self {
        self.failed_configs = v;
        self
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DataplaneStatusInfo {
    pub status: DataplaneStatusType,
}

impl DataplaneStatusInfo {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    #[must_use]
    pub fn set_status(mut self, s: DataplaneStatusType) -> Self {
        self.status = s;
        self
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BgpMessageCounters {
    pub capability: u64,
    pub keepalive: u64,
    pub notification: u64,
    pub open: u64,
    pub route_refresh: u64,
    pub update: u64,
}
impl BgpMessageCounters {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BgpMessages {
    pub received: Option<BgpMessageCounters>,
    pub sent: Option<BgpMessageCounters>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BgpNeighborPrefixes {
    pub received: u32,
    pub received_pre_policy: u32,
    pub sent: u32,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BgpNeighborStatus {
    pub enabled: bool,
    pub local_as: u32,
    pub peer_as: u32,
    pub peer_port: u32,
    pub peer_group: String,
    pub remote_router_id: String,
    pub session_state: BgpNeighborSessionState,
    pub connections_dropped: u64,
    pub established_transitions: u64,
    pub last_reset_reason: String,
    pub messages: Option<BgpMessages>,
    pub ipv4_unicast_prefixes: Option<BgpNeighborPrefixes>,
    pub ipv6_unicast_prefixes: Option<BgpNeighborPrefixes>,
    pub l2vpn_evpn_prefixes: Option<BgpNeighborPrefixes>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BgpVrfStatus {
    pub neighbors: HashMap<String, BgpNeighborStatus>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BgpStatus {
    pub vrfs: HashMap<String, BgpVrfStatus>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VpcInterfaceStatus {
    pub ifname: String,
    pub admin_status: InterfaceAdminStatusType,
    pub oper_status: InterfaceOperStatusType,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VpcStatus {
    pub id: String,
    pub name: String,
    pub vni: u32,
    pub route_count: u32,
    pub interfaces: HashMap<String, VpcInterfaceStatus>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct VpcPeeringCounters {
    pub name: String,
    pub src_vpc: String,
    pub dst_vpc: String,
    pub packets: u64,
    pub bytes: u64,
    pub drops: u64,
    pub pps: f64,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct DataplaneStatus {
    pub interface_statuses: Vec<InterfaceStatus>,
    pub frr_status: Option<FrrStatus>,
    pub dataplane_status: Option<DataplaneStatusInfo>,
    pub interface_runtime: HashMap<String, InterfaceRuntimeStatus>,
    pub bgp: Option<BgpStatus>,
    pub vpcs: HashMap<String, VpcStatus>,
    pub vpc_peering_counters: HashMap<String, VpcPeeringCounters>,
}

impl DataplaneStatus {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    pub fn add_interface_status(&mut self, s: InterfaceStatus) {
        self.interface_statuses.push(s);
    }
    pub fn add_interface_runtime(&mut self, ifname: String, s: InterfaceRuntimeStatus) {
        self.interface_runtime.insert(ifname, s);
    }
    pub fn add_vpc(&mut self, name: String, v: VpcStatus) {
        self.vpcs.insert(name, v);
    }
    pub fn add_peering(&mut self, name: String, c: VpcPeeringCounters) {
        self.vpc_peering_counters.insert(name, c);
    }
    pub fn set_frr_status(&mut self, s: FrrStatus) {
        self.frr_status = Some(s);
    }
    pub fn set_dataplane_status(&mut self, s: DataplaneStatusInfo) {
        self.dataplane_status = Some(s);
    }
    pub fn set_bgp(&mut self, b: BgpStatus) {
        self.bgp = Some(b);
    }
}
