// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Dataplane status model: status information for interfaces, FRR, and dataplane

use std::collections::BTreeMap;
use std::fmt::Display;

use crate::{ConfigError, ConfigResult};

/// Request to get dataplane status (empty message)
#[derive(Clone, Debug, Default, PartialEq)]
pub struct GetDataplaneStatusRequest {}

/// Response containing all dataplane status information
#[derive(Clone, Debug, PartialEq)]
pub struct GetDataplaneStatusResponse {
    pub interface_statuses: Vec<InterfaceStatus>,
    pub frr_status: Option<FrrStatus>,
    pub dataplane_status: Option<DataplaneStatusInfo>,
}

/// Status information for a network interface
#[derive(Clone, Debug, PartialEq)]
pub struct InterfaceStatus {
    pub ifname: String,
    pub status: InterfaceStatusType,
    pub admin_status: InterfaceAdminStatusType,
}

/// Operational status of an interface
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum InterfaceStatusType {
    Unknown,
    OperUp,
    OperDown,
    StatusError,
}

/// Administrative status of an interface
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum InterfaceAdminStatusType {
    Unknown,
    Up,
    Down,
}

/// Status information for FRR (Free Range Routing) daemon
#[derive(Clone, Debug, PartialEq)]
pub struct FrrStatus {
    pub zebra_status: ZebraStatusType,
    pub frr_agent_status: FrrAgentStatusType,
    pub applied_config_gen: u32,
    pub restarts: u32,
    pub applied_configs: u32,
    pub failed_configs: u32,
}

/// Status of the Zebra daemon
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ZebraStatusType {
    NotConnected,
    Connected,
}

/// Status of the FRR Agent
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum FrrAgentStatusType {
    NotConnected,
    Connected,
}

/// General dataplane status information
#[derive(Clone, Debug, PartialEq)]
pub struct DataplaneStatusInfo {
    pub status: DataplaneStatusType,
}

/// Overall status of the dataplane
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum DataplaneStatusType {
    Unknown,
    Healthy,
    Init,
    StatusError,
}

/// Collection of dataplane status information
#[derive(Clone, Debug, Default, PartialEq)]
pub struct DataplaneStatus {
    pub interface_statuses: BTreeMap<String, InterfaceStatus>,
    pub frr_status: Option<FrrStatus>,
    pub dataplane_status: Option<DataplaneStatusInfo>,
}

// Implementation methods
impl GetDataplaneStatusRequest {
    #[must_use]
    pub fn new() -> Self {
        Self {}
    }
}

impl GetDataplaneStatusResponse {
    #[must_use]
    pub fn new() -> Self {
        Self {
            interface_statuses: Vec::new(),
            frr_status: None,
            dataplane_status: None,
        }
    }

    #[must_use]
    pub fn with_interface_statuses(mut self, statuses: Vec<InterfaceStatus>) -> Self {
        self.interface_statuses = statuses;
        self
    }

    #[must_use]
    pub fn with_frr_status(mut self, status: FrrStatus) -> Self {
        self.frr_status = Some(status);
        self
    }

    #[must_use]
    pub fn with_dataplane_status(mut self, status: DataplaneStatusInfo) -> Self {
        self.dataplane_status = Some(status);
        self
    }

    pub fn add_interface_status(&mut self, status: InterfaceStatus) {
        self.interface_statuses.push(status);
    }

    pub fn validate(&self) -> ConfigResult {
        // Validate all interface statuses
        for if_status in &self.interface_statuses {
            if_status.validate()?;
        }

        // Validate FRR status if present
        if let Some(frr_status) = &self.frr_status {
            frr_status.validate()?;
        }

        // Validate dataplane status if present
        if let Some(dp_status) = &self.dataplane_status {
            dp_status.validate()?;
        }

        Ok(())
    }
}

impl InterfaceStatus {
    #[must_use]
    pub fn new(ifname: &str, status: InterfaceStatusType, admin_status: InterfaceAdminStatusType) -> Self {
        Self {
            ifname: ifname.to_owned(),
            status,
            admin_status,
        }
    }

    #[must_use]
    pub fn is_operational(&self) -> bool {
        matches!(self.status, InterfaceStatusType::OperUp)
    }

    #[must_use]
    pub fn is_admin_up(&self) -> bool {
        matches!(self.admin_status, InterfaceAdminStatusType::Up)
    }

    #[must_use]
    pub fn is_available(&self) -> bool {
        self.is_operational() && self.is_admin_up()
    }

    pub fn validate(&self) -> ConfigResult {
        if self.ifname.is_empty() {
            return Err(ConfigError::MissingIdentifier("interface name"));
        }
        Ok(())
    }
}

impl FrrStatus {
    #[must_use]
    pub fn new(
        zebra_status: ZebraStatusType,
        frr_agent_status: FrrAgentStatusType,
        applied_config_gen: u32,
        restarts: u32,
        applied_configs: u32,
        failed_configs: u32,
    ) -> Self {
        Self {
            zebra_status,
            frr_agent_status,
            applied_config_gen,
            restarts,
            applied_configs,
            failed_configs,
        }
    }

    #[must_use]
    pub fn is_zebra_connected(&self) -> bool {
        matches!(self.zebra_status, ZebraStatusType::Connected)
    }

    #[must_use]
    pub fn is_frr_agent_connected(&self) -> bool {
        matches!(self.frr_agent_status, FrrAgentStatusType::Connected)
    }

    #[must_use]
    pub fn is_fully_connected(&self) -> bool {
        self.is_zebra_connected() && self.is_frr_agent_connected()
    }

    #[must_use]
    pub fn has_failures(&self) -> bool {
        self.failed_configs > 0
    }

    #[must_use]
    pub fn success_rate(&self) -> f64 {
        if self.applied_configs == 0 {
            0.0
        } else {
            (self.applied_configs - self.failed_configs) as f64 / self.applied_configs as f64
        }
    }

    pub fn validate(&self) -> ConfigResult {
        // For now, no specific validation needed - all values are valid
        Ok(())
    }
}

impl DataplaneStatusInfo {
    #[must_use]
    pub fn new(status: DataplaneStatusType) -> Self {
        Self { status }
    }

    #[must_use]
    pub fn is_healthy(&self) -> bool {
        matches!(self.status, DataplaneStatusType::Healthy)
    }

    #[must_use]
    pub fn is_initializing(&self) -> bool {
        matches!(self.status, DataplaneStatusType::Init)
    }

    #[must_use]
    pub fn has_errors(&self) -> bool {
        matches!(self.status, DataplaneStatusType::StatusError)
    }

    pub fn validate(&self) -> ConfigResult {
        // For now, no specific validation needed - all values are valid
        Ok(())
    }
}

impl DataplaneStatus {
    #[must_use]
    pub fn new() -> Self {
        Self {
            interface_statuses: BTreeMap::new(),
            frr_status: None,
            dataplane_status: None,
        }
    }

    #[must_use]
    pub fn with_frr_status(mut self, status: FrrStatus) -> Self {
        self.frr_status = Some(status);
        self
    }

    #[must_use]
    pub fn with_dataplane_status(mut self, status: DataplaneStatusInfo) -> Self {
        self.dataplane_status = Some(status);
        self
    }

    pub fn add_interface_status(&mut self, status: InterfaceStatus) {
        self.interface_statuses.insert(status.ifname.clone(), status);
    }

    pub fn get_interface_status(&self, ifname: &str) -> Option<&InterfaceStatus> {
        self.interface_statuses.get(ifname)
    }

    pub fn interface_statuses(&self) -> impl Iterator<Item = &InterfaceStatus> {
        self.interface_statuses.values()
    }

    #[must_use]
    pub fn overall_health(&self) -> DataplaneStatusType {
        // Simple health assessment logic
        match &self.dataplane_status {
            Some(dp_status) if dp_status.has_errors() => DataplaneStatusType::StatusError,
            Some(dp_status) if dp_status.is_initializing() => DataplaneStatusType::Init,
            Some(dp_status) if dp_status.is_healthy() => {
                // Check FRR status
                match &self.frr_status {
                    Some(frr) if !frr.is_fully_connected() => DataplaneStatusType::StatusError,
                    Some(frr) if frr.is_fully_connected() => {
                        // Check if any interfaces have errors
                        let has_interface_errors = self.interface_statuses.values()
                            .any(|status| matches!(status.status, InterfaceStatusType::StatusError));
                        
                        if has_interface_errors {
                            DataplaneStatusType::StatusError
                        } else {
                            DataplaneStatusType::Healthy
                        }
                    }
                    _ => DataplaneStatusType::Unknown,
                }
            }
            _ => DataplaneStatusType::Unknown,
        }
    }

    pub fn validate(&self) -> ConfigResult {
        // Validate all interface statuses
        for if_status in self.interface_statuses.values() {
            if_status.validate()?;
        }

        // Validate FRR status if present
        if let Some(frr_status) = &self.frr_status {
            frr_status.validate()?;
        }

        // Validate dataplane status if present
        if let Some(dp_status) = &self.dataplane_status {
            dp_status.validate()?;
        }

        Ok(())
    }
}

// Display implementations
impl Display for InterfaceStatusType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            InterfaceStatusType::Unknown => write!(f, "unknown"),
            InterfaceStatusType::OperUp => write!(f, "up"),
            InterfaceStatusType::OperDown => write!(f, "down"),
            InterfaceStatusType::StatusError => write!(f, "error"),
        }
    }
}

impl Display for InterfaceAdminStatusType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            InterfaceAdminStatusType::Unknown => write!(f, "unknown"),
            InterfaceAdminStatusType::Up => write!(f, "up"),
            InterfaceAdminStatusType::Down => write!(f, "down"),
        }
    }
}

impl Display for ZebraStatusType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            ZebraStatusType::NotConnected => write!(f, "not connected"),
            ZebraStatusType::Connected => write!(f, "connected"),
        }
    }
}

impl Display for FrrAgentStatusType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            FrrAgentStatusType::NotConnected => write!(f, "not connected"),
            FrrAgentStatusType::Connected => write!(f, "connected"),
        }
    }
}

impl Display for DataplaneStatusType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            DataplaneStatusType::Unknown => write!(f, "unknown"),
            DataplaneStatusType::Healthy => write!(f, "healthy"),
            DataplaneStatusType::Init => write!(f, "initializing"),
            DataplaneStatusType::StatusError => write!(f, "error"),
        }
    }
}

impl Display for InterfaceStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}: {} (admin: {})", self.ifname, self.status, self.admin_status)
    }
}

impl Display for FrrStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "FRR: zebra={}, agent={} (config gen: {}, restarts: {}, applied: {}, failed: {})", 
               self.zebra_status, self.frr_agent_status, self.applied_config_gen, 
               self.restarts, self.applied_configs, self.failed_configs)
    }
}

impl Display for DataplaneStatusInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Dataplane: {}", self.status)
    }
}