// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use gateway_config::config as gateway_config;
use std::convert::TryFrom;

use crate::internal::dataplane_status::dataplane_status::{
    DataplaneStatus, DataplaneStatusInfo, DataplaneStatusType, FrrStatus, ZebraStatusType,
    FrrAgentStatusType, GetDataplaneStatusRequest, GetDataplaneStatusResponse, InterfaceStatus, 
    InterfaceStatusType, InterfaceAdminStatusType,
};

// Request conversion (empty message)
impl TryFrom<&gateway_config::GetDataplaneStatusRequest> for GetDataplaneStatusRequest {
    type Error = String;

    fn try_from(_grpc_req: &gateway_config::GetDataplaneStatusRequest) -> Result<Self, Self::Error> {
        Ok(GetDataplaneStatusRequest {})
    }
}

impl TryFrom<&GetDataplaneStatusRequest> for gateway_config::GetDataplaneStatusRequest {
    type Error = String;

    fn try_from(_req: &GetDataplaneStatusRequest) -> Result<Self, Self::Error> {
        Ok(gateway_config::GetDataplaneStatusRequest {})
    }
}

// Response conversion
impl TryFrom<&gateway_config::GetDataplaneStatusResponse> for GetDataplaneStatusResponse {
    type Error = String;

    fn try_from(grpc_resp: &gateway_config::GetDataplaneStatusResponse) -> Result<Self, Self::Error> {
        // Convert interface statuses
        let mut interface_statuses = Vec::with_capacity(grpc_resp.interface_statuses.len());
        for grpc_if_status in &grpc_resp.interface_statuses {
            interface_statuses.push(InterfaceStatus::try_from(grpc_if_status)?);
        }

        // Convert FRR status
        let frr_status = if let Some(grpc_frr_status) = &grpc_resp.frr_status {
            Some(FrrStatus::try_from(grpc_frr_status)?)
        } else {
            None
        };

        // Convert dataplane status
        let dataplane_status = if let Some(grpc_dp_status) = &grpc_resp.dataplane_status {
            Some(DataplaneStatusInfo::try_from(grpc_dp_status)?)
        } else {
            None
        };

        Ok(GetDataplaneStatusResponse {
            interface_statuses,
            frr_status,
            dataplane_status,
        })
    }
}

impl TryFrom<&GetDataplaneStatusResponse> for gateway_config::GetDataplaneStatusResponse {
    type Error = String;

    fn try_from(resp: &GetDataplaneStatusResponse) -> Result<Self, Self::Error> {
        // Convert interface statuses
        let mut interface_statuses = Vec::with_capacity(resp.interface_statuses.len());
        for if_status in &resp.interface_statuses {
            interface_statuses.push(gateway_config::InterfaceStatus::try_from(if_status)?);
        }

        // Convert FRR status
        let frr_status = if let Some(frr_status) = &resp.frr_status {
            Some(gateway_config::FrrStatus::try_from(frr_status)?)
        } else {
            None
        };

        // Convert dataplane status
        let dataplane_status = if let Some(dp_status) = &resp.dataplane_status {
            Some(gateway_config::DataplaneStatusInfo::try_from(dp_status)?)
        } else {
            None
        };

        Ok(gateway_config::GetDataplaneStatusResponse {
            interface_statuses,
            frr_status,
            dataplane_status,
        })
    }
}

// InterfaceStatus conversion
impl TryFrom<&gateway_config::InterfaceStatus> for InterfaceStatus {
    type Error = String;

    fn try_from(grpc_status: &gateway_config::InterfaceStatus) -> Result<Self, Self::Error> {
        let status_type = InterfaceStatusType::try_from(grpc_status.status)?;
        let admin_status_type = InterfaceAdminStatusType::try_from(grpc_status.admin_status)?;

        Ok(InterfaceStatus {
            ifname: grpc_status.ifname.clone(),
            status: status_type,
            admin_status: admin_status_type,
        })
    }
}

impl TryFrom<&InterfaceStatus> for gateway_config::InterfaceStatus {
    type Error = String;

    fn try_from(status: &InterfaceStatus) -> Result<Self, Self::Error> {
        let grpc_status = gateway_config::InterfaceStatusType::from(status.status.clone());
        let grpc_admin_status = gateway_config::InterfaceAdminStatusType::from(status.admin_status.clone());

        Ok(gateway_config::InterfaceStatus {
            ifname: status.ifname.clone(),
            status: grpc_status.into(),
            admin_status: grpc_admin_status.into(),
        })
    }
}

// FrrStatus conversion
impl TryFrom<&gateway_config::FrrStatus> for FrrStatus {
    type Error = String;

    fn try_from(grpc_status: &gateway_config::FrrStatus) -> Result<Self, Self::Error> {
        let zebra_status = ZebraStatusType::try_from(grpc_status.zebra_status)?;
        let frr_agent_status = FrrAgentStatusType::try_from(grpc_status.frr_agent_status)?;

        Ok(FrrStatus {
            zebra_status,
            frr_agent_status,
            applied_config_gen: grpc_status.applied_config_gen,
            restarts: grpc_status.restarts,
            applied_configs: grpc_status.applied_configs,
            failed_configs: grpc_status.failed_configs,
        })
    }
}

impl TryFrom<&FrrStatus> for gateway_config::FrrStatus {
    type Error = String;

    fn try_from(status: &FrrStatus) -> Result<Self, Self::Error> {
        let grpc_zebra_status = gateway_config::ZebraStatusType::from(status.zebra_status.clone());
        let grpc_frr_agent_status = gateway_config::FrrAgentStatusType::from(status.frr_agent_status.clone());

        Ok(gateway_config::FrrStatus {
            zebra_status: grpc_zebra_status.into(),
            frr_agent_status: grpc_frr_agent_status.into(),
            applied_config_gen: status.applied_config_gen,
            restarts: status.restarts,
            applied_configs: status.applied_configs,
            failed_configs: status.failed_configs,
        })
    }
}

// DataplaneStatusInfo conversion
impl TryFrom<&gateway_config::DataplaneStatusInfo> for DataplaneStatusInfo {
    type Error = String;

    fn try_from(grpc_info: &gateway_config::DataplaneStatusInfo) -> Result<Self, Self::Error> {
        let status_type = DataplaneStatusType::try_from(grpc_info.status)?;

        Ok(DataplaneStatusInfo {
            status: status_type,
        })
    }
}

impl TryFrom<&DataplaneStatusInfo> for gateway_config::DataplaneStatusInfo {
    type Error = String;

    fn try_from(info: &DataplaneStatusInfo) -> Result<Self, Self::Error> {
        let grpc_status = gateway_config::DataplaneStatusType::from(info.status.clone());

        Ok(gateway_config::DataplaneStatusInfo {
            status: grpc_status.into(),
        })
    }
}

// Enum conversions for InterfaceStatusType
impl TryFrom<i32> for InterfaceStatusType {
    type Error = String;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match gateway_config::InterfaceStatusType::try_from(value) {
            Ok(gateway_config::InterfaceStatusType::InterfaceStatusUnknown) => {
                Ok(InterfaceStatusType::Unknown)
            }
            Ok(gateway_config::InterfaceStatusType::InterfaceStatusOperUp) => {
                Ok(InterfaceStatusType::OperUp)
            }
            Ok(gateway_config::InterfaceStatusType::InterfaceStatusOperDown) => {
                Ok(InterfaceStatusType::OperDown)
            }
            Ok(gateway_config::InterfaceStatusType::InterfaceStatusError) => {
                Ok(InterfaceStatusType::StatusError)
            }
            Err(_) => Err(format!("Unknown interface status type: {}", value)),
        }
    }
}

impl From<InterfaceStatusType> for gateway_config::InterfaceStatusType {
    fn from(status_type: InterfaceStatusType) -> Self {
        match status_type {
            InterfaceStatusType::Unknown => {
                gateway_config::InterfaceStatusType::InterfaceStatusUnknown
            }
            InterfaceStatusType::OperUp => gateway_config::InterfaceStatusType::InterfaceStatusOperUp,
            InterfaceStatusType::OperDown => gateway_config::InterfaceStatusType::InterfaceStatusOperDown,
            InterfaceStatusType::StatusError => gateway_config::InterfaceStatusType::InterfaceStatusError,
        }
    }
}

// Enum conversions for InterfaceAdminStatusType
impl TryFrom<i32> for InterfaceAdminStatusType {
    type Error = String;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match gateway_config::InterfaceAdminStatusType::try_from(value) {
            Ok(gateway_config::InterfaceAdminStatusType::InterfaceAdminStatusUnknown) => {
                Ok(InterfaceAdminStatusType::Unknown)
            }
            Ok(gateway_config::InterfaceAdminStatusType::InterfaceAdminStatusUp) => {
                Ok(InterfaceAdminStatusType::Up)
            }
            Ok(gateway_config::InterfaceAdminStatusType::InterfaceAdminStatusDown) => {
                Ok(InterfaceAdminStatusType::Down)
            }
            Err(_) => Err(format!("Unknown interface admin status type: {}", value)),
        }
    }
}

impl From<InterfaceAdminStatusType> for gateway_config::InterfaceAdminStatusType {
    fn from(status_type: InterfaceAdminStatusType) -> Self {
        match status_type {
            InterfaceAdminStatusType::Unknown => {
                gateway_config::InterfaceAdminStatusType::InterfaceAdminStatusUnknown
            }
            InterfaceAdminStatusType::Up => gateway_config::InterfaceAdminStatusType::InterfaceAdminStatusUp,
            InterfaceAdminStatusType::Down => gateway_config::InterfaceAdminStatusType::InterfaceAdminStatusDown,
        }
    }
}

// Enum conversions for ZebraStatusType
impl TryFrom<i32> for ZebraStatusType {
    type Error = String;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match gateway_config::ZebraStatusType::try_from(value) {
            Ok(gateway_config::ZebraStatusType::ZebraStatusNotConnected) => {
                Ok(ZebraStatusType::NotConnected)
            }
            Ok(gateway_config::ZebraStatusType::ZebraStatusConnected) => {
                Ok(ZebraStatusType::Connected)
            }
            Err(_) => Err(format!("Unknown zebra status type: {}", value)),
        }
    }
}

impl From<ZebraStatusType> for gateway_config::ZebraStatusType {
    fn from(status_type: ZebraStatusType) -> Self {
        match status_type {
            ZebraStatusType::NotConnected => {
                gateway_config::ZebraStatusType::ZebraStatusNotConnected
            }
            ZebraStatusType::Connected => gateway_config::ZebraStatusType::ZebraStatusConnected,
        }
    }
}

// Enum conversions for FrrAgentStatusType
impl TryFrom<i32> for FrrAgentStatusType {
    type Error = String;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match gateway_config::FrrAgentStatusType::try_from(value) {
            Ok(gateway_config::FrrAgentStatusType::FrrAgentStatusNotConnected) => {
                Ok(FrrAgentStatusType::NotConnected)
            }
            Ok(gateway_config::FrrAgentStatusType::FrrAgentStatusConnected) => {
                Ok(FrrAgentStatusType::Connected)
            }
            Err(_) => Err(format!("Unknown FRR agent status type: {}", value)),
        }
    }
}

impl From<FrrAgentStatusType> for gateway_config::FrrAgentStatusType {
    fn from(status_type: FrrAgentStatusType) -> Self {
        match status_type {
            FrrAgentStatusType::NotConnected => {
                gateway_config::FrrAgentStatusType::FrrAgentStatusNotConnected
            }
            FrrAgentStatusType::Connected => {
                gateway_config::FrrAgentStatusType::FrrAgentStatusConnected
            }
        }
    }
}

// Enum conversions for DataplaneStatusType
impl TryFrom<i32> for DataplaneStatusType {
    type Error = String;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match gateway_config::DataplaneStatusType::try_from(value) {
            Ok(gateway_config::DataplaneStatusType::DataplaneStatusUnknown) => {
                Ok(DataplaneStatusType::Unknown)
            }
            Ok(gateway_config::DataplaneStatusType::DataplaneStatusHealthy) => {
                Ok(DataplaneStatusType::Healthy)
            }
            Ok(gateway_config::DataplaneStatusType::DataplaneStatusInit) => {
                Ok(DataplaneStatusType::Init)
            }
            Ok(gateway_config::DataplaneStatusType::DataplaneStatusError) => {
                Ok(DataplaneStatusType::StatusError)
            }
            Err(_) => Err(format!("Unknown dataplane status type: {}", value)),
        }
    }
}

impl From<DataplaneStatusType> for gateway_config::DataplaneStatusType {
    fn from(status_type: DataplaneStatusType) -> Self {
        match status_type {
            DataplaneStatusType::Unknown => {
                gateway_config::DataplaneStatusType::DataplaneStatusUnknown
            }
            DataplaneStatusType::Healthy => {
                gateway_config::DataplaneStatusType::DataplaneStatusHealthy
            }
            DataplaneStatusType::Init => gateway_config::DataplaneStatusType::DataplaneStatusInit,
            DataplaneStatusType::StatusError => gateway_config::DataplaneStatusType::DataplaneStatusError,
        }
    }
}