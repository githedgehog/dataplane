// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

// mgmt/src/grpc/server.rs

use async_trait::async_trait;
use std::convert::TryFrom;
use std::sync::Arc;
use tonic::{Request, Response, Status};

use crate::grpc::converter::convert_to_grpc_config;
use crate::models::external::gwconfig::GwConfig;
use crate::processor::proc::{ConfigRequest, ConfigResponse};
use crate::{grpc::converter, models::external::gwconfig::GenId};

// Import proto-generated types
use gateway_config::{
    ConfigService, ConfigServiceServer, Error, GatewayConfig, GetConfigGenerationRequest,
    GetConfigGenerationResponse, GetConfigRequest, UpdateConfigRequest, UpdateConfigResponse,
};

/// Trait for configuration management
#[async_trait]
pub trait ConfigManager: Send + Sync {
    async fn get_current_config(&self) -> Result<GatewayConfig, String>;
    async fn get_generation(&self) -> Result<i64, String>;
    async fn apply_config(&self, config: GatewayConfig) -> Result<(), String>;
}

/// Implementation of the gRPC server
pub struct ConfigServiceImpl {
    config_manager: Arc<dyn ConfigManager>,
}

impl ConfigServiceImpl {
    pub fn new(config_manager: Arc<dyn ConfigManager>) -> Self {
        Self { config_manager }
    }
}

#[async_trait]
impl ConfigService for ConfigServiceImpl {
    async fn get_config(
        &self,
        _request: Request<GetConfigRequest>,
    ) -> Result<Response<GatewayConfig>, Status> {
        // Get current config from manager
        let current_config = self
            .config_manager
            .get_current_config()
            .await
            .map_err(|e| Status::internal(format!("Failed to get configuration: {e}")))?;

        Ok(Response::new(current_config))
    }

    async fn get_config_generation(
        &self,
        _request: Request<GetConfigGenerationRequest>,
    ) -> Result<Response<GetConfigGenerationResponse>, Status> {
        let generation = self
            .config_manager
            .get_generation()
            .await
            .map_err(|e| Status::internal(format!("Failed to get generation: {e}")))?;

        Ok(Response::new(GetConfigGenerationResponse { generation }))
    }

    async fn update_config(
        &self,
        request: Request<UpdateConfigRequest>,
    ) -> Result<Response<UpdateConfigResponse>, Status> {
        let update_request = request.into_inner();
        let grpc_config = update_request
            .config
            .ok_or_else(|| Status::invalid_argument("Missing config in update request"))?;

        // Apply the configuration
        match self.config_manager.apply_config(grpc_config).await {
            Ok(_) => Ok(Response::new(UpdateConfigResponse {
                error: Error::None as i32,
                message: "Configuration updated successfully".to_string(),
            })),
            Err(e) => Ok(Response::new(UpdateConfigResponse {
                error: Error::ApplyFailed as i32,
                message: format!("Failed to apply configuration: {e}"),
            })),
        }
    }
}

/// Basic configuration manager implementation
pub struct BasicConfigManager {
    channel_tx: Sender<ConfigChannelRequest>,
}

impl BasicConfigManager {
    pub fn new(channel_tx: Sender<ConfigChannelRequest>) -> Self {
        Self { channel_tx }
    }

    // Example function showing how to use TryFrom conversions for components
    // This is not part of the ConfigManager trait but shows how to use TryFrom
    async fn validate_device(&self, device: &gateway_config::Device) -> Result<(), String> {
        // Use TryFrom to convert to internal type
        let device_config = crate::models::internal::device::DeviceConfig::try_from(device)?;

        // Perform validation on internal type
        if device_config.settings.hostname.is_empty() {
            return Err("Device hostname cannot be empty".to_string());
        }

        // Could do more validation here

        Ok(())
    }

    // Example function showing how to use TryFrom for interface validation
    async fn validate_interfaces(
        &self,
        interfaces: &[gateway_config::Interface],
    ) -> Result<(), String> {
        // Convert and validate all interfaces
        for interface in interfaces {
            let internal_interface =
                crate::models::internal::interfaces::interface::InterfaceConfig::try_from(
                    interface,
                )?;

            // Perform validation
            if internal_interface.name.is_empty() {
                return Err("Interface name cannot be empty".to_string());
            }

            // Validate VTEP interfaces have required fields
            if let crate::models::internal::interfaces::interface::InterfaceType::Vtep(_) =
                &internal_interface.iftype
            {
                if internal_interface.addresses.is_empty() {
                    return Err(format!(
                        "VTEP interface {} must have an IP address",
                        internal_interface.name
                    ));
                }
            }
        }

        Ok(())
    }
}

#[async_trait]
impl ConfigManager for BasicConfigManager {
    async fn get_current_config(&self) -> Result<GatewayConfig, String> {
        // build a request to the config processor, send it and get the response
        let (req, rx) = ConfigChannelRequest::new(ConfigRequest::GetCurrentConfig);
        self.channel_tx
            .send(req)
            .await
            .map_err(|_| "Failure relaying request".to_string())?;
        let response = rx
            .await
            .map_err(|_| "Failure receiving from config processor".to_string())?;
        match response {
            ConfigResponse::GetCurrentConfig(opt_config) => {
                if let Some(config) = *opt_config {
                    Ok(convert_to_grpc_config(&config.external)
                        .await
                        .expect("Failed to convert to gRPC"))
                } else {
                    Err("No config is currently applied".to_string())
                }
            }
            _ => unreachable!(),
        }
    }

    async fn get_generation(&self) -> Result<GenId, String> {
        // build a request to the config processor, send it and get the response
        let (req, rx) = ConfigChannelRequest::new(ConfigRequest::GetGeneration);
        self.channel_tx
            .send(req)
            .await
            .map_err(|_| "Failure relaying request".to_string())?;
        let response = rx
            .await
            .map_err(|_| "Failure receiving from config processor".to_string())?;
        match response {
            ConfigResponse::GetGeneration(opt_genid) => {
                opt_genid.ok_or_else(|| "No config is currently applied".to_string())
            }
            _ => unreachable!(),
        }
    }

    async fn apply_config(&self, grpc_config: GatewayConfig) -> Result<(), String> {
        // Example: Validate components using TryFrom conversions
        if let Some(device) = &grpc_config.device {
            self.validate_device(device).await?;
        }

        // Validate interfaces in all VRFs
        if let Some(underlay) = &grpc_config.underlay {
            for vrf in &underlay.vrfs {
                self.validate_interfaces(&vrf.interfaces).await?;
            }
        }

        // Continue with conversion and applying config
        // Use the async converter function
        let external_config = converter::convert_from_grpc_config(&grpc_config).await?;

        // Create a new GwConfig with this ExternalConfig
        let gw_config = Box::new(GwConfig::new(external_config));

        // build a request to the config processor, send it and get the response
        let (req, rx) = ConfigChannelRequest::new(ConfigRequest::ApplyConfig(gw_config));
        self.channel_tx
            .send(req)
            .await
            .map_err(|_| "Failure relaying request".to_string())?;
        let response = rx
            .await
            .map_err(|_| "Failure receiving from config processor".to_string())?;
        match response {
            ConfigResponse::ApplyConfig(result) => {
                result.map_err(|e| format!("Failed to apply config: {e}"))
            }
            _ => unreachable!(),
        }
    }
}

use crate::processor::proc::ConfigChannelRequest;
use tokio::sync::mpsc::Sender;

/// Function to create the gRPC service
pub fn create_config_service(
    channel_tx: Sender<ConfigChannelRequest>,
) -> ConfigServiceServer<ConfigServiceImpl> {
    let config_manager = Arc::new(BasicConfigManager::new(channel_tx));
    let service = ConfigServiceImpl::new(config_manager);
    ConfigServiceServer::new(service)
}
