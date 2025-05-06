// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

// mgmt/src/grpc/server.rs

use async_trait::async_trait;
use std::convert::TryFrom;
use std::sync::Arc;
use tonic::{Request, Response, Status};
use tracing::error;

// Import proto-generated types
use gateway_config::{
    ConfigService, ConfigServiceServer, Error, GatewayConfig, GetConfigGenerationRequest,
    GetConfigGenerationResponse, GetConfigRequest, UpdateConfigRequest, UpdateConfigResponse,
};

use crate::frr::frrmi::FrrMi;
use crate::processor::proc::new_gw_config;

// Import database access
use crate::models::external::configdb::gwconfigdb::GwConfigDatabase;
use tokio::sync::RwLock;

// Import converter module for async functions
use crate::grpc::converter;
use crate::models::external::configdb::gwconfig::GwConfig;

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
    config_db: Arc<RwLock<GwConfigDatabase>>,
    frrmi: FrrMi,
}

impl BasicConfigManager {
    pub fn new(config_db: Arc<RwLock<GwConfigDatabase>>, frrmi: FrrMi) -> Self {
        Self { config_db, frrmi }
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
        let config_db = self.config_db.read().await;
        let gw_config = config_db
            .get_current_config()
            .ok_or_else(|| "No configuration found".to_string())?;

        // Use the async converter function
        converter::convert_to_grpc_config(&gw_config.external).await
    }

    async fn get_generation(&self) -> Result<i64, String> {
        let config_db = self.config_db.read().await;
        if let Some(gw_config_gen) = config_db.get_current_gen() {
            Ok(gw_config_gen)
        } else {
            Err("No config is currently applied".to_string())
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

        // Create a new GwConfig
        let gw_config = GwConfig::new(external_config);

        // Get a write lock on the DB
        let mut config_db = self.config_db.write().await;

        // Process the config
        new_gw_config(&mut config_db, gw_config, &self.frrmi)
            .await
            .map_err(|e| {
                error!("Applying config failed: {e}");
                e.to_string()
            })
    }
}

/// Function to create the gRPC service
pub fn create_config_service(
    config_db: Arc<RwLock<GwConfigDatabase>>,
    frrmi: FrrMi,
) -> ConfigServiceServer<ConfigServiceImpl> {
    let config_manager = Arc::new(BasicConfigManager::new(config_db, frrmi));
    let service = ConfigServiceImpl::new(config_manager);
    ConfigServiceServer::new(service)
}
