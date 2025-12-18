// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

// mgmt/src/grpc/server.rs

use async_trait::async_trait;
use std::sync::Arc;
use tonic::{Request, Response, Status};
use tracing::{debug, error};

use crate::processor::mgmt_client::ConfigClient;
use config::converters::grpc::{
    convert_dataplane_status_to_grpc, convert_gateway_config_from_grpc_with_defaults,
};
use config::internal::status::DataplaneStatus;
use config::{GenId, GwConfig};

// Import proto-generated types
use gateway_config::{
    ConfigService, ConfigServiceServer, Error, GatewayConfig, GetConfigGenerationRequest,
    GetConfigGenerationResponse, GetConfigRequest, GetDataplaneStatusRequest,
    GetDataplaneStatusResponse, UpdateConfigRequest, UpdateConfigResponse,
};

/// Trait for configuration management
#[async_trait]
pub trait ConfigManager: Send + Sync {
    async fn get_current_config(&self) -> Result<GatewayConfig, String>;
    async fn get_generation(&self) -> Result<i64, String>;
    async fn apply_config(&self, config: GatewayConfig) -> Result<(), String>;
    async fn get_dataplane_status(&self) -> Result<DataplaneStatus, String>;
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

    async fn get_dataplane_status(
        &self,
        _request: Request<GetDataplaneStatusRequest>,
    ) -> Result<Response<GetDataplaneStatusResponse>, Status> {
        let internal = self
            .config_manager
            .get_dataplane_status()
            .await
            .map_err(|e| Status::internal(format!("Failed to get dataplane status: {e}")))?;

        let grpc = convert_dataplane_status_to_grpc(&internal)
            .map_err(|e| Status::internal(format!("Failed to encode status: {e}")))?;

        Ok(Response::new(grpc))
    }
}

/// Basic configuration manager implementation
pub struct BasicConfigManager {
    client: ConfigClient,
}

impl BasicConfigManager {
    pub fn new(client: ConfigClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl ConfigManager for BasicConfigManager {
    async fn get_current_config(&self) -> Result<GatewayConfig, String> {
        let config = self
            .client
            .get_current_config()
            .await
            .map_err(|e| e.to_string())?;
        gateway_config::GatewayConfig::try_from(&config.external)
    }

    async fn get_generation(&self) -> Result<GenId, String> {
        self.client
            .get_generation()
            .await
            .map_err(|e| e.to_string())
    }

    async fn apply_config(&self, grpc_config: GatewayConfig) -> Result<(), String> {
        // Convert config from gRPC to native external model
        let external_config = convert_gateway_config_from_grpc_with_defaults(&grpc_config)
            .map_err(|e| {
                error!("Failed to parse config: {e}");
                e
            })?;

        self.client
            .apply_config(GwConfig::new(external_config))
            .await
            .map_err(|e| e.to_string())
    }

    async fn get_dataplane_status(&self) -> Result<DataplaneStatus, String> {
        debug!("Received request to get dataplane status");
        self.client.get_status().await.map_err(|e| e.to_string())
    }
}

/// Function to create the gRPC service
pub fn create_config_service(client: ConfigClient) -> ConfigServiceServer<ConfigServiceImpl> {
    let config_manager = Arc::new(BasicConfigManager::new(client));
    let service = ConfigServiceImpl::new(config_manager);
    ConfigServiceServer::new(service)
}
