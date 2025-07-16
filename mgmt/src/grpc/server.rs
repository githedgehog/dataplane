// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

// mgmt/src/grpc/server.rs

use async_trait::async_trait;
use std::sync::Arc;
use tonic::{Request, Response, Status};
use tracing::debug;

use crate::processor::proc::{ConfigRequest, ConfigResponse};
use config::converters::grpc::convert_gateway_config_from_grpc_with_defaults;
use config::{GenId, GwConfig};

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
}

#[async_trait]
impl ConfigManager for BasicConfigManager {
    async fn get_current_config(&self) -> Result<GatewayConfig, String> {
        debug!("Received request to get current config");

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
                    gateway_config::GatewayConfig::try_from(&config.external)
                } else {
                    Err("No config is currently applied".to_string())
                }
            }
            _ => unreachable!(),
        }
    }

    async fn get_generation(&self) -> Result<GenId, String> {
        debug!("Received request to get current config generation");

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
        debug!("Received request to apply new config");

        // Convert config from gRPC to native external model
        let external_config = convert_gateway_config_from_grpc_with_defaults(&grpc_config)?;

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
