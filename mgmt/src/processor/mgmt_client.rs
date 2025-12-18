// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Interface to management processor

#![allow(unused)] // TEMPORARY

use config::ConfigError;
use config::ConfigResult;
use config::GenId;
use config::GwConfig;
use config::internal::status::DataplaneStatus;

use tokio::sync::mpsc::Sender;
use tokio::sync::oneshot;
use tokio::sync::oneshot::Receiver;
#[allow(unused)]
use tracing::{debug, error, info};

use thiserror::Error;

/// A request type to the `ConfigProcessor`
#[derive(Debug)]
pub enum ConfigRequest {
    ApplyConfig(Box<GwConfig>),
    GetCurrentConfig,
    GetGeneration,
    GetDataplaneStatus,
}

/// A response from the `ConfigProcessor`
#[derive(Debug)]
pub enum ConfigResponse {
    ApplyConfig(ConfigResult),
    GetCurrentConfig(Box<Option<GwConfig>>),
    GetGeneration(Option<GenId>),
    GetDataplaneStatus(Box<DataplaneStatus>),
}
type ConfigResponseChannel = oneshot::Sender<ConfigResponse>;

/// A type that includes a request to the `ConfigProcessor` and a channel to
/// issue the response back
pub struct ConfigChannelRequest {
    pub(crate) request: ConfigRequest, /* a request to the mgmt processor */
    pub(crate) reply_tx: ConfigResponseChannel, /* the one-shot channel to respond */
}
impl ConfigChannelRequest {
    #[must_use]
    pub fn new(request: ConfigRequest) -> (Self, Receiver<ConfigResponse>) {
        let (reply_tx, reply_rx) = oneshot::channel();
        let request = Self { request, reply_tx };
        (request, reply_rx)
    }
}

/// The type of errors that can happen when issuing requests to a [`ConfigProcessor`]
#[derive(Error, Debug)]
#[allow(clippy::enum_variant_names)]
pub enum ConfigProcessorError {
    #[error("Failure sending request to config processor: {0}")]
    SendRequestError(#[from] tokio::sync::mpsc::error::SendError<ConfigChannelRequest>),
    #[error("Failure receiving response from config processor: {0}")]
    RecvResponseError(#[from] tokio::sync::oneshot::error::RecvError),
    #[error("Failure applying config: {0}")]
    ApplyConfigError(#[from] ConfigError),
    #[error("No configuration is applied")]
    NoConfigApplied,
}

/// A cloneable object that allows sending requests to a [`ConfigProcessor`].
#[derive(Clone)]
pub struct ConfigClient {
    tx: Sender<ConfigChannelRequest>,
}

impl ConfigClient {
    #[must_use]
    pub fn new(channel_tx: Sender<ConfigChannelRequest>) -> Self {
        Self { tx: channel_tx }
    }

    /// Apply the provided `GwConfig`
    ///
    /// # Errors
    /// This method returns `ConfigProcessorError` if the config request could not be sent, the response
    /// could not be received or the response was a failure.
    pub async fn apply_config(&self, gwconfig: GwConfig) -> Result<(), ConfigProcessorError> {
        let (req, rx) = ConfigChannelRequest::new(ConfigRequest::ApplyConfig(Box::new(gwconfig)));
        self.tx.send(req).await?;
        match rx.await? {
            ConfigResponse::ApplyConfig(Err(e)) => Err(e.into()),
            ConfigResponse::ApplyConfig(Ok(())) => Ok(()),
            _ => unreachable!(),
        }
    }

    /// Get the config currently applied.
    ///
    /// # Errors
    /// This method returns `ConfigProcessorError` if the request could not be sent or the response
    /// could not be received.
    pub async fn get_current_config(&self) -> Result<GwConfig, ConfigProcessorError> {
        let (req, rx) = ConfigChannelRequest::new(ConfigRequest::GetCurrentConfig);
        self.tx.send(req).await?;
        let gwconfig = match rx.await? {
            ConfigResponse::GetCurrentConfig(opt_config) => opt_config,
            _ => unreachable!(),
        };
        gwconfig.ok_or(ConfigProcessorError::NoConfigApplied)
    }

    /// Apply the generation id of the configuration currently applied.
    ///
    /// # Errors
    /// This method returns `ConfigProcessorError` if the config request could not be sent or the response
    /// could not be received.
    pub async fn get_generation(&self) -> Result<GenId, ConfigProcessorError> {
        let (req, rx) = ConfigChannelRequest::new(ConfigRequest::GetGeneration);
        self.tx.send(req).await?;
        let genid = match rx.await? {
            ConfigResponse::GetGeneration(genid) => genid,
            _ => unreachable!(),
        };
        genid.ok_or(ConfigProcessorError::NoConfigApplied)
    }

    /// Retrieve the current status of dataplane.
    ///
    /// # Errors
    /// This method returns `ConfigProcessorError` if the config request could not be sent or the response
    /// could not be received.
    pub async fn get_status(&self) -> Result<DataplaneStatus, ConfigProcessorError> {
        let (req, rx) = ConfigChannelRequest::new(ConfigRequest::GetDataplaneStatus);
        self.tx.send(req).await?;
        match rx.await? {
            ConfigResponse::GetDataplaneStatus(status) => Ok(*status),
            _ => unreachable!(),
        }
    }
}
