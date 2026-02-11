// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! A configuration validator. This validator may perform the same validation that
//! the dataplane process. The intent is to compile this validator as WASM / WASI.
//! The validator expects a `GatewayAgent` CRD in JSON or YAML from stdin and produces
//! a result as a YAML string in stdout.

#![deny(clippy::all)]
#![allow(clippy::result_large_err)]
#![allow(clippy::field_reassign_with_default)]

use config::{ExternalConfig, GwConfig};
use k8s_types::generated::gateway_agent_crd::GatewayAgent;
use serde::{Deserialize, Serialize};
use std::io::{self, Read};

#[derive(Default)]
struct ConfigErrors {
    errors: Vec<String>, // only one error is supported at the moment
}

/// The type representing an error when validating a request
enum ValidateError {
    /// This type contains errors that may occur when using this tool.
    EnvironmentError(String),

    /// This type contains errors that may occur when deserializing from JSON or YAML.
    /// If the inputs are machine-generated, these should not occur.
    DeserializeError(String),

    /// This type contains errors that may occur if the metadata is incomplete or wrong.
    /// This should catch integration issues or problems in the K8s infrastructure.
    MetadataError(String),

    /// This type contains errors that may occur when converting the CRD to a gateway configuration.
    /// These may happen mostly due to type violations, out-of-range values, etc.
    ConversionError(String),

    /// This type contains configuration errors. If errors of this type are produced, this means
    /// that the configuration is syntactically correct and could be parsed, but it is:
    ///   - incomplete or
    ///   - contains values that are semantically incorrect as a whole or
    ///   - contains values that are not allowed / supported
    ///
    /// which would prevent the gateway from functioning correctly.
    /// Together with some conversion errors, these are errors the user is responsible for.
    Configuration(ConfigErrors),
}
impl ValidateError {
    /// Provide a string indicating the type of error
    fn get_type(&self) -> &str {
        match self {
            ValidateError::EnvironmentError(_) => "Environment",
            ValidateError::DeserializeError(_) => "Deserialization",
            ValidateError::MetadataError(_) => "Metadata",
            ValidateError::ConversionError(_) => "Conversion",
            ValidateError::Configuration(_) => "Configuration",
        }
    }

    /// Provide a list of messages depending on the error type
    fn get_msg(&self) -> Vec<String> {
        match self {
            ValidateError::EnvironmentError(v) => vec![v.clone()],
            ValidateError::DeserializeError(v) => vec![v.clone()],
            ValidateError::MetadataError(v) => vec![v.clone()],
            ValidateError::ConversionError(v) => vec![v.clone()],
            ValidateError::Configuration(v) => v.errors.to_vec(),
        }
    }
}

impl From<&ValidateError> for ValidateReply {
    fn from(value: &ValidateError) -> Self {
        let r#type = value.get_type();
        let msg = value.get_msg();

        ValidateReply {
            success: false,
            errors: msg
                .iter()
                .map(|m| ValidateErrorOut {
                    r#type: r#type.to_owned(),
                    message: m.clone(),
                    context: None,
                })
                .collect(),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct ValidateErrorOut {
    r#type: String,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    context: Option<String>,
}

/// The type representing the outcome of a validation request
#[derive(Serialize, Deserialize)]
struct ValidateReply {
    success: bool,
    errors: Vec<ValidateErrorOut>,
}
impl ValidateReply {
    fn success() -> Self {
        Self {
            success: true,
            errors: vec![],
        }
    }
}

/// Deserialize JSON/YAML string as a `GatewayAgent`
fn deserialize(ga_input: &str) -> Result<GatewayAgent, ValidateError> {
    let crd = serde_yaml_ng::from_str::<GatewayAgent>(ga_input)
        .map_err(|e| ValidateError::DeserializeError(e.to_string()))?;
    Ok(crd)
}

/// Validate metadata
fn validate_metadata(crd: &GatewayAgent) -> Result<&str, ValidateError> {
    let genid = crd.metadata.generation.ok_or(ValidateError::MetadataError(
        "Missing generation Id".to_string(),
    ))?;
    if genid == 0 {
        return Err(ValidateError::MetadataError(
            "Invalid generation Id".to_string(),
        ));
    }
    let gwname = crd
        .metadata
        .name
        .as_ref()
        .ok_or(ValidateError::MetadataError(
            "Missing gateway name".to_string(),
        ))?;
    if gwname.is_empty() {
        return Err(ValidateError::MetadataError(
            "Invalid gateway name".to_string(),
        ));
    }
    let namespace = crd
        .metadata
        .namespace
        .as_ref()
        .ok_or(ValidateError::MetadataError(
            "Missing namespace".to_string(),
        ))?;
    if namespace.as_str() != "fab" {
        return Err(ValidateError::MetadataError(format!(
            "Invalid namespace {namespace}"
        )));
    }

    Ok(gwname.as_str())
}

/// Main validation function
fn validate(gwagent_json: &str) -> Result<(), ValidateError> {
    let crd = deserialize(gwagent_json)?;
    let gwname = validate_metadata(&crd)?;

    let external = ExternalConfig::try_from(&crd)
        .map_err(|e| ValidateError::ConversionError(e.to_string()))?;

    let mut gwconfig = GwConfig::new(gwname, external);
    gwconfig.validate().map_err(|e| {
        let mut config = ConfigErrors::default();
        config.errors.push(e.to_string());
        ValidateError::Configuration(config)
    })?;

    Ok(())
}

/// Read from stdin, deserialize as JSON and validate
fn validate_from_stdin() -> Result<(), ValidateError> {
    let mut input = String::new();
    io::stdin()
        .read_to_string(&mut input)
        .map_err(|e| ValidateError::EnvironmentError(format!("Failed to read from stdin: {e}")))?;

    validate(&input)
}

/// Build a validation reply to be output as JSON
fn build_reply(result: Result<(), ValidateError>) -> ValidateReply {
    match result {
        Ok(()) => ValidateReply::success(),
        Err(e) => ValidateReply::from(&e),
    }
}

fn main() {
    let result = validate_from_stdin();
    let reply = build_reply(result);
    match serde_yaml_ng::to_string(&reply) {
        Ok(out) => println!("{out}"),
        Err(e) => eprintln!("Failure serializing validation response: {e}"),
    }
}
