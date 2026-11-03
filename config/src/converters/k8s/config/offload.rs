// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! The gateway-wide NIC offload switch, from the gateway's own annotations.

use k8s_intf::gateway_agent_crd::GatewayAgentSpec;

use super::ratelimit::ALPHA_PREFIX;
use crate::converters::k8s::FromK8sConversionError;

/// The gateway annotation that, set to `"false"`, keeps the gateway's policy out of its NICs:
/// everything is enforced in software alone. Unset or `"true"`, a capable NIC enforces what it can
/// in front of software.
pub const ATTEMPT_OFFLOADS: &str = "gateway.alpha.githedgehog.com/attempt-offloads";

/// Whether the gateway's annotations turn NIC offload off.
///
/// # Errors
///
/// Rejects a value of [`ATTEMPT_OFFLOADS`] other than `"true"` or `"false"`, and unknown alpha
/// gateway annotations.
pub fn offloads_disabled(spec: &GatewayAgentSpec) -> Result<bool, FromK8sConversionError> {
    let annotations = spec.gateway.as_ref().and_then(|g| g.annotations.as_ref());
    let mut disabled = false;
    for (key, value) in annotations.into_iter().flatten() {
        if !key.starts_with(ALPHA_PREFIX) {
            continue;
        }
        if key == super::ingress::INGRESS_POLICY {
            continue;
        }
        if key != ATTEMPT_OFFLOADS {
            return Err(FromK8sConversionError::NotAllowed(format!(
                "unknown alpha gateway annotation {key} on the gateway"
            )));
        }
        disabled = match value.trim() {
            "true" => false,
            "false" => true,
            other => {
                return Err(FromK8sConversionError::InvalidData(format!(
                    "{ATTEMPT_OFFLOADS}: expected \"true\" or \"false\", got {other:?}"
                )));
            }
        };
    }
    Ok(disabled)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use serde_json::{Value, json};

    use super::*;

    fn spec(annotations: &Value) -> GatewayAgentSpec {
        serde_json::from_value(json!({ "gateway": { "annotations": annotations } })).unwrap()
    }

    /// Offload is attempted unless the gateway says otherwise.
    #[test]
    fn the_gateway_annotation_turns_offload_off() {
        let disabled = |value: &str| offloads_disabled(&spec(&json!({ ATTEMPT_OFFLOADS: value })));
        let bare: GatewayAgentSpec = serde_json::from_value(json!({})).unwrap();
        assert!(!offloads_disabled(&bare).unwrap());
        assert!(!offloads_disabled(&spec(&json!({}))).unwrap());
        assert!(!disabled("true").unwrap());
        assert!(disabled("false").unwrap());
        assert!(disabled("no").is_err());
        assert!(
            !offloads_disabled(&spec(&json!({ "fabric.githedgehog.com/other": "x" }))).unwrap()
        );
        assert!(
            offloads_disabled(&spec(&json!({ "gateway.alpha.githedgehog.com/typo": "x" })))
                .is_err()
        );
    }

    /// The switch reaches the validated overlay, which the rate limiter publishes it with.
    #[test]
    fn the_switch_reaches_the_overlay() {
        let overlay = |value: &str| {
            crate::external::overlay::Overlay::try_from(&spec(&json!({ ATTEMPT_OFFLOADS: value })))
                .unwrap()
                .validate()
                .unwrap()
        };
        assert!(overlay("false").offloads_disabled());
        assert!(!overlay("true").offloads_disabled());
    }
}
