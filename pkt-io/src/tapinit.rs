// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Tap initialization

use std::collections::HashMap;

use args::InterfaceArg;
use interface_manager::interface::TapDevice;
use net::interface::InterfaceIndex;
use tracing::{error, info};

/// Creates a tap device for each of the [`InterfaceArg`]s provided.
///
/// # Errors
///
/// This function fails if any of the taps cannot be created.
pub async fn tap_init_async(
    ifargs: &[InterfaceArg],
) -> std::io::Result<HashMap<InterfaceArg, InterfaceIndex>> {
    info!("Creating tap devices");
    let mut out = HashMap::with_capacity(ifargs.len());
    for interface in ifargs {
        let response = TapDevice::open(&interface.interface).await;
        match response {
            Ok(tap) => {
                out.insert(interface.clone(), tap.ifindex());
            }
            Err(e) => {
                error!("Failed to create tap '{}': {e}", interface.interface);
                return Err(e);
            }
        }
    }
    Ok(out)
}
