// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Tap initialization

use args::InterfaceArg;
use interface_manager::interface::TapDevice;
use tokio::runtime::Runtime;
use tracing::{error, info};

/// Creates a tap device for each of the [`InterfaceArg`]s provided.
///
/// # Errors
///
/// This function fails if any of the taps cannot be created.
pub async fn tap_init_async(ifargs: &[InterfaceArg]) -> std::io::Result<()> {
    info!("Creating tap devices");
    for ifarg in ifargs.iter() {
        if let Err(e) = TapDevice::open(&ifarg.interface).await {
            error!("Failed to create tap '{}':{e}", ifarg.interface);
            return Err(e);
        } else {
            info!("Created tap device '{}'", ifarg.interface);
        }
    }
    Ok(())
}

/// Creates a tap device for each of the [`InterfaceArg`]s provided.
/// This is a sync wrapper to `tap_init_async`.
///
/// # Errors
///
/// This function fails if any of the taps cannot be created.
pub fn tap_init<'a>(port_specs: &[InterfaceArg]) -> std::io::Result<()> {
    Runtime::new()
        .expect("Tokio runtime creation failed!")
        .block_on(tap_init_async(port_specs))
}
