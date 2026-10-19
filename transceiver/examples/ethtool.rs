// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Read and decode the module of a network device: `ethtool <ifindex>`.
//!
//! Needs `CAP_NET_ADMIN`.

use dataplane_transceiver::Capture;
use dataplane_transceiver::ethtool::EthtoolEeprom;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let ifindex: u32 = std::env::args()
        .nth(1)
        .ok_or("usage: ethtool <ifindex>")?
        .parse()?;
    let (connection, handle) = ethtool2::new_connection()?;
    tokio::spawn(connection);
    let eeprom = EthtoolEeprom::new(handle, ifindex);
    let (module, image) = eeprom.capture(Capture::new()).await?;
    println!("{module:#?}");
    let (refreshed, _) = eeprom.capture(Capture::refresh(image)).await?;
    println!(
        "refreshed temperature: {:?}",
        refreshed.monitors.temperature
    );
    Ok(())
}
