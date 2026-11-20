// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Read the pluggable modules of ports that have no kernel netdev, through DPDK.
//!
//! The transceiver agent reads modules through ethtool netlink, which needs a netdev. A port bound
//! to vfio has none, but DPDK can read its module for the PMDs that support it. DPDK returns a
//! flat memory image rather than addressing pages, which covers SFF modules (SFP, QSFP+, QSFP28)
//! but not CMIS ones (QSFP-DD, OSFP, QSFP112), whose banked pages it cannot reach.
//!
//! The reads are bus transactions which may block for milliseconds, so they run on a thread of
//! their own, which borrows the ports like the supervisor does.

use std::convert::Infallible;
use std::time::Duration;

use concurrency::thread;
use dpdk::dev::ModuleKind;
use errno::ErrorCode;
use lifecycle::Subsystem;
use stats::TransceiverMetrics;
use tokio::sync::watch;
use tracing::info;
use transceiver::{Capture, Detail, Flat, FlatEeprom, FlatLayout, Image};

use super::port::Port;
use crate::drivers::DriverError;
use crate::transceiver_agent::{FULL_READ_EVERY, ModuleSnapshot};

/// How often to check for shutdown while waiting for the next reading.
const CANCEL_CHECK: Duration = Duration::from_millis(250);

/// A port's module memory, read through its PMD.
struct DevEeprom<'p, 'eal>(&'p Port<'eal>);

impl FlatEeprom for DevEeprom<'_, '_> {
    type Error = ErrorCode;

    fn read_at(&mut self, offset: usize, buf: &mut [u8]) -> Result<(), ErrorCode> {
        let offset = u32::try_from(offset).map_err(|_| ErrorCode::parse_i32(errno::NEG_EINVAL))?;
        self.0.dev.module_eeprom(offset, buf)
    }
}

/// One port's module, and what is kept between readings.
struct ModuleReader<'p, 'eal> {
    port: &'p Port<'eal>,
    metrics: TransceiverMetrics,
    image: Option<Image>,
    polls: u32,
    up: bool,
    /// Why reading stopped for good, once it has.
    given_up: bool,
}

impl<'p, 'eal> ModuleReader<'p, 'eal> {
    fn new(port: &'p Port<'eal>) -> Self {
        Self {
            port,
            metrics: TransceiverMetrics::new(port.name.as_ref()),
            image: None,
            polls: 0,
            up: false,
            given_up: false,
        }
    }

    /// Read the module, and publish what was read, or why nothing was.
    fn poll(&mut self, publish: &watch::Sender<ModuleSnapshot>) {
        if self.given_up {
            return;
        }
        // The module may have been swapped while the link was down.
        let up = self.port.dev.link().is_ok_and(|link| link.up);
        if up && !self.up {
            self.image = None;
        }
        self.up = up;
        let reading = self.read();
        match &reading {
            Ok(module) => self.metrics.publish(module),
            Err(_) => self.metrics.absent(),
        }
        ModuleSnapshot::record(publish, &self.port.name, reading);
    }

    fn read(&mut self) -> Result<transceiver::Module, String> {
        let not_supported = [errno::NEG_ENOTSUP, errno::NEG_EOPNOTSUPP].map(ErrorCode::parse_i32);
        let info = match self.port.dev.module_info() {
            Ok(info) => info,
            Err(e) if not_supported.contains(&e) => {
                info!(
                    "port {}: the PMD cannot read pluggable modules",
                    self.port.name
                );
                self.given_up = true;
                return Err("the PMD cannot read pluggable modules".to_owned());
            }
            Err(e) => return Err(format!("no module could be read: {e}")),
        };
        let layout = match info.kind {
            ModuleKind::Sff8079 => FlatLayout::Sff8079,
            ModuleKind::Sff8472 => FlatLayout::Sff8472,
            ModuleKind::Sff8636 | ModuleKind::Sff8436 => FlatLayout::Sff8636 {
                len: usize::try_from(info.len).unwrap_or(0),
            },
            ModuleKind::Other(code) => {
                return Err(format!(
                    "the PMD reports module type {code}, which cannot be read through DPDK"
                ));
            }
        };
        self.polls = self.polls.wrapping_add(1);
        let capture = match self.image.take() {
            Some(known) if !self.polls.is_multiple_of(FULL_READ_EVERY) => Capture::refresh(known),
            _ => Capture::new(),
        };
        let mut eeprom = Flat::new(DevEeprom(self.port), layout);
        let (module, image) = transceiver::read(&mut eeprom, capture).map_err(|e| e.to_string())?;
        if matches!(module.detail, Detail::Cmis(_)) {
            return Err("CMIS modules cannot be read through DPDK".to_owned());
        }
        self.image = Some(image);
        Ok(module)
    }
}

/// Read the modules of the `ports` that have no kernel netdev every `interval`, until `subsystem`
/// stops, and publish them with the transceiver agent's readings.
///
/// # Errors
///
/// Fails if the thread cannot be spawned.
pub(crate) fn spawn_module_reader<'p, 'scope, 'eal>(
    scope: &'scope thread::Scope<'scope, '_>,
    subsystem: &Subsystem,
    ports: &'p [Port<'eal>],
    interval: Duration,
    publish: watch::Sender<ModuleSnapshot>,
) -> Result<(), DriverError>
where
    'p: 'scope,
{
    let mut readers: Vec<ModuleReader<'p, 'eal>> = ports
        .iter()
        .filter(|port| port.if_index.is_none())
        .map(ModuleReader::new)
        .collect();
    if readers.is_empty() {
        return Ok(());
    }
    let subsystem = subsystem.clone();
    thread::Builder::new()
        .name("dpdk-modules".to_string())
        .spawn_scoped(scope, move || {
            info!(
                "reading the modules of {} port(s) without a kernel netdev through DPDK",
                readers.len()
            );
            while !subsystem.is_cancelled() {
                for reader in &mut readers {
                    reader.poll(&publish);
                }
                let mut waited = Duration::ZERO;
                while waited < interval && !subsystem.is_cancelled() {
                    thread::sleep(CANCEL_CHECK);
                    waited += CANCEL_CHECK;
                }
            }
            Ok::<(), Infallible>(())
        })
        .map_err(|e| {
            DriverError::PortSetup(format!("failed to spawn the DPDK module reader: {e}"))
        })?;
    Ok(())
}
