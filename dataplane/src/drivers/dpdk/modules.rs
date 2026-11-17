// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Read the pluggable modules of ports that have no kernel netdev, through DPDK.
//!
//! The transceiver agent reads modules through ethtool netlink, which needs a netdev. A port bound
//! to vfio has none, but DPDK can read its module for the PMDs that support it. DPDK returns a
//! flat memory image rather than addressing pages, which covers SFF modules (SFP, QSFP+, QSFP28)
//! but not CMIS ones (QSFP-DD, OSFP, QSFP112), whose banked pages it cannot reach.
//!
//! The reads run on the driver's supervisor thread, which queries the ports already: DPDK does
//! not promise that a port can serve two queries at once, and some PMDs reach shared firmware or
//! the module's bus for them. A read is a bus transaction which may take milliseconds, so the
//! supervisor reads at most one module on each of its polls, to keep its period short.

use clock::{Duration, Instant};
use dpdk::dev::ModuleKind;
use errno::ErrorCode;
use stats::TransceiverMetrics;
use tokio::sync::watch;
use tracing::info;
use transceiver::{Capture, Detail, Flat, FlatEeprom, FlatLayout, Image};

use super::port::Port;
use crate::drivers::status::PortReport;
use crate::transceiver_agent::{FULL_READ_EVERY, ModuleSnapshot};

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
    /// When the module should be read next.
    due: Instant,
    /// Whether reading stopped, as the PMD cannot read modules, or not this one: it says the same
    /// for both, so a link coming up, maybe with another module, gives it another chance.
    given_up: bool,
}

impl<'p, 'eal> ModuleReader<'p, 'eal> {
    fn new(port: &'p Port<'eal>, now: Instant) -> Self {
        Self {
            port,
            metrics: TransceiverMetrics::new(port.name.as_ref()),
            image: None,
            polls: 0,
            up: false,
            due: now,
            given_up: false,
        }
    }

    /// Follow the port's link, as the supervisor read it.
    fn follow_link(&mut self, up: bool, now: Instant) {
        // The module may have been swapped while the link was down: read it afresh, and soon.
        if up && !self.up {
            self.image = None;
            self.due = self.due.min(now);
            self.given_up = false;
        }
        self.up = up;
    }

    /// Read the module, and publish what was read, or why nothing was.
    fn poll(&mut self, publish: &watch::Sender<ModuleSnapshot>) {
        let reading = self.read();
        match &reading {
            Ok(module) => self.metrics.publish(module),
            Err(_) => self.metrics.absent(),
        }
        ModuleSnapshot::record(publish, &self.port.name, reading);
    }

    /// Read the module. On failure, forget what the last read found: the module may be gone, or
    /// another one may be in its place, which a refresh would not notice.
    fn read(&mut self) -> Result<transceiver::Module, String> {
        let read = self.try_read();
        if read.is_err() {
            self.image = None;
        }
        read
    }

    fn try_read(&mut self) -> Result<transceiver::Module, String> {
        let not_supported = [errno::NEG_ENOTSUP, errno::NEG_EOPNOTSUPP].map(ErrorCode::parse_i32);
        let info = match self.port.dev.module_info() {
            Ok(info) => info,
            Err(e) if not_supported.contains(&e) => {
                info!(
                    "port {}: the PMD cannot read pluggable modules, or not this one",
                    self.port.name
                );
                self.given_up = true;
                return Err("the PMD cannot read pluggable modules, or not this one".to_owned());
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

/// The modules of the ports that have no kernel netdev, which the supervisor reads in turn.
pub(crate) struct ModuleReaders<'p, 'eal> {
    readers: Vec<ModuleReader<'p, 'eal>>,
    interval: Duration,
    publish: watch::Sender<ModuleSnapshot>,
}

impl<'p, 'eal> ModuleReaders<'p, 'eal> {
    /// Read the modules of the `ports` that have no kernel netdev every `interval`, and publish
    /// them with the transceiver agent's readings; `None` if every port has a netdev.
    pub(crate) fn new(
        ports: &'p [Port<'eal>],
        interval: Duration,
        publish: watch::Sender<ModuleSnapshot>,
    ) -> Option<Self> {
        let now = clock::now();
        let readers: Vec<ModuleReader<'p, 'eal>> = ports
            .iter()
            .filter(|port| port.if_index.is_none())
            .map(|port| ModuleReader::new(port, now))
            .collect();
        if readers.is_empty() {
            return None;
        }
        info!(
            "reading the modules of {} port(s) without a kernel netdev through DPDK",
            readers.len()
        );
        // The supervisor reads one module per poll, so a port may wait a few seconds for its first
        // reading: say so meanwhile.
        for reader in &readers {
            ModuleSnapshot::record(
                &publish,
                &reader.port.name,
                Err("not read yet: the first read through DPDK is pending".to_owned()),
            );
        }
        Some(Self {
            readers,
            interval,
            publish,
        })
    }

    /// Follow the links in `reports`, and read the module that is the most overdue, if any.
    ///
    /// One module at most, so that the supervisor's poll waits for one read only.
    pub(crate) fn poll(&mut self, reports: &[PortReport]) {
        let now = clock::now();
        for reader in &mut self.readers {
            let up = reports
                .iter()
                .any(|report| report.name == reader.port.name.as_ref() && report.link_up);
            reader.follow_link(up, now);
        }
        let next = self
            .readers
            .iter_mut()
            .filter(|reader| !reader.given_up && reader.due <= now)
            .min_by_key(|reader| reader.due);
        if let Some(reader) = next {
            reader.poll(&self.publish);
            reader.due = clock::saturating_add(now, self.interval);
        }
    }
}
