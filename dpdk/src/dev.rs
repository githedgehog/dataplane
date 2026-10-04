// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Ethernet device management.

use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use core::ffi::{CStr, c_uint};
use core::fmt::{Debug, Display, Formatter};
use core::marker::PhantomData;
use core::ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign};
use tracing::{debug, error, info};

use crate::eal::Eal;
use crate::queue;
use crate::queue::hairpin::{HairpinConfigFailure, HairpinQueue, HairpinQueueId};
use crate::queue::rx::{RxQueue, RxQueueConfig};
use crate::queue::tx::{TxQueue, TxQueueConfig};
use crate::queue::{QueueStore, Queues};
use crate::socket::SocketId;
use crate::sync::Mutex;
use dpdk_sys::rte_eth_rx_mq_mode::{RTE_ETH_MQ_RX_NONE, RTE_ETH_MQ_RX_RSS};
use dpdk_sys::rte_eth_tx_mq_mode::RTE_ETH_MQ_TX_NONE;
use dpdk_sys::*;
use errno::{Errno, ErrorCode, StandardErrno};
use queue::{rx, tx};

mod claim;
pub(crate) use claim::Ownership;
pub use claim::{ClaimError, ForeignOwner, PortClaim, PortOwner};
mod probe;
pub use probe::ProbeError;
#[cfg(test)]
mod queue_tests;
#[cfg(test)]
mod rss_tests;

/// Default Ethernet MTU, clamped to the device limits when configured.
pub const DEFAULT_MTU: u16 = 1500;

/// A DPDK Ethernet port index.
///
/// This is a transparent newtype around `u16` to provide type safety and prevent accidental misuse.
#[repr(transparent)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
// TODO: inner value should be `pub(crate)`
pub struct DevIndex(pub u16);

impl Display for DevIndex {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Failure to read a valid source MAC address from a device.
#[derive(Debug, thiserror::Error)]
pub enum MacAddressError {
    #[error(transparent)]
    Driver(#[from] ErrorCode),
    #[error(transparent)]
    InvalidAddress(#[from] net::eth::mac::SourceMacAddressError),
}

#[derive(Debug, thiserror::Error, Copy, Clone)]
pub enum DevInfoError {
    #[error("Device information not supported")]
    NotSupported,
    #[error("Device information not available")]
    NotAvailable,
    #[error("Invalid argument")]
    InvalidArgument,
    #[error("Unknown error which matches a standard errno")]
    UnknownStandard(StandardErrno),
    #[error("Unknown error: {0:?}")]
    Unknown(Errno),
}

impl DevIndex {
    /// The maximum number of ports supported by DPDK.
    pub const MAX: u16 = RTE_MAX_ETHPORTS as u16;

    /// The index of the port represented as a `u16`.
    #[must_use]
    pub fn as_u16(&self) -> u16 {
        self.0
    }

    /// Query device information without an EAL lifetime.
    ///
    /// Keep this private to the crate: [`Manager::info`] and [`Manager::iter`] tie the result
    /// to their EAL borrow before exposing it to callers.
    ///
    /// # Errors
    ///
    /// Returns [`DevInfoError`] if the device information cannot be retrieved.
    #[tracing::instrument(level = "trace", ret)]
    pub(crate) fn info(&self) -> Result<DevInfo<'static>, DevInfoError> {
        let mut dev_info = rte_eth_dev_info::default();

        let ret = unsafe { rte_eth_dev_info_get(self.0, &mut dev_info) };

        if ret != 0 {
            return match ret {
                errno::NEG_ENOTSUP => {
                    error!(
                        "Device information not supported for port {index}",
                        index = self.0
                    );
                    Err(DevInfoError::NotSupported)
                }
                errno::NEG_ENODEV => {
                    error!(
                        "Device information not available for port {index}",
                        index = self.0
                    );
                    Err(DevInfoError::NotAvailable)
                }
                errno::NEG_EINVAL => {
                    error!(
                        "Invalid argument when getting device info for port {index}",
                        index = self.0
                    );
                    Err(DevInfoError::InvalidArgument)
                }
                val => {
                    let unknown = match StandardErrno::parse_i32(val) {
                        Ok(standard) => {
                            return Err(DevInfoError::UnknownStandard(standard));
                        }
                        Err(unknown) => unknown,
                    };
                    error!(
                        "Unknown error when getting device info for port {index}: {val} (error code: {unknown:?})",
                        index = self.0,
                        val = val
                    );
                    Err(DevInfoError::Unknown(Errno(val)))
                }
            };
            // error!(
            //     "Failed to get device info for port {index}: {err}",
            //     index = self.0
            // );
            // return Err(err);
        }

        Ok(DevInfo {
            index: DevIndex(self.0),
            inner: dev_info,
            eal: PhantomData,
        })
    }

    /// Get the [`SocketId`] of the device associated with this device index.
    ///
    /// If the socket id cannot be determined, this function will return `SocketId::ANY`.
    ///
    /// # Errors
    ///
    /// This function will return an error if the port index is invalid.
    ///
    /// # Safety
    ///
    /// * This function requires that the DPDK environment has been initialized
    ///   (statically ensured).
    /// * This function may panic if DPDK returns an unexpected (undocumented) error code after
    ///   failing to determine the socket id.
    pub fn socket_id(&self) -> Result<SocketId, ErrorCode> {
        let socket_id = unsafe { rte_eth_dev_socket_id(self.as_u16()) };
        if socket_id == -1 {
            match unsafe { rte_errno_get() } {
                0 => {
                    debug!("Unable to determine SocketId for port {self}.  Using ANY",);
                    return Ok(SocketId::ANY);
                }
                errno::EINVAL => {
                    // We are asking DPDK for the socket id of a port that doesn't exist.
                    return Err(ErrorCode::parse_i32(errno::EINVAL));
                }
                errno => {
                    // Getting here means we have an unknown error.
                    // This should never happen as we have already checked for the two known error
                    // conditions.
                    // The only thing to do now is [`Eal::fatal_error`] and exit.
                    // Unknown errors are programmer errors and are never recoverable.
                    Eal::fatal_error(format!(
                        "Unknown errno {errno} when determining SocketId for port {self},",
                    ));
                }
            };
        }

        if socket_id < -1 {
            // This should never happen, *but* the socket id is supposed to be a `c_uint`.
            // However, DPDK has a depressing number of sign and bit-width errors in its API, so we
            // need to check for nonsense values to make a properly safe wrapper.
            // Better to panic than malfunction.
            Eal::fatal_error(format!("SocketId for port {self} is negative? {socket_id}"));
        }

        Ok(SocketId(socket_id as c_uint))
    }
}

impl From<DevIndex> for u16 {
    fn from(value: DevIndex) -> u16 {
        value.0
    }
}

/// RSS parameters applied during device configuration, before RX queue setup.
#[derive(Debug, PartialEq, Clone, Eq, PartialOrd, Ord, Hash)]
pub struct RssConf {
    /// Toeplitz key, or `None` for the driver default. A supplied key must contain
    /// exactly the device's `hash_key_size` bytes.
    pub key: Option<Box<[u8]>>,
    /// Requested `RTE_ETH_RSS_*` hash types.
    pub hf: u64,
}

impl RssConf {
    /// The standard 40-byte Microsoft Toeplitz RSS key.
    ///
    /// This is the key nearly every NIC and driver defaults to, so a software model of the hash can
    /// use it to predict a device's reported `mbuf.hash.rss`.
    ///
    /// It is *not* symmetric: `H(src, dst) != H(dst, src)`.  A key of period two
    /// (`0x6d5a` repeated) would be, but symmetry is not worth buying here: mlx5 offers symmetric
    /// Toeplitz only through the `rte_flow` RSS action, and a NAT'd flow's reverse packet does not
    /// carry the reversed tuple anyway, so no hash property the NIC can have would co-locate the
    /// two halves.
    pub const DEFAULT_KEY: [u8; 40] = [
        0x6d, 0x5a, 0x56, 0xda, 0x25, 0x5b, 0x0e, 0xc2, 0x41, 0x67, 0x25, 0x3d, 0x43, 0xa3, 0x8f,
        0xb0, 0xd0, 0xca, 0x2b, 0xcb, 0xae, 0x7b, 0x30, 0xb4, 0x77, 0xcb, 0x2d, 0xa3, 0x80, 0x30,
        0xf2, 0x0c, 0x6a, 0x42, 0xb7, 0x3b, 0xbe, 0xac, 0x01, 0xfa,
    ];

    /// The hash types worth asking for on a forwarding plane: L3 addresses for every IP packet,
    /// plus L4 ports for TCP and UDP so that two flows between the same pair of hosts can land on
    /// different queues.
    ///
    /// A device is not obliged to support all of these; [`RssConf::supported_on`] narrows the set
    /// to what a given device advertises.
    pub const DEFAULT_HASH_TYPES: u64 =
        (RTE_ETH_RSS_IP as u64) | (RTE_ETH_RSS_TCP as u64) | (RTE_ETH_RSS_UDP as u64);

    /// An RSS configuration for `dev` using the driver's default key and as much of
    /// [`DEFAULT_HASH_TYPES`](Self::DEFAULT_HASH_TYPES) as the device advertises.
    ///
    /// Returns `None` if the device advertises no RSS hash functions at all, which is how the
    /// emulated NICs (e1000, e1000e, and virtio without multi-queue negotiation) report.  Those
    /// devices cannot spread across queues and must not be handed an RSS configuration.
    ///
    /// Intersecting rather than erroring is deliberate: `rte_eth_dev_configure` rejects an
    /// `rss_hf` that is not a subset of `flow_type_rss_offloads`, and which hash types a device
    /// supports is a property of the device rather than a thing a caller can be expected to know.
    /// Asking for TCP ports on a device that only hashes L3 should cost L4 spread, not the port.
    #[must_use]
    pub fn supported_on(dev: &DevInfo) -> Option<RssConf> {
        Self::from_hash_types(dev.rss_hash_types())
    }

    /// [`supported_on`](Self::supported_on) against a raw `flow_type_rss_offloads` mask.
    ///
    /// Split out from `supported_on` because a [`DevInfo`] can only be obtained from a real probed
    /// device -- unit tests run under `--no-pci`, where none exists -- and the intersection is the
    /// part with behaviour worth pinning down.
    #[must_use]
    pub fn from_hash_types(supported: u64) -> Option<RssConf> {
        let hf = Self::DEFAULT_HASH_TYPES & supported;
        if hf == 0 {
            return None;
        }
        Some(RssConf { key: None, hf })
    }
}

/// Device queue counts, offloads, MTU, and RSS.
#[derive(Debug, PartialEq, Clone, Eq, PartialOrd, Ord, Hash)]
pub struct DevConfig {
    // /// Information about the device.
    // pub info: DevInfo<'info>,
    /// The number of receive queues to be made available after device initialization.
    pub num_rx_queues: u16,
    /// The number of transmit queues to be made available after device initialization.
    pub num_tx_queues: u16,
    /// The number of hairpin queues to be made available after device initialization.
    pub num_hairpin_queues: u16,
    /// The transmit offloads to request. The device enables the intersection of these and what it
    /// supports; nothing is enabled implicitly. `MBUF_FAST_FREE` is never requested, because it
    /// would let the driver return shared or indirect mbufs straight to their pool.
    pub tx_offloads: TxOffloadConfig,
    /// The receive offloads to request, intersected with what the device supports.
    pub rx_offloads: RxOffload,
    /// Requested MTU. `None` uses [`DEFAULT_MTU`] clamped to device limits;
    /// an explicit value outside those limits returns [`DevConfigError::MtuOutOfRange`].
    pub mtu: Option<u16>,
    /// RSS parameters. `None` requests no hash types (`rss_hf = 0`).
    pub rss: Option<RssConf>,
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
/// Errors that can occur when configuring a DPDK ethernet device.
pub enum DevConfigError {
    /// The driver rejected the configuration.
    #[error("the driver rejected the configuration: {message} ({code:?})")]
    DriverSpecificError {
        /// The error code the driver returned.
        code: Errno,
        /// DPDK's description of `code`, copied out of its per-thread buffer.
        message: String,
    },
    /// The requested MTU is outside the device's advertised `[min, max]` range.
    #[error("MTU {requested} is outside the device's range [{min}, {max}]")]
    MtuOutOfRange {
        /// The MTU that was requested.
        requested: u16,
        /// The device's minimum supported MTU.
        min: u16,
        /// The device's maximum supported MTU.
        max: u16,
    },
    /// RSS hashing was requested but the device advertises no RSS hash functions.
    #[error("RSS was requested but the device supports no RSS hash functions")]
    RssUnsupported,
    /// The supplied RSS key does not match the device's required length.
    #[error("the RSS key is {actual} bytes but the device requires {expected}")]
    RssKeyLength {
        /// The supplied key length.
        actual: usize,
        /// The key length advertised by the device.
        expected: u8,
    },
    /// The requested RSS hash types include bits the device does not support.
    ///
    /// `rte_eth_dev_configure` rejects any `rss_hf` that is not a subset of the device's
    /// `flow_type_rss_offloads`.  Use [`RssConf::supported_on`] to intersect a wish list with what
    /// a given device can actually hash on.
    #[error("RSS hash types {requested:#x} include bits outside the supported {supported:#x}")]
    RssHashTypesUnsupported {
        /// The `RTE_ETH_RSS_*` bits that were requested.
        requested: u64,
        /// The `RTE_ETH_RSS_*` bits the device advertises.
        supported: u64,
    },
}

impl DevConfig {
    /// Clamp the default MTU or validate an explicit request.
    /// A zero `max_mtu` leaves validation to the driver.
    fn resolve_mtu(&self, dev: &DevInfo) -> Result<u16, DevConfigError> {
        let min = dev.inner.min_mtu;
        let max = dev.inner.max_mtu;
        if max == 0 || min > max {
            return Ok(self.mtu.unwrap_or(DEFAULT_MTU));
        }
        match self.mtu {
            Some(requested) if requested < min || requested > max => {
                Err(DevConfigError::MtuOutOfRange {
                    requested,
                    min,
                    max,
                })
            }
            Some(requested) => Ok(requested),
            None => Ok(DEFAULT_MTU.clamp(min, max)),
        }
    }

    /// Configure a claimed port, preserving its EAL lifetime.
    ///
    /// Returns [`DevConfigFailure`] with the claim if configuration fails.
    // The error hands the claim back; this large result is used only during setup.
    #[allow(clippy::result_large_err)]
    pub fn apply<'eal>(
        &self,
        port: PortClaim<'eal>,
    ) -> Result<Dev<'eal, Configured>, DevConfigFailure<'eal>> {
        let config = match self.configure(port.info()) {
            Ok(config) => config,
            Err(error) => return Err(DevConfigFailure { error, claim: port }),
        };
        let (dev, owner) = port.into_parts();
        Ok(Dev {
            lifecycle: PortLifecycle {
                port: dev.index(),
                stage: Stage::Configured,
                config,
                owner,
            },
            info: dev,
            queues: Mutex::new(Some(QueueStore::new(
                self.num_rx_queues + self.num_hairpin_queues,
                self.num_tx_queues + self.num_hairpin_queues,
            ))),
            state: PhantomData,
            _thread: PhantomData,
        })
    }

    /// Configure the port and return the configuration it must retain.
    /// DPDK keeps a pointer to this copy's RSS key until the port closes.
    fn configure(&self, dev: &DevInfo<'_>) -> Result<DevConfig, DevConfigError> {
        let mtu = self.resolve_mtu(dev)?;
        let mut config = self.clone();
        let rss_conf = config.prepare_rss(dev)?;
        if let Some(rss) = &config.rss
            && rss.hf & !dev.rss_hash_types() != 0
        {
            return Err(DevConfigError::RssHashTypesUnsupported {
                requested: rss.hf,
                supported: dev.rss_hash_types(),
            });
        }
        let mut eth_conf = rte_eth_conf {
            txmode: rte_eth_txmode {
                mq_mode: RTE_ETH_MQ_TX_NONE,
                offloads: {
                    let requested = TxOffload::from(self.tx_offloads);
                    let supported = dev.tx_offload_caps();
                    (requested & supported).0
                        & !u64::from(dpdk_sys::RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
                },
                ..Default::default()
            },
            rxmode: rte_eth_rxmode {
                mtu: u32::from(mtu),
                // Devices without RSS support reject RTE_ETH_MQ_RX_RSS.
                mq_mode: if dev.supports_rss() {
                    RTE_ETH_MQ_RX_RSS
                } else {
                    RTE_ETH_MQ_RX_NONE
                },
                // Used only when TCP LRO is enabled; zero requests the driver default.
                max_lro_pkt_size: dev.inner.max_lro_pkt_size,
                offloads: self.rx_offloads.0 & dev.rx_offload_caps().0,
                ..Default::default()
            },
            ..Default::default()
        };

        eth_conf.rx_adv_conf.rss_conf = rss_conf;

        let nb_rx_queues = self.num_rx_queues + self.num_hairpin_queues;
        let nb_tx_queues = self.num_tx_queues + self.num_hairpin_queues;

        let ret = unsafe {
            rte_eth_dev_configure(dev.index().as_u16(), nb_rx_queues, nb_tx_queues, &eth_conf)
        };

        if ret != 0 {
            error!(
                "Failed to configure port {port}, error code: {code}",
                port = dev.index(),
                code = ret
            );

            // `rte_eth_dev_configure` returns a negative errno. `rte_strerror` formats into a
            // per-thread buffer that the next call overwrites, so copy the message out now.
            // SAFETY: `rte_strerror` always returns a valid NUL-terminated string.
            let message = unsafe { CStr::from_ptr(rte_strerror(-ret)) }
                .to_string_lossy()
                .into_owned();
            return Err(DevConfigError::DriverSpecificError {
                code: Errno::from(-ret),
                message,
            });
        }
        Ok(config)
    }

    // The returned key pointer borrows this config; keep it alive and unchanged while in use.
    fn prepare_rss(&mut self, dev: &DevInfo) -> Result<rte_eth_rss_conf, DevConfigError> {
        let Some(rss) = &mut self.rss else {
            return Ok(rte_eth_rss_conf::default());
        };
        if !dev.supports_rss() {
            return Err(DevConfigError::RssUnsupported);
        }
        let mut conf = rte_eth_rss_conf {
            rss_hf: rss.hf,
            ..Default::default()
        };
        if let Some(key) = &mut rss.key {
            let expected = dev.inner.hash_key_size;
            if key.len() != usize::from(expected) {
                return Err(DevConfigError::RssKeyLength {
                    actual: key.len(),
                    expected,
                });
            }
            conf.rss_key = key.as_mut_ptr();
            conf.rss_key_len = expected;
        }
        Ok(conf)
    }
}

/// A configuration error and the retained port claim, allowing a retry.
#[derive(Debug, thiserror::Error)]
#[error("failed to configure port {}: {error}", self.claim.info().index())]
pub struct DevConfigFailure<'eal> {
    /// The configuration error.
    #[source]
    pub error: DevConfigError,
    /// The claim retained after configuration failed.
    pub claim: PortClaim<'eal>,
}

#[repr(transparent)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
/// Transmit offload flags for ethernet devices.
pub struct TxOffload(u64);

#[repr(transparent)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
/// Receive offload flags for ethernet devices.
pub struct RxOffload(u64);

impl From<TxOffload> for u64 {
    fn from(value: TxOffload) -> Self {
        value.0
    }
}

impl From<u64> for TxOffload {
    fn from(value: u64) -> Self {
        TxOffload(value)
    }
}

impl From<RxOffload> for u64 {
    fn from(value: RxOffload) -> Self {
        value.0
    }
}

impl From<u64> for RxOffload {
    fn from(value: u64) -> Self {
        RxOffload(value)
    }
}

#[non_exhaustive]
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
/// Verbose configuration for transmit offloads.
///
/// This struct is mostly for coherent reporting on network cards.
///
/// TODO: fill in remaining offload types from `rte_ethdev.h`
pub struct TxOffloadConfig {
    /// GENEVE tunnel segmentation offload.
    pub geneve_tnl_tso: bool,
    /// GRE tunnel segmentation offload.
    pub gre_tnl_tso: bool,
    /// IPIP tunnel segmentation offload.
    pub ipip_tnl_tso: bool,
    /// IPv4 checksum calculation.
    pub ipv4_cksum: bool,
    /// MACsec insertion.
    pub macsec_insert: bool,
    /// Outer IPv4 checksum calculation.
    pub outer_ipv4_cksum: bool,
    /// QinQ (double VLAN) insertion.
    pub qinq_insert: bool,
    /// SCTP checksum calculation.
    pub sctp_cksum: bool,
    /// TCP checksum calculation.
    pub tcp_cksum: bool,
    /// TCP segmentation offload.
    pub tcp_tso: bool,
    /// UDP checksum calculation.
    pub udp_cksum: bool,
    /// UDP segmentation offload.
    pub udp_tso: bool,
    /// VLAN tag insertion.
    pub vlan_insert: bool,
    /// VXLAN tunnel segmentation offload.
    pub vxlan_tnl_tso: bool,
    /// Any flags that are not known to map to a valid offload.
    pub unknown: u64,
}

impl TxOffloadConfig {
    /// Request no transmit offloads.
    #[must_use]
    pub const fn none() -> Self {
        TxOffloadConfig {
            geneve_tnl_tso: false,
            gre_tnl_tso: false,
            ipip_tnl_tso: false,
            ipv4_cksum: false,
            macsec_insert: false,
            outer_ipv4_cksum: false,
            qinq_insert: false,
            sctp_cksum: false,
            tcp_cksum: false,
            tcp_tso: false,
            udp_cksum: false,
            udp_tso: false,
            vlan_insert: false,
            vxlan_tnl_tso: false,
            unknown: 0,
        }
    }

    /// Request every transmit offload this type can name.
    #[must_use]
    pub const fn all() -> Self {
        TxOffloadConfig {
            geneve_tnl_tso: true,
            gre_tnl_tso: true,
            ipip_tnl_tso: true,
            ipv4_cksum: true,
            macsec_insert: true,
            outer_ipv4_cksum: true,
            qinq_insert: true,
            sctp_cksum: true,
            tcp_cksum: true,
            tcp_tso: true,
            udp_cksum: true,
            udp_tso: true,
            vlan_insert: true,
            vxlan_tnl_tso: true,
            unknown: 0,
        }
    }
}

impl Display for TxOffloadConfig {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl From<TxOffloadConfig> for TxOffload {
    fn from(value: TxOffloadConfig) -> Self {
        use dpdk_sys::rte_eth_tx_offload::*;
        TxOffload(
            if value.geneve_tnl_tso {
                TX_OFFLOAD_GENEVE_TNL_TSO
            } else {
                0
            } | if value.gre_tnl_tso {
                TX_OFFLOAD_GRE_TNL_TSO
            } else {
                0
            } | if value.ipip_tnl_tso {
                TX_OFFLOAD_IPIP_TNL_TSO
            } else {
                0
            } | if value.ipv4_cksum {
                TX_OFFLOAD_IPV4_CKSUM
            } else {
                0
            } | if value.macsec_insert {
                TX_OFFLOAD_MACSEC_INSERT
            } else {
                0
            } | if value.outer_ipv4_cksum {
                TX_OFFLOAD_OUTER_IPV4_CKSUM
            } else {
                0
            } | if value.qinq_insert {
                TX_OFFLOAD_QINQ_INSERT
            } else {
                0
            } | if value.sctp_cksum {
                TX_OFFLOAD_SCTP_CKSUM
            } else {
                0
            } | if value.tcp_cksum {
                TX_OFFLOAD_TCP_CKSUM
            } else {
                0
            } | if value.tcp_tso { TX_OFFLOAD_TCP_TSO } else { 0 }
                | if value.udp_cksum {
                    TX_OFFLOAD_UDP_CKSUM
                } else {
                    0
                }
                | if value.udp_tso { TX_OFFLOAD_UDP_TSO } else { 0 }
                | if value.vlan_insert {
                    TX_OFFLOAD_VLAN_INSERT
                } else {
                    0
                }
                | if value.vxlan_tnl_tso {
                    TX_OFFLOAD_VXLAN_TNL_TSO
                } else {
                    0
                }
                | value.unknown,
        )
    }
}

impl From<TxOffload> for TxOffloadConfig {
    fn from(value: TxOffload) -> Self {
        use dpdk_sys::rte_eth_tx_offload::*;
        TxOffloadConfig {
            geneve_tnl_tso: value.0 & TX_OFFLOAD_GENEVE_TNL_TSO != 0,
            gre_tnl_tso: value.0 & TX_OFFLOAD_GRE_TNL_TSO != 0,
            ipip_tnl_tso: value.0 & TX_OFFLOAD_IPIP_TNL_TSO != 0,
            ipv4_cksum: value.0 & TX_OFFLOAD_IPV4_CKSUM != 0,
            macsec_insert: value.0 & TX_OFFLOAD_MACSEC_INSERT != 0,
            outer_ipv4_cksum: value.0 & TX_OFFLOAD_OUTER_IPV4_CKSUM != 0,
            qinq_insert: value.0 & TX_OFFLOAD_QINQ_INSERT != 0,
            sctp_cksum: value.0 & TX_OFFLOAD_SCTP_CKSUM != 0,
            tcp_cksum: value.0 & TX_OFFLOAD_TCP_CKSUM != 0,
            tcp_tso: value.0 & TX_OFFLOAD_TCP_TSO != 0,
            udp_cksum: value.0 & TX_OFFLOAD_UDP_CKSUM != 0,
            udp_tso: value.0 & TX_OFFLOAD_UDP_TSO != 0,
            vlan_insert: value.0 & TX_OFFLOAD_VLAN_INSERT != 0,
            vxlan_tnl_tso: value.0 & TX_OFFLOAD_VXLAN_TNL_TSO != 0,
            unknown: value.0 & !TxOffload::ALL_KNOWN.0,
        }
    }
}

impl TxOffload {
    /// No transmit offloads.
    pub const NONE: TxOffload = TxOffload(0);

    /// GENEVE tunnel segmentation offload.
    pub const GENEVE_TNL_TSO: TxOffload = TxOffload(rte_eth_tx_offload::TX_OFFLOAD_GENEVE_TNL_TSO);
    /// GRE tunnel segmentation offload.
    pub const GRE_TNL_TSO: TxOffload = TxOffload(rte_eth_tx_offload::TX_OFFLOAD_GRE_TNL_TSO);
    /// IPIP tunnel segmentation offload.
    pub const IPIP_TNL_TSO: TxOffload = TxOffload(rte_eth_tx_offload::TX_OFFLOAD_IPIP_TNL_TSO);
    /// IPv4 checksum calculation.
    pub const IPV4_CKSUM: TxOffload = TxOffload(rte_eth_tx_offload::TX_OFFLOAD_IPV4_CKSUM);
    /// MACsec insertion.
    pub const MACSEC_INSERT: TxOffload = TxOffload(rte_eth_tx_offload::TX_OFFLOAD_MACSEC_INSERT);
    /// Outer IPv4 checksum calculation.
    pub const OUTER_IPV4_CKSUM: TxOffload =
        TxOffload(rte_eth_tx_offload::TX_OFFLOAD_OUTER_IPV4_CKSUM);
    /// QinQ (double VLAN) insertion.
    pub const QINQ_INSERT: TxOffload = TxOffload(rte_eth_tx_offload::TX_OFFLOAD_QINQ_INSERT);
    /// SCTP checksum calculation.
    pub const SCTP_CKSUM: TxOffload = TxOffload(rte_eth_tx_offload::TX_OFFLOAD_SCTP_CKSUM);
    /// TCP checksum calculation.
    pub const TCP_CKSUM: TxOffload = TxOffload(rte_eth_tx_offload::TX_OFFLOAD_TCP_CKSUM);
    /// TCP segmentation offload.
    pub const TCP_TSO: TxOffload = TxOffload(rte_eth_tx_offload::TX_OFFLOAD_TCP_TSO);
    /// UDP checksum calculation.
    pub const UDP_CKSUM: TxOffload = TxOffload(rte_eth_tx_offload::TX_OFFLOAD_UDP_CKSUM);
    /// UDP segmentation offload.
    pub const UDP_TSO: TxOffload = TxOffload(rte_eth_tx_offload::TX_OFFLOAD_UDP_TSO);
    /// VXLAN tunnel segmentation offload.
    pub const VXLAN_TNL_TSO: TxOffload = TxOffload(rte_eth_tx_offload::TX_OFFLOAD_VXLAN_TNL_TSO);
    /// VLAN tag insertion.
    pub const VLAN_INSERT: TxOffload = TxOffload(rte_eth_tx_offload::TX_OFFLOAD_VLAN_INSERT);

    /// Union of all [`TxOffload`]s documented at the time of writing.
    pub const ALL_KNOWN: TxOffload = {
        use rte_eth_tx_offload::*;
        TxOffload(
            TX_OFFLOAD_GENEVE_TNL_TSO
                | TX_OFFLOAD_GRE_TNL_TSO
                | TX_OFFLOAD_IPIP_TNL_TSO
                | TX_OFFLOAD_IPV4_CKSUM
                | TX_OFFLOAD_MACSEC_INSERT
                | TX_OFFLOAD_OUTER_IPV4_CKSUM
                | TX_OFFLOAD_QINQ_INSERT
                | TX_OFFLOAD_SCTP_CKSUM
                | TX_OFFLOAD_TCP_CKSUM
                | TX_OFFLOAD_TCP_TSO
                | TX_OFFLOAD_UDP_CKSUM
                | TX_OFFLOAD_UDP_TSO
                | TX_OFFLOAD_VLAN_INSERT
                | TX_OFFLOAD_VXLAN_TNL_TSO,
        )
    };
}

impl RxOffload {
    /// No receive offloads.
    pub const NONE: RxOffload = RxOffload(0);

    /// Deliver the NIC's computed RSS hash in each mbuf's `hash.rss` field.
    ///
    /// Without this the hardware still steers by the hash but never reports it, so software cannot
    /// see which flows the NIC believes it is spreading -- which is the first thing anyone wants
    /// when RSS distributes badly.
    ///
    /// `rte_eth_dev_configure` rejects this offload unless the receive mq-mode has the RSS flag
    /// set, so it is only legal alongside a [`DevConfig::rss`].
    ///
    /// Note that an `rte_flow` MARK or FDIR action overwrites the same union in the mbuf, so a
    /// rule carrying one makes the hash unreadable -- the reason `flow_api_probe` sees
    /// `rss_hash=None`.
    pub const RSS_HASH: RxOffload = RxOffload(RTE_ETH_RX_OFFLOAD_RSS_HASH as u64);
}

impl BitOr for TxOffload {
    type Output = Self;

    fn bitor(self, rhs: Self) -> TxOffload {
        TxOffload(self.0 | rhs.0)
    }
}

impl BitAnd for TxOffload {
    type Output = Self;

    fn bitand(self, rhs: Self) -> TxOffload {
        TxOffload(self.0 & rhs.0)
    }
}

impl BitXor for TxOffload {
    type Output = Self;

    fn bitxor(self, rhs: Self) -> TxOffload {
        TxOffload(self.0 ^ rhs.0)
    }
}

impl BitOrAssign for TxOffload {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl BitAndAssign for TxOffload {
    fn bitand_assign(&mut self, rhs: Self) {
        self.0 &= rhs.0;
    }
}

impl BitXorAssign for TxOffload {
    fn bitxor_assign(&mut self, rhs: Self) {
        self.0 ^= rhs.0;
    }
}

/// Information about a DPDK ethernet device.
///
/// This struct is a wrapper around the `rte_eth_dev_info` struct from DPDK.
///
/// It borrows the EAL it came from, as does any device configured from it:
///
/// ```compile_fail,E0505
/// # use dataplane_dpdk::eal::Eal;
/// fn info_outlives_eal(eal: Eal) {
///     let info = eal.dev.iter().next().expect("a port");
///     drop(eal);
///     let _ = info.index();
/// }
/// ```
#[derive(Debug)]
pub struct DevInfo<'eal> {
    pub(crate) index: DevIndex,
    pub(crate) inner: rte_eth_dev_info,
    pub(crate) eal: PhantomData<&'eal ()>,
}

unsafe impl Send for DevInfo<'_> {}
unsafe impl Sync for DevInfo<'_> {}

#[derive(Debug)]
struct DevIterator<'eal> {
    cursor: DevIndex,
    /// Ties each yielded [`DevInfo`] to the EAL lifetime.
    eal: PhantomData<&'eal ()>,
}

impl<'eal> Iterator for DevIterator<'eal> {
    type Item = DevInfo<'eal>;

    fn next(&mut self) -> Option<DevInfo<'eal>> {
        let cursor = self.cursor;

        debug!("Checking port {cursor}");

        let port_id =
            unsafe { rte_eth_find_next_owned_by(cursor.as_u16(), u64::from(RTE_ETH_DEV_NO_OWNER)) };

        // This is the normal exit condition after we've found all the devices.
        if port_id >= u64::from(RTE_MAX_ETHPORTS) {
            return None;
        }

        let port = DevIndex(port_id as u16);
        self.cursor = DevIndex(port.0 + 1);

        match port.info() {
            Ok(info) => Some(info),
            Err(err) => {
                // At this point I'm ok with this being a fatal error, but in the future
                // we will likely need to deal with more dynamic ports.
                let err_msg = format!("Failed to get device info for port {port}: {err}");
                error!("{err_msg}");
                Eal::fatal_error(err_msg);
            }
        }
    }
}

/// Manager of DPDK ethernet devices.
#[non_exhaustive]
#[repr(transparent)]
#[derive(Debug)]
pub struct Manager;

impl Drop for Manager {
    fn drop(&mut self) {
        debug!("Closing DPDK ethernet device manager");
    }
}

impl Manager {
    /// Initialize the DPDK device manager.
    ///
    /// <div class="warning">
    ///
    /// * This method should only be called once per [`Eal`] lifetime.
    ///
    /// * The return value should only _ever_ be stored in the [`Eal`] singleton.
    ///
    /// </div>
    pub(crate) fn init() -> Manager {
        Manager
    }

    /// Iterate over all available DPDK ethernet devices and return information about each one.
    #[tracing::instrument(level = "trace")]
    pub fn iter(&self) -> impl Iterator<Item = DevInfo<'_>> {
        DevIterator {
            cursor: DevIndex(0),
            eal: PhantomData,
        }
    }

    /// Get information about an ethernet device.
    ///
    /// # Arguments
    ///
    /// * `index`: the index of the device to get information about.
    ///
    /// # Errors
    ///
    /// This function will return an [`DevInfoError`] if the device information could not be
    /// retrieved.
    ///
    /// # Safety
    ///
    /// This function should never panic assuming DPDK is correctly implemented.
    #[tracing::instrument(level = "trace", ret)]
    pub fn info(&self, index: DevIndex) -> Result<DevInfo<'_>, DevInfoError> {
        index.info()
    }

    /// Returns the number of ethernet devices available to the EAL.
    ///
    /// Safe wrapper around [`rte_eth_dev_count_avail`]
    #[tracing::instrument(level = "trace", ret)]
    pub fn num_devices(&self) -> u16 {
        unsafe { rte_eth_dev_count_avail() }
    }
}

impl DevInfo<'_> {
    /// Get the port index of the device.
    #[must_use]
    pub fn index(&self) -> DevIndex {
        self.index
    }

    /// Get the device `if_index`.
    ///
    /// This is the Linux interface index of the device.
    #[must_use]
    pub fn if_index(&self) -> u32 {
        self.inner.if_index
    }

    /// The ethdev name assigned by the PMD.
    ///
    /// Often a PCI address, but PMDs may add port or representor suffixes.
    /// Virtual and SoC devices use other naming schemes.
    ///
    /// # Errors
    ///
    /// Returns the DPDK error for an invalid port, or `EINVAL` for a non-UTF-8 name.
    #[tracing::instrument(level = "trace", skip(self))]
    pub fn name(&self) -> Result<String, ErrorCode> {
        let mut buf = [0 as core::ffi::c_char; dpdk_sys::RTE_ETH_NAME_MAX_LEN as usize];
        let ret = unsafe {
            dpdk_sys::rte_eth_dev_get_name_by_port(self.index.as_u16(), buf.as_mut_ptr())
        };
        if ret != 0 {
            return Err(ErrorCode::parse_i32(ret));
        }
        // SAFETY: on success DPDK has written a NUL-terminated string of at most
        // `RTE_ETH_NAME_MAX_LEN` bytes into `buf`, which is exactly that long.
        let name = unsafe { CStr::from_ptr(buf.as_ptr()) };
        name.to_str()
            .map(ToString::to_string)
            .map_err(|_| ErrorCode::parse_i32(errno::NEG_EINVAL))
    }

    #[allow(clippy::expect_used)]
    #[tracing::instrument(level = "debug")]
    /// Get the driver name of the device.
    ///
    /// # Panics
    ///
    /// This function will panic if the driver name is not valid utf-8.
    pub fn driver_name(&self) -> &str {
        unsafe { CStr::from_ptr(self.inner.driver_name) }
            .to_str()
            .expect("driver name is not valid utf-8")
    }

    #[tracing::instrument(level = "trace")]
    /// Get the maximum set of available tx offloads supported by the device.
    pub fn tx_offload_caps(&self) -> TxOffload {
        self.inner.tx_offload_capa.into()
    }

    #[tracing::instrument(level = "trace")]
    /// Get the maximum set of available rx offloads supported by the device.
    pub fn rx_offload_caps(&self) -> RxOffload {
        self.inner.rx_offload_capa.into()
    }

    #[tracing::instrument(level = "trace")]
    /// RX offloads allowed in queue configuration.
    /// Port-wide capabilities may include offloads that cannot be set per queue.
    pub fn rx_queue_offload_caps(&self) -> RxOffload {
        self.inner.rx_queue_offload_capa.into()
    }

    #[tracing::instrument(level = "trace")]
    /// TX offloads allowed in queue configuration.
    /// See [`DevInfo::rx_queue_offload_caps`].
    pub fn tx_queue_offload_caps(&self) -> TxOffload {
        self.inner.tx_queue_offload_capa.into()
    }

    /// Whether the device advertises RSS support.
    #[must_use]
    pub fn supports_rss(&self) -> bool {
        self.inner.flow_type_rss_offloads != 0
    }

    /// The set of `RTE_ETH_RSS_*` hash types the device advertises.
    ///
    /// `rte_eth_dev_configure` rejects any `rss_hf` that is not a subset of this, so a caller
    /// building an [`RssConf`] by hand must intersect against it.  [`RssConf::supported_on`] does
    /// that.
    #[must_use]
    pub fn rss_hash_types(&self) -> u64 {
        self.inner.flow_type_rss_offloads
    }

    /// The exact RSS key length, in bytes, the device requires.
    ///
    /// `rte_eth_dev_configure` rejects a key of any other length -- not a shorter one, not a
    /// longer one.  mlx5 reports 40; other drivers differ (i40e wants 52).
    #[must_use]
    pub fn rss_hash_key_size(&self) -> u8 {
        self.inner.hash_key_size
    }
}

/// Runtime device state used by the port teardown guard.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Stage {
    /// Configured and never started. Queues may be set up.
    Configured,
    /// Running. Packets flow; the queue set is fixed.
    Started,
    /// Stopped; queries and close are allowed, but restart is not.
    Stopped,
    /// Closed; no further port operations are allowed.
    Closed,
}

/// Sealed device states: [`Configured`], [`Started`], [`Stopped`], and [`Closed`].
pub trait DevState: dev_state::Sealed + Debug {
    /// The runtime state used to select the required teardown operations.
    const STAGE: Stage;
}

/// States with an open port: [`Configured`], [`Started`], and [`Stopped`].
pub trait Open: DevState {}

/// States that can be closed: [`Configured`] and [`Stopped`].
pub trait Inactive: Open {}

mod dev_state {
    /// Restricts [`super::DevState`] to this module's states.
    pub trait Sealed {}
    impl Sealed for super::Configured {}
    impl Sealed for super::Started {}
    impl Sealed for super::Stopped {}
    impl Sealed for super::Closed {}
}

/// A configured device whose queues can be set up before start.
#[derive(Debug)]
pub struct Configured;

/// A running device whose queues can receive and transmit.
#[derive(Debug)]
pub struct Started;

/// A stopped device. Queries and close are supported; restart and queue setup are not.
///
/// ```compile_fail,E0599
/// # use dataplane_dpdk::dev::{Dev, Stopped};
/// fn restart(dev: Dev<Stopped>) { let _ = dev.start(); }
/// ```
///
/// ```compile_fail,E0599
/// # use dataplane_dpdk::dev::{Dev, Stopped};
/// # use dataplane_dpdk::queue::tx::TxQueueConfig;
/// fn add_queue(mut dev: Dev<Stopped>, config: TxQueueConfig) { let _ = dev.new_tx_queue(config); }
/// ```
#[derive(Debug)]
pub struct Stopped;

/// A closed device whose port resources have been released. No port operations remain.
///
/// ```compile_fail,E0599
/// # use dataplane_dpdk::dev::{Dev, Closed};
/// fn restart(dev: Dev<Closed>) { let _ = dev.start(); }
/// ```
///
/// ```compile_fail,E0599
/// # use dataplane_dpdk::dev::{Dev, Closed};
/// fn stop_again(dev: Dev<Closed>) { let _ = dev.stop(); }
/// ```
///
/// ```compile_fail,E0599
/// # use dataplane_dpdk::dev::{Dev, Closed};
/// fn query(dev: Dev<Closed>) { let _ = dev.mac_address(); }
/// ```
#[derive(Debug)]
pub struct Closed;

impl DevState for Configured {
    const STAGE: Stage = Stage::Configured;
}
impl DevState for Started {
    const STAGE: Stage = Stage::Started;
}
impl DevState for Stopped {
    const STAGE: Stage = Stage::Stopped;
}
impl DevState for Closed {
    const STAGE: Stage = Stage::Closed;
}

impl Open for Configured {}
impl Open for Started {}
impl Open for Stopped {}

impl Inactive for Configured {}
impl Inactive for Stopped {}

/// Stops and closes the port on drop, allowing `Dev` fields to move between states.
#[derive(Debug)]
struct PortLifecycle<'eal> {
    port: DevIndex,
    stage: Stage,
    /// Owns the RSS key whose address DPDK retains.
    config: DevConfig,
    /// Retains failed-close records after DPDK releases the port ID.
    owner: &'eal Ownership,
}

impl PortLifecycle<'_> {
    fn leak_rss_key(&mut self) {
        // Failed teardown may leave native references to this allocation.
        if let Some(key) = self.config.rss.as_mut().and_then(|rss| rss.key.take()) {
            core::mem::forget(key);
        }
    }

    fn close(&mut self) -> Result<(), DevCloseError> {
        // Disarm the guard: even a failed close may release the port ID.
        self.stage = Stage::Closed;
        let ret = unsafe { rte_eth_dev_close(self.port.as_u16()) };
        if ret != 0 {
            // Preserve the failure after DPDK removes the port from the owner table.
            self.owner.record_teardown_failure();
            self.leak_rss_key();
            return Err(DevCloseError {
                port: self.port,
                error: ErrorCode::parse_i32(ret),
            });
        }
        info!("Device {port} closed", port = self.port);
        Ok(())
    }
}

impl Drop for PortLifecycle<'_> {
    /// Stop and close the port, logging errors. Explicit transitions return errors to the caller.
    fn drop(&mut self) {
        if self.stage == Stage::Closed {
            return;
        }
        if self.stage == Stage::Started {
            info!("Stopping DPDK ethernet device {port}", port = self.port);
            let ret = unsafe { rte_eth_dev_stop(self.port.as_u16()) };
            if ret != 0 {
                self.leak_rss_key();
                error!(
                    "Failed to stop device {port} on drop, error code: {ret}",
                    port = self.port,
                );
                // DPDK requires the port to stop successfully before close.
                return;
            }
        }
        if let Err(error) = self.close() {
            error!(%error, "Device teardown failed");
        }
    }
}

#[derive(Debug)]
/// A DPDK Ethernet device with a lifecycle [`DevState`].
///
/// [`DevConfig::apply`] creates a [`Configured`] device.
/// [`start`][Dev::<Configured>::start], [`stop`][Dev::<Started>::stop], and [`close`][Dev::close]
/// transition it to [`Started`], [`Stopped`], and [`Closed`], respectively.
///
/// Dropping a device stops and closes its port.
/// EAL teardown also attempts to close ports left open by leaked devices before releasing mempools.
///
/// # Thread affinity
///
/// A device is `!Send` but `Sync`: configuration and teardown stay on the [`Eal`] thread.
/// This serializes close with port queries, which read driver state without locking.
/// Other threads can borrow the device to query it or take its queues; the borrow prevents close.
///
/// ```compile_fail,E0277
/// # use dataplane_dpdk::dev::{Dev, Started};
/// fn assert_send<T: Send>() {}
/// assert_send::<Dev<'static, Started>>();
/// ```
///
/// ```
/// # use dataplane_dpdk::dev::{Dev, Started};
/// fn assert_sync<T: Sync>() {}
/// assert_sync::<Dev<'static, Started>>();
/// ```
pub struct Dev<'eal, S: DevState = Configured> {
    /// Owns the configuration and closes the port before releasing it.
    lifecycle: PortLifecycle<'eal>,
    /// Port identity; callers cannot replace it.
    pub(crate) info: DevInfo<'eal>,
    /// Queues owned until handoff, then borrowed from the device.
    /// The mutex permits sharing Dev while transferring each queue exactly once.
    queues: Mutex<Option<QueueStore<'eal>>>,
    state: PhantomData<S>,
    /// Keeps the device on the EAL thread; see "Thread affinity".
    _thread: PhantomData<EalThreadBound>,
}

/// Keeps a value on the EAL thread while allowing shared references (`!Send + Sync`).
#[derive(Debug)]
struct EalThreadBound(PhantomData<*const ()>);

// SAFETY: the marker holds no data, so sharing a reference to it shares nothing.
unsafe impl Sync for EalThreadBound {}

impl<'eal, S: DevState> Dev<'eal, S> {
    /// Information about the underlying port.
    #[must_use]
    pub fn info(&self) -> &DevInfo<'eal> {
        &self.info
    }

    /// The applied configuration. Its RSS key stays owned by this device.
    #[must_use]
    pub fn config(&self) -> &DevConfig {
        &self.lifecycle.config
    }

    /// Move device fields and update the teardown guard to the new state.
    fn transition<T: DevState>(mut self) -> Dev<'eal, T> {
        self.lifecycle.stage = T::STAGE;
        Dev {
            lifecycle: self.lifecycle,
            info: self.info,
            queues: self.queues,
            state: PhantomData,
            _thread: PhantomData,
        }
    }
}

impl<'eal, S: Open> Dev<'eal, S> {
    /// The device's primary source MAC address.
    ///
    /// Returns an error if the driver fails or reports a zero or multicast address.
    #[tracing::instrument(level = "trace", skip(self))]
    pub fn mac_address(&self) -> Result<net::eth::mac::SourceMac, MacAddressError> {
        let mut addr: rte_ether_addr = unsafe { core::mem::zeroed() };
        let ret = unsafe { rte_eth_macaddr_get(self.info.index().as_u16(), &raw mut addr) };
        if ret == 0 {
            Ok(net::eth::mac::SourceMac::new(net::eth::mac::Mac(
                addr.addr_bytes,
            ))?)
        } else {
            Err(MacAddressError::Driver(ErrorCode::parse_i32(ret)))
        }
    }

    /// Read the port's current MTU, for example to configure its control-plane tap.
    ///
    /// # Errors
    ///
    /// Returns the driver's [`ErrorCode`] if the MTU could not be read.
    #[tracing::instrument(level = "trace", skip(self))]
    pub fn mtu(&self) -> Result<u16, ErrorCode> {
        let mut mtu: u16 = 0;
        let ret =
            unsafe { dpdk_sys::rte_eth_dev_get_mtu(self.info.index().as_u16(), &raw mut mtu) };
        if ret == 0 {
            Ok(mtu)
        } else {
            Err(ErrorCode::parse_i32(ret))
        }
    }

    /// Enable or disable promiscuous mode.
    ///
    /// # Errors
    ///
    /// Returns the driver's error, including `ENOTSUP` when unsupported.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn set_promiscuous(&mut self, enable: bool) -> Result<(), ErrorCode> {
        let port = self.info.index().as_u16();
        let ret = if enable {
            unsafe { rte_eth_promiscuous_enable(port) }
        } else {
            unsafe { rte_eth_promiscuous_disable(port) }
        };
        if ret == 0 {
            debug!(
                "Promiscuous mode {state} on port {port}",
                state = if enable { "enabled" } else { "disabled" }
            );
            Ok(())
        } else {
            Err(ErrorCode::parse_i32(ret))
        }
    }
}

impl<'eal> Dev<'eal, Configured> {
    /// Access the queue store before start.
    ///
    /// # Panics
    ///
    /// Panics if the store was taken, which Configured prevents.
    #[allow(clippy::expect_used)]
    fn with_store<R>(&mut self, f: impl FnOnce(&mut QueueStore<'eal>) -> R) -> R {
        let mut guard = self.queues.lock();
        let store = guard
            .as_mut()
            .expect("a configured device cannot have had its queues taken");
        f(store)
    }

    /// Configure a receive queue, available through [`Queues::take_rx`] after start.
    pub fn new_rx_queue(&mut self, config: RxQueueConfig<'eal>) -> Result<(), rx::ConfigFailure> {
        // Two handles to one queue would let two threads poll it at once.
        self.with_store(|store| store.check_rx(config.queue_index))?;
        let rx_queue = RxQueue::setup(self, config)?;
        self.with_store(|store| store.insert_rx(rx_queue));
        Ok(())
    }

    /// Configure a transmit queue, available through [`Queues::take_tx`] after start.
    pub fn new_tx_queue(&mut self, config: TxQueueConfig) -> Result<(), tx::ConfigFailure> {
        self.with_store(|store| store.check_tx(config.queue_index))?;
        let tx_queue = TxQueue::setup(self, config)?;
        self.with_store(|store| store.insert_tx(tx_queue));
        Ok(())
    }

    /// Configure a hairpin queue and return its ID for [`Queues::take_hairpin`] after start.
    pub fn new_hairpin_queue(
        &mut self,
        rx: RxQueueConfig<'eal>,
        tx: TxQueueConfig,
    ) -> Result<HairpinQueueId, HairpinConfigFailure> {
        self.with_store(|store| store.check_rx(rx.queue_index))
            .map_err(HairpinConfigFailure::RxQueueCreationFailed)?;
        self.with_store(|store| store.check_tx(tx.queue_index))
            .map_err(HairpinConfigFailure::TxQueueCreationFailed)?;
        let rx = RxQueue::setup(self, rx).map_err(HairpinConfigFailure::RxQueueCreationFailed)?;
        let tx = TxQueue::setup(self, tx).map_err(HairpinConfigFailure::TxQueueCreationFailed)?;
        let hairpin = HairpinQueue::new(self, rx, tx)?;
        Ok(self.with_store(|store| store.insert_hairpin(hairpin)))
    }

    /// Start the device.
    ///
    /// # Errors
    ///
    /// Returns [`DevStartFailure`] with the still-configured device for retry or disposal.
    #[allow(clippy::result_large_err)] // Preserve device ownership on failure.
    pub fn start(self) -> Result<Dev<'eal, Started>, DevStartFailure<'eal>> {
        let ret = unsafe { rte_eth_dev_start(self.info.index().as_u16()) };
        if ret != 0 {
            error!(
                "Failed to start port {port}, error code: {ret}",
                port = self.info.index(),
            );
            return Err(DevStartFailure {
                error: ErrorCode::parse_i32(ret),
                dev: self,
            });
        }
        info!("Device {port} started", port = self.info.index());
        Ok(self.transition())
    }
}

impl<'eal, S: Inactive> Dev<'eal, S> {
    /// Close the port and transition to [`Closed`].
    ///
    /// Consumes the device even on error. DPDK releases the port despite a driver error,
    /// so retrying could close a different device that reused its ID.
    /// On error, retain the RSS key and mempools because the driver may still reference them.
    ///
    /// ```compile_fail,E0599
    /// # use dataplane_dpdk::dev::{Dev, Started};
    /// fn close_running(dev: Dev<Started>) { let _ = dev.close(); }
    /// ```
    pub fn close(mut self) -> Result<Dev<'eal, Closed>, DevCloseError> {
        self.lifecycle.close()?;
        Ok(self.transition())
    }
}

impl<'eal> Dev<'eal, Started> {
    /// Stop the device.
    ///
    /// # Errors
    ///
    /// Returns [`DevStopFailure`] with the still-running device.
    #[allow(clippy::result_large_err)] // Preserve device ownership on failure.
    pub fn stop(self) -> Result<Dev<'eal, Stopped>, DevStopFailure<'eal>> {
        let ret = unsafe { rte_eth_dev_stop(self.info.index().as_u16()) };
        if ret != 0 {
            error!(
                "Failed to stop port {port}, error code: {ret}",
                port = self.info.index(),
            );
            return Err(DevStopFailure {
                error: ErrorCode::parse_i32(ret),
                dev: self,
            });
        }
        info!("Device {port} stopped", port = self.info.index());
        Ok(self.transition())
    }

    /// Take the queues once, returning `None` on subsequent calls.
    /// The handles borrow this device and require exclusive access for polling.
    ///
    /// ```compile_fail,E0505
    /// # use dataplane_dpdk::dev::{Dev, Started};
    /// # use dataplane_dpdk::queue::rx::RxQueueIndex;
    /// fn use_after_stop(dev: Dev<Started>) {
    ///     let mut queues = dev.take_queues().expect("queues");
    ///     let mut rxq = queues.take_rx(RxQueueIndex(0)).expect("rx 0");
    ///     let _stopped = dev.stop();
    ///     let _burst = rxq.receive();
    /// }
    /// ```
    ///
    /// ```compile_fail,E0596
    /// # use dataplane_dpdk::queue::rx::RxQueue;
    /// fn poll_shared(rxq: &RxQueue<'_>) {
    ///     let _burst = rxq.receive();
    /// }
    /// ```
    pub fn take_queues(&self) -> Option<Queues<'_>> {
        let store = self.queues.lock().take()?;
        // Queue lifetimes shorten from the EAL borrow to this device borrow.
        Some(Queues::new(store))
    }
}

/// A start error and the still-configured device.
#[derive(Debug, thiserror::Error)]
#[error("failed to start device {}: {error}", self.dev.info.index())]
pub struct DevStartFailure<'eal> {
    /// The error that caused the start to fail.
    #[source]
    pub error: ErrorCode,
    /// The device, still in its [`Configured`] state.
    pub dev: Dev<'eal, Configured>,
}

/// A stop error and the still-running device.
#[derive(Debug, thiserror::Error)]
#[error("failed to stop device {}: {error}", self.dev.info.index())]
pub struct DevStopFailure<'eal> {
    /// The error that caused the stop to fail.
    #[source]
    pub error: ErrorCode,
    /// The device, still in its [`Started`] state.
    pub dev: Dev<'eal, Started>,
}

/// A close error. The device is consumed and cannot be retried.
///
/// DPDK has released the port regardless, and the driver may still reference mbufs, so the EAL
/// will not free its mempools at teardown.
#[derive(Debug, thiserror::Error)]
#[error("failed to close device {port}: {error}")]
pub struct DevCloseError {
    /// The port ID at the time of the close attempt; it may since have been reused.
    pub port: DevIndex,
    /// The error that caused the close to fail.
    #[source]
    pub error: ErrorCode,
}

#[derive(Debug, thiserror::Error)]
pub enum SocketIdLookupError {
    #[error("Invalid port ID")]
    DevDoesNotExist(DevIndex),
    #[error("Unknown error code set")]
    UnknownErrno(ErrorCode),
}

#[cfg(test)]
mod rss_conf_tests {
    use super::*;

    /// mlx5's `flow_type_rss_offloads`: `~MLX5_RSS_HF_MASK` from `mlx5_defs.h`.
    ///
    /// The `L3_SRC_ONLY`/`L3_DST_ONLY`/`L4_*_ONLY` modifier bits mlx5 also advertises are left out.
    /// They only narrow a hash type that is already selected, so they cannot change the
    /// intersection under test -- and `RTE_ETH_RSS_L3_SRC_ONLY` is `RTE_BIT64(63)`, which bindgen
    /// does not emit into `dpdk-sys` at all (`RTE_ETH_RSS_L3_DST_ONLY`, one bit lower, comes
    /// through fine). That gap is real but belongs to `dpdk-sys`, not here.
    const MLX5_RSS_OFFLOADS: u64 = (RTE_ETH_RSS_IP as u64)
        | (RTE_ETH_RSS_UDP as u64)
        | (RTE_ETH_RSS_TCP as u64)
        | (RTE_ETH_RSS_ESP as u64);

    /// The key length `rte_eth_dev_configure` demands must match what mlx5 reports
    /// (`MLX5_RSS_HASH_KEY_LEN`). A key of any other length is rejected outright, so this is not a
    /// style preference.
    #[test]
    fn the_default_key_is_the_length_mlx5_requires() {
        assert_eq!(RssConf::DEFAULT_KEY.len(), 40);
    }

    /// On mlx5 every hash type this crate asks for is supported, so the intersection must not
    /// silently narrow. If it does, flows stop spreading by L4 port and every connection between
    /// one pair of hosts collapses onto a single worker.
    #[test]
    fn mlx5_supports_every_hash_type_we_ask_for() {
        let conf = RssConf::from_hash_types(MLX5_RSS_OFFLOADS).expect("mlx5 supports RSS");
        assert_eq!(conf.hf, RssConf::DEFAULT_HASH_TYPES);
        assert_eq!(conf.key, None);

        // Named individually rather than left to the equality above, which compares the
        // intersection against the wish list and so would still hold if the wish list itself were
        // narrowed. These are the bits whose loss is operationally visible: without L4, every
        // connection between one pair of hosts hashes alike and lands on a single worker.
        for (bit, what) in [
            (RTE_ETH_RSS_IP as u64, "L3 addresses"),
            (RTE_ETH_RSS_TCP as u64, "TCP ports"),
            (RTE_ETH_RSS_UDP as u64, "UDP ports"),
        ] {
            assert_ne!(conf.hf & bit, 0, "RSS on mlx5 would not hash over {what}");
        }
    }

    /// A device that hashes on L3 but not L4 must still get an RSS configuration -- just a
    /// narrower one. Erroring instead would refuse to spread traffic at all on a device that can
    /// perfectly well spread it by address.
    #[test]
    fn an_l3_only_device_gets_a_narrowed_configuration() {
        let conf = RssConf::from_hash_types(RTE_ETH_RSS_IP as u64).expect("L3 hashing is enough");
        assert_eq!(conf.hf, RTE_ETH_RSS_IP as u64);
        assert_eq!(conf.hf & RTE_ETH_RSS_TCP as u64, 0);
    }

    /// The emulated NICs (e1000, e1000e, virtio without multi-queue negotiation) report no hash
    /// functions at all. Handing such a device an RSS configuration makes `rte_eth_dev_configure`
    /// fail outright, so this case must produce `None` rather than an empty-but-present config.
    #[test]
    fn a_device_that_cannot_hash_gets_no_configuration() {
        assert_eq!(RssConf::from_hash_types(0), None);
    }

    /// A device advertising only hash types we do not ask for is the same case: the intersection
    /// is empty, and an `rss_hf` of zero under `RTE_ETH_MQ_RX_RSS` would configure a hash over
    /// nothing, sending every packet to queue 0 while looking configured.
    #[test]
    fn an_empty_intersection_is_not_a_configuration() {
        assert_eq!(RssConf::from_hash_types(RTE_ETH_RSS_ESP as u64), None);
    }

    /// The standard Toeplitz key is deliberately **not** symmetric, and this test exists to say so
    /// where someone would otherwise "fix" it.
    ///
    /// A key of period two (`0x6d5a` repeated) would make `H(src, dst) == H(dst, src)`. That is
    /// not wanted here: mlx5 aside, a NAT'd flow's reverse packet carries the translated tuple
    /// rather than the reversed one, so symmetry would buy nothing while measurably worsening the
    /// hash's distribution. See the note on [`RssConf`].
    #[test]
    fn the_default_key_is_not_symmetric() {
        let (pairs, _) = RssConf::DEFAULT_KEY.as_chunks::<2>();
        let symmetric = pairs.iter().all(|pair| pair == &pairs[0]);
        assert!(
            !symmetric,
            "the default RSS key has become period-2 (symmetric); \
             see the RssConf docs for why that is not the fix it looks like"
        );
    }
}
