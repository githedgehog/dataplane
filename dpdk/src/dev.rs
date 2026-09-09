// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Ethernet device management.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::ffi::{CStr, c_uint};
use core::fmt::{Debug, Display, Formatter};
use core::marker::PhantomData;
use core::ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign};
use tracing::{debug, error, info};

use crate::eal::Eal;
use crate::queue;
use crate::queue::hairpin::{HairpinConfigFailure, HairpinQueue};
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
pub(crate) use claim::OwnerId;
pub use claim::{ClaimError, ForeignOwner, PortClaim, PortOwner};

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

    /// Get information about an ethernet device.
    ///
    /// # Arguments
    ///
    /// * `index`: the index of the device to get information about.
    ///
    /// # Errors
    ///
    /// This function will return a [`DevInfoError`] if the device information could not be
    /// retrieved.
    ///
    /// # Safety
    ///
    /// This function should never panic assuming DPDK is correctly implemented.
    /// Crate-private, and returns an unbranded `DevInfo<'static>`.
    ///
    /// A `DevIndex` is a bare `u16` with nothing to derive an EAL brand from, so this cannot
    /// produce one honestly. The public routes ([`Manager::info`], [`Manager::iter`]) take
    /// `&'eal self` and shorten the result, which is a safe covariant coercion -- and being
    /// crate-private is what stops external code reaching the unbranded form and manufacturing a
    /// `Dev<'static, _>`.
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

/// RSS parameters applied before receive queues are created.
/// mlx5 requires this order to deliver RSS hashes in mbufs.
#[derive(Debug, PartialEq, Clone, Eq, PartialOrd, Ord, Hash)]
pub struct RssConf {
    /// The Toeplitz RSS key. `None` keeps the driver's own default; `Some` must be exactly the
    /// device's `hash_key_size` bytes (40 on mlx5, 52 on ice and i40e).
    pub key: Option<Vec<u8>>,
    /// The set of `RTE_ETH_RSS_*` hash types to hash over (e.g. `RTE_ETH_RSS_IPV4`).
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

/// How to configure a device: queue counts, offloads, MTU and RSS.
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
    /// RSS hashing configuration applied at configure time.  `None` leaves RSS hashing off
    /// (`rss_hf = 0`), so the NIC computes no hash and reports none in the mbuf.
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
    /// The requested RSS key is not the length the device requires.
    ///
    /// `rte_eth_dev_configure` rejects a key whose length is not exactly the device's
    /// `hash_key_size`, so this is checked here to report which device wanted what.
    #[error("RSS key is {requested} bytes; the device requires {device}")]
    RssKeyLenMismatch {
        /// The length of the key that was supplied.
        requested: usize,
        /// The key length the device requires.
        device: u8,
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

    /// Apply the configuration to a claimed port.
    ///
    /// # Errors
    ///
    /// Returns [`DevConfigFailure`], which hands the claim back, if the configuration is invalid
    /// for the device or the driver rejects it.
    ///
    /// # Note on the lifetime
    ///
    /// `'eal` is derived from the claim, never chosen by the caller. An unconstrained `'eal` would
    /// let a caller name `'static` and manufacture a `Dev<'static, _>` out of nothing, which would
    /// make the brand -- and every guarantee resting on it -- vacuous. A [`PortClaim`] carries the
    /// brand because it can only be obtained from the [`Eal`].
    // The error hands the claim back; this large result is used only during setup.
    #[allow(clippy::result_large_err)]
    pub fn apply<'eal>(
        &self,
        port: PortClaim<'eal>,
    ) -> Result<Dev<'eal, Configured>, DevConfigFailure<'eal>> {
        if let Err(error) = self.configure(port.info()) {
            return Err(DevConfigFailure { error, claim: port });
        }
        let dev = port.into_info();
        Ok(Dev {
            lifecycle: PortLifecycle {
                port: dev.index(),
                stage: Stage::Configured,
            },
            info: dev,
            config: self.clone(),
            queues: Mutex::new(Some(QueueStore::default())),
            state: PhantomData,
        })
    }

    /// Configure `dev`'s port with `rte_eth_dev_configure`.
    fn configure(&self, dev: &DevInfo<'_>) -> Result<(), DevConfigError> {
        let mtu = self.resolve_mtu(dev)?;
        // Reject an RSS request the device cannot honor rather than silently dropping it, for the
        // same reason `resolve_mtu` rejects an out-of-range MTU: a misconfiguration that only
        // shows up as traffic landing on the wrong queue is far harder to diagnose than an error
        // at configure time.
        if let Some(rss) = &self.rss {
            if !dev.supports_rss() {
                return Err(DevConfigError::RssUnsupported);
            }
            // Both of these are checks `rte_eth_dev_configure` performs itself, but it reports
            // them as a bare `-EINVAL` that surfaces here as `DriverSpecificError("Invalid
            // argument")` with no indication of which of a dozen fields was wrong.  Checking them
            // up front is the difference between a one-line fix and an afternoon.
            if let Some(key) = &rss.key
                && key.len() != dev.rss_hash_key_size() as usize
            {
                return Err(DevConfigError::RssKeyLenMismatch {
                    requested: key.len(),
                    device: dev.rss_hash_key_size(),
                });
            }
            if rss.hf & !dev.rss_hash_types() != 0 {
                return Err(DevConfigError::RssHashTypesUnsupported {
                    requested: rss.hf,
                    supported: dev.rss_hash_types(),
                });
            }
        }
        // Keep the RSS key alive until rte_eth_dev_configure copies it.
        let mut rss_key_buf: Option<Vec<u8>> = self.rss.as_ref().and_then(|rss| rss.key.clone());
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

        if let Some(rss) = &self.rss {
            let mut rss_conf: rte_eth_rss_conf = unsafe { core::mem::zeroed() };
            // A null key asks the driver to keep its own default.
            if let Some(key) = rss_key_buf.as_mut() {
                rss_conf.rss_key = key.as_mut_ptr();
                // Checked above to equal the device's `u8` `hash_key_size`.
                #[allow(clippy::cast_possible_truncation)]
                let len = key.len() as u8;
                rss_conf.rss_key_len = len;
            }
            rss_conf.rss_hf = rss.hf;
            eth_conf.rx_adv_conf.rss_conf = rss_conf;
        }

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
        Ok(())
    }
}

/// A configuration error and the still-unused claim, so the caller can fix the configuration and
/// retry without losing the port.
#[derive(Debug, thiserror::Error)]
#[error("failed to configure port {}: {error}", self.claim.info().index())]
pub struct DevConfigFailure<'eal> {
    /// What was wrong.
    #[source]
    pub error: DevConfigError,
    /// The claim, still held.
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
    /// Carries the brand so the yielded [`DevInfo`]s have one; see [`DevIndex::info`].
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

        // For whatever reason, DPDK can't decide if port_id is `u16` or `u64`.
        self.cursor = DevIndex(port_id as u16 + 1);

        match cursor.info() {
            Ok(info) => Some(info),
            Err(err) => {
                // At this point I'm ok with this being a fatal error, but in the future
                // we will likely need to deal with more dynamic ports.
                let err_msg = format!("Failed to get device info for port {cursor}: {err}");
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

    /// The device's name, as DPDK's bus layer knows it.
    ///
    /// For a PCI device this is its extended BDF address (`0000:02:00.1`), whatever kernel driver
    /// the device is bound to and whether or not it has one. That makes it the only stable identity
    /// a port has: [`if_index`](Self::if_index) is 0 for a device bound to `vfio-pci`, because such
    /// a device has no netdev, and the port index is just the order the EAL happened to probe in.
    ///
    /// Not always a PCI address -- DPDK also names SoC devices (`fsl-gmac0`) and virtual ones
    /// (`net_tap0`) through the same call -- so callers matching against configuration should parse
    /// rather than assume.
    ///
    /// # Errors
    ///
    /// Returns the driver's [`ErrorCode`] if the port index is not valid, or `EINVAL` if the name
    /// DPDK returns is not UTF-8.
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

/// The lifecycle stage of a port, as a runtime value.
///
/// This is the term-level mirror of the [`DevState`] typestate. It exists because [`Drop`] cannot
/// be specialized per typestate: the guard that actually stops and closes the port
/// (`PortLifecycle`) is not generic, so it records the stage it is responsible for.
///
/// Each stage is named after the DPDK call that produced it: `rte_eth_dev_configure`, `_start`,
/// `_stop`, `_close`.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Stage {
    /// Configured and never started. Queues may be set up.
    Configured,
    /// Running. Packets flow; the queue set is fixed.
    Started,
    /// Stopped after running. It can be queried and closed; restarting is not supported yet.
    Stopped,
    /// Closed. All port resources have been released and the port cannot be restarted.
    Closed,
}

/// Sealed device states: [`Configured`], [`Started`], [`Stopped`], and [`Closed`].
pub trait DevState: dev_state::Sealed + Debug {
    /// The [`Stage`] this typestate denotes, recorded in `PortLifecycle` on every transition so
    /// that the non-generic `Drop` knows what teardown the port still owes.
    const STAGE: Stage;
}

/// Sealed marker trait for the typestates in which the port's resources still exist, and so can
/// still be queried: [`Configured`], [`Started`], and [`Stopped`], but not [`Closed`].
///
/// `rte_eth_dev_close` "frees all port resources", so a port operation on a [`Closed`] device is a
/// use-after-free in the PMD. Bounding those methods on `Open` rather than [`DevState`] makes that
/// a compile error instead.
pub trait Open: DevState {}

/// Sealed marker trait for the typestates that are not running and so can be closed:
/// [`Configured`] and [`Stopped`].
pub trait Inactive: Open {}

mod dev_state {
    /// Sealed-trait support for [`super::DevState`]; external crates cannot add new typestates.
    pub trait Sealed {}
    impl Sealed for super::Configured {}
    impl Sealed for super::Started {}
    impl Sealed for super::Stopped {}
    impl Sealed for super::Closed {}
}

/// Typestate marker: the device is configured and has never been started. Queues are set up here.
#[derive(Debug)]
pub struct Configured;

/// Typestate marker: the device is running.  It can receive and transmit; its queue set is fixed.
#[derive(Debug)]
pub struct Started;

/// Typestate marker: the device ran and has been stopped. It can still be queried -- this is the
/// moment to read final port counters -- and closed.
///
/// Its queue handles were handed to workers and are gone, so it cannot be given queues or started
/// again; restarting is future work, not a silent no-op:
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

/// Typestate marker: the device has been closed and all of its port resources released.
///
/// This is a terminal state. Per [`rte_eth_dev_close`]'s contract the device "cannot be
/// restarted", so there is no transition out of it -- a [`Dev<Closed>`] can only be dropped.
///
/// A closed device cannot be restarted:
///
/// ```compile_fail,E0599
/// # use dataplane_dpdk::dev::{Dev, Closed};
/// fn restart(dev: Dev<Closed>) { let _ = dev.start(); }
/// ```
///
/// nor stopped again:
///
/// ```compile_fail,E0599
/// # use dataplane_dpdk::dev::{Dev, Closed};
/// fn stop_again(dev: Dev<Closed>) { let _ = dev.stop(); }
/// ```
///
/// and its port resources are gone, so it cannot be queried -- [`Closed`] is the one typestate
/// that does not implement [`Open`]:
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

/// The stop-and-close obligation for a port, as an owned value.
///
/// Holding the teardown here rather than in a `Drop` on [`Dev`] itself is what lets `Dev` move
/// between typestates safely: a type that implements `Drop` cannot have its fields moved out, so
/// with the `Drop` on `Dev` every transition needed a `ManuallyDrop` plus a `ptr::read` per field.
/// With the obligation isolated in this guard, `Dev` implements no `Drop` of its own and
/// [`Dev::transition`] is an ordinary move.
#[derive(Debug)]
struct PortLifecycle {
    port: DevIndex,
    stage: Stage,
}

impl Drop for PortLifecycle {
    /// Stop the port if it is running, then close it, releasing its resources.
    ///
    /// This is a backstop, not the intended path: [`Dev::stop`] and [`Dev::close`] return the
    /// driver's error, whereas here it can only be logged. It runs regardless, because Rust cannot
    /// forbid dropping a value -- without it, a device dropped without an explicit `close` would
    /// leak its queue rings and leave the port unusable for the rest of the process.
    fn drop(&mut self) {
        if self.stage == Stage::Closed {
            return;
        }
        if self.stage == Stage::Started {
            info!("Stopping DPDK ethernet device {port}", port = self.port);
            let ret = unsafe { rte_eth_dev_stop(self.port.as_u16()) };
            if ret != 0 {
                error!(
                    "Failed to stop device {port} on drop, error code: {ret}",
                    port = self.port,
                );
                // Closing an un-stopped port is not valid; there is nothing further to try.
                return;
            }
        }
        info!("Closing DPDK ethernet device {port}", port = self.port);
        let ret = unsafe { rte_eth_dev_close(self.port.as_u16()) };
        if ret != 0 {
            error!(
                "Failed to close device {port} on drop, error code: {ret}",
                port = self.port,
            );
        }
    }
}

#[derive(Debug)]
/// A DPDK ethernet device, parameterized by its lifecycle [`DevState`].
///
/// A freshly [`applied`][DevConfig::apply] device is [`Configured`] (the default);
/// [`start`][Dev::<Configured>::start] makes it [`Started`], [`stop`][Dev::<Started>::stop] makes it
/// [`Stopped`], and [`close`][Dev::close] makes it [`Closed`]. Each state is named after the DPDK
/// call that produced it.
pub struct Dev<'eal, S: DevState = Configured> {
    /// Owns the port's stop/close obligation -- the only field here with a `Drop` that does
    /// anything to the device.
    ///
    /// Declared first, so it also happens to drop first, but that ordering is *not* load-bearing
    /// and this type deliberately has no `Drop` of its own to enforce it. `Dev` implementing `Drop` is exactly
    /// what would forbid moving its fields out, which is what makes [`transition`](Self::transition)
    /// an ordinary safe move instead of a `ManuallyDrop` plus a `ptr::read` per field.
    ///
    /// It is not load-bearing because no other field has a teardown effect on DPDK state. `info`
    /// and `config` are plain data, and the [`Pool`](crate::mem::Pool) handle in each queue's
    /// config is a handle that owns nothing; mempools are freed only at EAL teardown. If
    /// pools were ever reclaimed earlier, the ordering here would become real and this type would
    /// need the obligation restructured (most likely by having `PortLifecycle` own the queue
    /// store) rather than a `Drop` bolted on.
    lifecycle: PortLifecycle,
    /// The device info. Private: every port operation reads its index from here, so replacing it
    /// would aim them at another port.
    pub(crate) info: DevInfo<'eal>,
    /// The configuration the device was applied with.
    pub(crate) config: DevConfig,
    /// The device's queues, until they are taken for distribution to workers.
    ///
    /// Stored with a `'static` brand and handed out shortened to the borrow of the device.  The
    /// brand is covariant, so that shortening is an ordinary safe coercion; it is only the other
    /// direction that would be unsound.
    ///
    /// Behind a `Mutex` rather than a `Cell` so that `Dev` stays `Sync`: a queue handle is branded
    /// with `&Dev`, so making the device `!Sync` would make every handle `!Send` and no worker
    /// thread could be given one.  The lock is taken at queue setup and once at hand-off, never on
    /// the datapath.
    queues: Mutex<Option<QueueStore<'eal>>>,
    state: PhantomData<S>,
}

impl<'eal, S: DevState> Dev<'eal, S> {
    /// Information about the underlying port.
    #[must_use]
    pub fn info(&self) -> &DevInfo<'eal> {
        &self.info
    }

    /// The configuration the device was applied with.
    #[must_use]
    pub fn config(&self) -> &DevConfig {
        &self.config
    }

    /// Move all owned device state into a `Dev` of a different typestate.
    ///
    /// `Dev` deliberately implements no `Drop` of its own -- the teardown lives in the
    /// [`PortLifecycle`] field -- so this is an ordinary move of every field, with no `unsafe`.
    /// Updating `lifecycle.stage` is what keeps the guard's view of the port in step with the
    /// typestate.
    fn transition<T: DevState>(mut self) -> Dev<'eal, T> {
        self.lifecycle.stage = T::STAGE;
        Dev {
            lifecycle: self.lifecycle,
            info: self.info,
            config: self.config,
            queues: self.queues,
            state: PhantomData,
        }
    }
}

/// What a port's link is doing, as returned by [`Dev::link`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkStatus {
    /// Carrier is present.
    pub up: bool,
    /// Negotiated speed in Mbit/s. `u32::MAX` is DPDK's "unknown".
    pub speed_mbps: u32,
    /// Full duplex rather than half.
    pub full_duplex: bool,
    /// The speed was autonegotiated rather than fixed.
    pub autoneg: bool,
}

impl core::fmt::Display for LinkStatus {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if !self.up {
            return write!(f, "down");
        }
        if self.speed_mbps == u32::MAX {
            return write!(f, "up at an unknown speed");
        }
        write!(
            f,
            "up at {} Mbit/s {}",
            self.speed_mbps,
            if self.full_duplex {
                "full duplex"
            } else {
                "half duplex"
            }
        )
    }
}

/// A port's I/O counters, as returned by [`Dev::stats`].
///
/// A plain owned snapshot rather than a borrow of DPDK's `rte_eth_stats`: the counters are read by
/// value at a point in time, and copying eight `u64`s is cheaper than reasoning about when the
/// driver may rewrite them.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct PortStats {
    /// Packets successfully received.
    pub ipackets: u64,
    /// Packets successfully transmitted.
    pub opackets: u64,
    /// Bytes successfully received.
    pub ibytes: u64,
    /// Bytes successfully transmitted.
    pub obytes: u64,
    /// Packets dropped by the hardware because no receive descriptor was free.
    ///
    /// This is the counter for "the port had it and the application was not keeping up".
    pub imissed: u64,
    /// Erroneous packets received.
    pub ierrors: u64,
    /// Packets that failed to transmit.
    pub oerrors: u64,
    /// Receive mbuf allocation failures.
    ///
    /// Non-zero means the receive mempool ran dry: the PMD could not refill a descriptor, so the
    /// port dropped traffic it had otherwise accepted. Distinct from [`imissed`](Self::imissed),
    /// which is the application being too slow rather than the pool being too small.
    pub rx_nombuf: u64,
}

impl<'eal, S: Open> Dev<'eal, S> {
    /// The device's primary MAC address, as the PMD reports it.
    ///
    /// # Errors
    ///
    /// Returns the driver's [`ErrorCode`] if the address could not be read.
    #[tracing::instrument(level = "trace", skip(self))]
    pub fn mac_address(&self) -> Result<net::eth::mac::Mac, ErrorCode> {
        let mut addr: rte_ether_addr = unsafe { core::mem::zeroed() };
        let ret = unsafe { rte_eth_macaddr_get(self.info.index().as_u16(), &raw mut addr) };
        if ret == 0 {
            Ok(net::eth::mac::Mac(addr.addr_bytes))
        } else {
            Err(ErrorCode::parse_i32(ret))
        }
    }

    /// The device's current MTU, as the PMD reports it.
    ///
    /// This is the number the port is actually running with, not the one that was requested:
    /// [`DevConfig::apply`] clamps a configured MTU into the device's advertised
    /// `[min_mtu, max_mtu]` range, so asking the device is the only way to learn what it settled
    /// on. That matters to anything which has to agree with the port about frame size -- notably
    /// the control-plane tap that stands in for this port in the kernel.
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

    /// The device's I/O statistics, as the PMD reports them.
    ///
    /// These are the counters that separate "the wire lost it" from "we lost it", and there is no
    /// other way to tell those apart: the kernel's `ethtool -S` sees only its own queues, so on a
    /// bifurcated driver such as mlx5 it reports a frame delivered to the port while saying nothing
    /// about whether any DPDK queue received it. [`PortStats::imissed`] and
    /// [`PortStats::rx_nombuf`] are where a frame that reached the port and never reached a
    /// Whether the port has carrier, and at what speed.
    ///
    /// Worth having because a port with no link is otherwise **invisible**: DPDK will configure a
    /// device, set up every queue and report it started with the link down, and the datapath then
    /// runs perfectly while carrying nothing. Nothing in the driver is wrong in that state, so
    /// nothing in the driver complains.
    ///
    /// For a bifurcated device this most often means the kernel netdev is administratively down --
    /// `mlx5_core` keeps the netdev, and the physical port follows its state. Moving an interface
    /// between network namespaces clears `IFF_UP`, which is exactly how a port ends up here.
    ///
    /// The `_nowait` form deliberately: this is for reporting, and the blocking variant can sit for
    /// up to nine seconds per port waiting for autonegotiation.
    ///
    /// # Errors
    ///
    /// Returns the driver's [`ErrorCode`]; a PMD without link support reports `ENOTSUP`.
    #[tracing::instrument(level = "trace", skip(self))]
    pub fn link(&self) -> Result<LinkStatus, ErrorCode> {
        let mut raw: dpdk_sys::rte_eth_link = unsafe { core::mem::zeroed() };
        // SAFETY: `raw` is live for the call and the port index comes from a started device.
        let ret =
            unsafe { dpdk_sys::rte_eth_link_get_nowait(self.info.index().as_u16(), &raw mut raw) };
        if ret != 0 {
            return Err(ErrorCode::parse_i32(ret));
        }
        // SAFETY: the union's struct arm is the documented way to read the fields; the `val64` arm
        // exists only so the PMD can write the whole thing atomically.
        let inner = unsafe { raw.annon1.annon1 };
        Ok(LinkStatus {
            up: u32::from(inner.link_status()) == dpdk_sys::RTE_ETH_LINK_UP,
            speed_mbps: inner.link_speed,
            full_duplex: u32::from(inner.link_duplex()) == dpdk_sys::RTE_ETH_LINK_FULL_DUPLEX,
            autoneg: inner.link_autoneg() != 0,
        })
    }

    /// receive burst is accounted for.
    ///
    /// # Errors
    ///
    /// Returns the driver's [`ErrorCode`] if the counters could not be read; PMDs that do not
    /// implement statistics report `ENOTSUP`.
    #[tracing::instrument(level = "trace", skip(self))]
    pub fn stats(&self) -> Result<PortStats, ErrorCode> {
        let mut raw: dpdk_sys::rte_eth_stats = unsafe { core::mem::zeroed() };
        let ret = unsafe { dpdk_sys::rte_eth_stats_get(self.info.index().as_u16(), &raw mut raw) };
        if ret != 0 {
            return Err(ErrorCode::parse_i32(ret));
        }
        Ok(PortStats {
            ipackets: raw.ipackets,
            opackets: raw.opackets,
            ibytes: raw.ibytes,
            obytes: raw.obytes,
            imissed: raw.imissed,
            ierrors: raw.ierrors,
            oerrors: raw.oerrors,
            rx_nombuf: raw.rx_nombuf,
        })
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
    /// Run `f` against the queue store.
    ///
    /// Deliberately closure-based rather than returning a mapped guard: `MutexGuard::map` exists
    /// only on `concurrency`'s parking_lot backend, and the std and loom backends wrap the guard in
    /// their own newtype without it. Using it here would build on the default backend and break
    /// under `--features loom`.
    ///
    /// # Panics
    ///
    /// Panics if the queues have already been taken. Unreachable: taking them requires a
    /// [`Dev<Started>`], and this is only callable on a [`Dev<Configured>`], which cannot have been
    /// started yet.
    #[allow(clippy::expect_used)]
    fn with_store<R>(&mut self, f: impl FnOnce(&mut QueueStore<'eal>) -> R) -> R {
        let mut guard = self.queues.lock();
        let store = guard
            .as_mut()
            .expect("a stopped device cannot have had its queues taken");
        f(store)
    }

    // TODO: return type should provide a handle back to the queue
    /// Configure a new [`RxQueue`]
    pub fn new_rx_queue(&mut self, config: RxQueueConfig<'eal>) -> Result<(), rx::ConfigFailure> {
        // Two handles to one queue would let two threads poll it at once.
        if self.with_store(|store| store.has_rx(config.queue_index)) {
            return Err(rx::ConfigFailure::AlreadyConfigured(config.queue_index));
        }
        let rx_queue = RxQueue::setup(self, config)?;
        self.with_store(|store| store.rx.push(rx_queue));
        Ok(())
    }

    // TODO: return type should provide a handle back to the queue
    /// Configure a new [`TxQueue`]
    pub fn new_tx_queue(&mut self, config: TxQueueConfig) -> Result<(), tx::ConfigFailure> {
        if self.with_store(|store| store.has_tx(config.queue_index)) {
            return Err(tx::ConfigFailure::AlreadyConfigured(config.queue_index));
        }
        let tx_queue = TxQueue::setup(self, config)?;
        self.with_store(|store| store.tx.push(tx_queue));
        Ok(())
    }

    // TODO: return type should provide a handle back to the queue
    /// Configure a new [`HairpinQueue`]
    pub fn new_hairpin_queue(
        &mut self,
        rx: RxQueueConfig<'eal>,
        tx: TxQueueConfig,
    ) -> Result<(), HairpinConfigFailure> {
        if self.with_store(|store| store.has_rx(rx.queue_index)) {
            return Err(HairpinConfigFailure::RxQueueCreationFailed(
                rx::ConfigFailure::AlreadyConfigured(rx.queue_index),
            ));
        }
        if self.with_store(|store| store.has_tx(tx.queue_index)) {
            return Err(HairpinConfigFailure::TxQueueCreationFailed(
                tx::ConfigFailure::AlreadyConfigured(tx.queue_index),
            ));
        }
        let rx = RxQueue::setup(self, rx).map_err(HairpinConfigFailure::RxQueueCreationFailed)?;
        let tx = TxQueue::setup(self, tx).map_err(HairpinConfigFailure::TxQueueCreationFailed)?;
        let hairpin = HairpinQueue::new(self, rx, tx)?;
        self.with_store(|store| store.hairpin.push(hairpin));
        Ok(())
    }

    /// Start the device.
    ///
    /// # Errors
    ///
    /// Returns [`DevStartFailure`] with the stopped device for retry or disposal.
    // The error owns the device; this large result is used only during setup.
    #[allow(clippy::result_large_err)]
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
    /// Close the device, releasing all of its port resources, and transition it to the terminal
    /// [`Closed`] state.
    ///
    /// Only a stopped device can be closed, which is why this lives here and not on
    /// [`Dev<Started>`]; and per [`rte_eth_dev_close`]'s contract the port "cannot be restarted"
    /// afterwards, so [`Closed`] has no transition out of it.
    ///
    /// Closing is what returns the mbufs still held in the device's queue rings to their
    /// [`Pool`](crate::mem::Pool), so it must happen before those pools are released at EAL
    /// teardown. Dropping the device closes it too; prefer this when you want to observe the
    /// error.
    ///
    /// A running device has no `close`; it must be stopped first:
    ///
    /// ```compile_fail,E0599
    /// # use dataplane_dpdk::dev::{Dev, Started};
    /// fn close_running(dev: Dev<Started>) { let _ = dev.close(); }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns a [`DevCloseFailure`] -- which hands the device back unchanged -- if the
    /// device could not be closed.
    // See the note on `start`: the `Result` is large by design and this is a cold path.
    #[allow(clippy::result_large_err)]
    pub fn close(self) -> Result<Dev<'eal, Closed>, DevCloseFailure<'eal, S>> {
        let ret = unsafe { rte_eth_dev_close(self.info.index().as_u16()) };
        if ret != 0 {
            error!(
                "Failed to close port {port}, error code: {ret}",
                port = self.info.index(),
            );
            return Err(DevCloseFailure {
                error: ErrorCode::parse_i32(ret),
                dev: self,
            });
        }
        info!("Device {port} closed", port = self.info.index());
        Ok(self.transition())
    }
}

impl<'eal> Dev<'eal, Started> {
    /// Stop the device.
    ///
    /// # Errors
    ///
    /// Returns [`DevStopFailure`] with the still-running device.
    // The error owns the device; this large result is used only during teardown.
    #[allow(clippy::result_large_err)]
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

    /// Take the device's queues, for distribution to the workers that will drive them.
    ///
    /// Returns `None` if they have already been taken -- the set is handed out exactly once. That
    /// is the point: DPDK requires one queue to be driven by one thread, so a queue handed to two
    /// callers would be a data race no amount of care downstream could fix. Handing the set out
    /// once, and each queue out of it by value, makes that rule a property of the type system.
    ///
    /// The returned [`Queues`] borrows the device, so no queue can outlive it -- and since
    /// [`stop`](Self::stop) consumes the device by value, using a queue after the device stops does
    /// not compile:
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
    /// Nor can a queue be polled through a shared reference, since `rte_eth_rx_burst` is not safe
    /// to call concurrently for one queue:
    ///
    /// ```compile_fail,E0596
    /// # use dataplane_dpdk::queue::rx::RxQueue;
    /// fn poll_shared(rxq: &RxQueue<'_>) {
    ///     let _burst = rxq.receive();
    /// }
    /// ```
    pub fn take_queues(&self) -> Option<Queues<'_>> {
        let store = self.queues.lock().take()?;
        // `RxQueue<'static>` shortens to `RxQueue<'_>` by covariance -- a safe coercion.
        Some(Queues::new(store.rx, store.tx, store.hairpin))
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

/// Returned when [`Dev::close`] fails.
///
/// Carries the error and the device, returned in the state it was closed from so the caller can
/// retry or drop it.
#[derive(Debug, thiserror::Error)]
#[error("failed to close device {}: {error}", self.dev.info.index())]
pub struct DevCloseFailure<'eal, S: Inactive = Configured> {
    /// The error that caused the close to fail.
    #[source]
    pub error: ErrorCode,
    /// The device, unchanged.
    pub dev: Dev<'eal, S>,
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
