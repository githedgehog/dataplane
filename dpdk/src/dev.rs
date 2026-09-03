// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Ethernet device management.

use alloc::format;
use alloc::vec::Vec;
use core::ffi::{CStr, c_uint};
use core::fmt::{Debug, Display, Formatter};
use core::marker::PhantomData;
use core::mem::ManuallyDrop;
use core::ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign};
use tracing::{debug, error, info};

use crate::eal::Eal;
use crate::queue;
use crate::queue::hairpin::{HairpinConfigFailure, HairpinQueue};
use crate::queue::rx::{RxQueue, RxQueueConfig, RxQueueIndex};
use crate::queue::tx::{TxQueue, TxQueueConfig, TxQueueIndex};
use crate::socket::SocketId;
use dpdk_sys::rte_eth_rx_mq_mode::{RTE_ETH_MQ_RX_NONE, RTE_ETH_MQ_RX_RSS};
use dpdk_sys::rte_eth_tx_mq_mode::RTE_ETH_MQ_TX_NONE;
use dpdk_sys::*;
use errno::{Errno, ErrorCode, StandardErrno};
use queue::{rx, tx};

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
    #[tracing::instrument(level = "trace", ret)]
    pub fn info(&self) -> Result<DevInfo, DevInfoError> {
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
#[derive(Debug, PartialEq, Copy, Clone, Eq, PartialOrd, Ord, Hash)]
pub struct RssConf {
    /// The Toeplitz RSS key.  mlx5 expects exactly 40 bytes (its `hash_key_size`).
    pub key: [u8; 40],
    /// The set of `RTE_ETH_RSS_*` hash types to hash over (e.g. `RTE_ETH_RSS_IPV4`).
    pub hf: u64,
}

#[derive(Debug, PartialEq, Copy, Clone, Eq, PartialOrd, Ord, Hash)]
/// TODO: add `rx_offloads` support
pub struct DevConfig {
    // /// Information about the device.
    // pub info: DevInfo<'info>,
    /// The number of receive queues to be made available after device initialization.
    pub num_rx_queues: u16,
    /// The number of transmit queues to be made available after device initialization.
    pub num_tx_queues: u16,
    /// The number of hairpin queues to be made available after device initialization.
    pub num_hairpin_queues: u16,
    /// The transmit offloads to be requested on the device.
    ///
    /// If `None`, the device will use all supported Offloads.
    /// If `Some`, the device will use the intersection of the supported offloads and the requested
    /// offloads.
    /// TODO: this is a silly API.
    /// Setting it to `None` should disable all offloads, but instead we default to enabling all
    /// supported.
    /// Rework this bad idea.
    pub tx_offloads: Option<TxOffloadConfig>,
    // TODO: more reasonable type for [`RxOffload`] here (similar to [`TxOffloadConfig`])
    pub rx_offloads: Option<RxOffload>,
    /// Requested MTU. `None` uses [`DEFAULT_MTU`] clamped to device limits;
    /// an explicit value outside those limits returns [`DevConfigError::MtuOutOfRange`].
    pub mtu: Option<u16>,
    /// RSS hashing configuration applied at configure time.  `None` leaves RSS hashing off
    /// (`rss_hf = 0`), so the NIC computes no hash and reports none in the mbuf.
    pub rss: Option<RssConf>,
}

#[derive(Debug)]
/// Errors that can occur when configuring a DPDK ethernet device.
pub enum DevConfigError {
    /// A driver-specific error occurred when configuring the ethernet device.
    DriverSpecificError(&'static str),
    /// The requested MTU is outside the device's advertised `[min, max]` range.
    MtuOutOfRange {
        /// The MTU that was requested.
        requested: u16,
        /// The device's minimum supported MTU.
        min: u16,
        /// The device's maximum supported MTU.
        max: u16,
    },
    /// RSS hashing was requested but the device advertises no RSS hash functions.
    RssUnsupported,
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

    /// Apply the configuration to the device.
    pub fn apply(&self, dev: DevInfo) -> Result<Dev, DevConfigError> {
        const ANY_SUPPORTED: u64 = u64::MAX;
        let mtu = self.resolve_mtu(&dev)?;
        if self.rss.is_some() && !dev.supports_rss() {
            return Err(DevConfigError::RssUnsupported);
        }
        // Keep the RSS key alive until rte_eth_dev_configure copies it.
        let mut rss_key_buf: [u8; 40];
        let mut eth_conf = rte_eth_conf {
            txmode: rte_eth_txmode {
                mq_mode: RTE_ETH_MQ_TX_NONE,
                offloads: {
                    let requested = self
                        .tx_offloads
                        .map_or(TxOffload(ANY_SUPPORTED), TxOffload::from);
                    let supported = dev.tx_offload_caps();
                    (requested & supported).0
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
                offloads: {
                    let requested = self.rx_offloads.unwrap_or(RxOffload(ANY_SUPPORTED));
                    let supported = dev.rx_offload_caps();
                    requested.0 & supported.0
                },
                ..Default::default()
            },
            ..Default::default()
        };

        if let Some(rss) = self.rss {
            rss_key_buf = rss.key;
            let mut rss_conf: rte_eth_rss_conf = unsafe { core::mem::zeroed() };
            rss_conf.rss_key = rss_key_buf.as_mut_ptr();
            rss_conf.rss_key_len = rss_key_buf.len() as u8;
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

            // NOTE: it is not clear from the docs if `ret` is going to be a valid errno value.
            // I am assuming it is for now.
            // TODO: see if we can determine if `ret` is a valid errno value.
            let rte_error = unsafe { CStr::from_ptr(rte_strerror(ret)) }
                .to_str()
                .unwrap_or("Unknown error");
            return Err(DevConfigError::DriverSpecificError(rte_error));
        }
        Ok(Dev {
            info: dev,
            config: *self,
            rx_queues: Vec::with_capacity(self.num_rx_queues as usize),
            tx_queues: Vec::with_capacity(self.num_tx_queues as usize),
            hairpin_queues: Vec::with_capacity(self.num_hairpin_queues as usize),
            state: PhantomData,
        })
    }
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

impl Default for TxOffloadConfig {
    /// Defaults to enabling all known offloads
    fn default() -> Self {
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
    /// Disable TX offloads. `DevConfig::tx_offloads = None` enables all supported offloads.
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
    /// Disable RX offloads. `DevConfig::rx_offloads = None` enables all supported offloads.
    pub const NONE: RxOffload = RxOffload(0);
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
pub struct DevInfo {
    pub(crate) index: DevIndex,
    pub(crate) inner: rte_eth_dev_info,
}

unsafe impl Send for DevInfo {}
unsafe impl Sync for DevInfo {}

#[repr(transparent)]
#[derive(Debug)]
struct DevIterator {
    cursor: DevIndex,
}

impl DevIterator {}

impl Iterator for DevIterator {
    type Item = DevInfo;

    fn next(&mut self) -> Option<DevInfo> {
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
    pub fn iter(&self) -> impl Iterator<Item = DevInfo> {
        DevIterator {
            cursor: DevIndex(0),
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
    pub fn info(&self, index: DevIndex) -> Result<DevInfo, DevInfoError> {
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

impl DevInfo {
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

    /// The largest MTU the device advertises support for, or `0` if it advertises no range.
    #[must_use]
    pub fn max_mtu(&self) -> u16 {
        self.inner.max_mtu
    }

    /// The smallest MTU the device advertises support for.
    #[must_use]
    pub fn min_mtu(&self) -> u16 {
        self.inner.min_mtu
    }

    /// Whether the device advertises RSS support.
    #[must_use]
    pub fn supports_rss(&self) -> bool {
        self.inner.flow_type_rss_offloads != 0
    }
}

/// Sealed device states: [`Stopped`] and [`Started`].
pub trait DevState: dev_state::Sealed {
    /// Whether Drop must stop the device.
    const RUNNING: bool;
}

mod dev_state {
    /// Sealed-trait support for [`super::DevState`]; external crates cannot add new typestates.
    pub trait Sealed {}
    impl Sealed for super::Stopped {}
    impl Sealed for super::Started {}
}

/// A configured device whose queues can be changed before starting.
#[derive(Debug)]
pub struct Stopped;

/// Typestate marker: the device is running.  It can receive and transmit; its queue set is fixed.
#[derive(Debug)]
pub struct Started;

impl DevState for Stopped {
    const RUNNING: bool = false;
}
impl DevState for Started {
    const RUNNING: bool = true;
}

#[derive(Debug)]
/// A DPDK ethernet device, parameterized by its lifecycle [`DevState`].
///
/// A freshly [`applied`][DevConfig::apply] device is [`Stopped`] (the default); call
/// [`start`][Dev::<Stopped>::start] to transition it to [`Started`] and back with
/// [`stop`][Dev::<Started>::stop].
pub struct Dev<S: DevState = Stopped> {
    /// The device info
    pub info: DevInfo,
    /// The configuration of the device.
    pub config: DevConfig,
    pub(crate) rx_queues: Vec<RxQueue>,
    pub(crate) tx_queues: Vec<TxQueue>,
    pub(crate) hairpin_queues: Vec<HairpinQueue>,
    state: PhantomData<S>,
}

impl<S: DevState> Dev<S> {
    /// Move device state without running Drop on the source.
    fn transition<T: DevState>(self) -> Dev<T> {
        let this = ManuallyDrop::new(self);
        // SAFETY: ManuallyDrop prevents teardown; each field is moved exactly once.
        unsafe {
            Dev {
                info: core::ptr::read(&this.info),
                config: core::ptr::read(&this.config),
                rx_queues: core::ptr::read(&this.rx_queues),
                tx_queues: core::ptr::read(&this.tx_queues),
                hairpin_queues: core::ptr::read(&this.hairpin_queues),
                state: PhantomData,
            }
        }
    }
}

impl<S: DevState> Dev<S> {
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

impl Dev<Stopped> {
    // TODO: return type should provide a handle back to the queue
    /// Configure a new [`RxQueue`]
    pub fn new_rx_queue(&mut self, config: RxQueueConfig) -> Result<(), rx::ConfigFailure> {
        let rx_queue = RxQueue::setup(self, config)?;
        self.rx_queues.push(rx_queue);
        Ok(())
    }

    // TODO: return type should provide a handle back to the queue
    /// Configure a new [`TxQueue`]
    pub fn new_tx_queue(&mut self, config: TxQueueConfig) -> Result<(), tx::ConfigFailure> {
        let tx_queue = TxQueue::setup(self, config)?;
        self.tx_queues.push(tx_queue);
        Ok(())
    }

    // TODO: return type should provide a handle back to the queue
    /// Configure a new [`HairpinQueue`]
    pub fn new_hairpin_queue(
        &mut self,
        rx: RxQueueConfig,
        tx: TxQueueConfig,
    ) -> Result<(), HairpinConfigFailure> {
        let rx = RxQueue::setup(self, rx).map_err(HairpinConfigFailure::RxQueueCreationFailed)?;
        let tx = TxQueue::setup(self, tx).map_err(HairpinConfigFailure::TxQueueCreationFailed)?;
        let hairpin = HairpinQueue::new(self, rx, tx)?;
        self.hairpin_queues.push(hairpin);
        Ok(())
    }

    /// Start the device.
    ///
    /// # Errors
    ///
    /// Returns [`DevStartFailure`] with the stopped device for retry or disposal.
    // The error owns the device; this large result is used only during setup.
    #[allow(clippy::result_large_err)]
    pub fn start(self) -> Result<Dev<Started>, DevStartFailure> {
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

impl Dev<Started> {
    /// Stop the device.
    ///
    /// # Errors
    ///
    /// Returns [`DevStopFailure`] with the still-running device.
    // The error owns the device; this large result is used only during teardown.
    #[allow(clippy::result_large_err)]
    pub fn stop(self) -> Result<Dev<Stopped>, DevStopFailure> {
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

    /// Find a configured receive queue by index.
    #[tracing::instrument(level = "trace")]
    pub fn rx_queue(&self, index: RxQueueIndex) -> Option<&RxQueue> {
        self.rx_queues
            .iter()
            .find(|x| x.config.queue_index == index)
    }

    /// Find a configured transmit queue by index.
    #[tracing::instrument(level = "trace")]
    pub fn tx_queue(&self, index: TxQueueIndex) -> Option<&TxQueue> {
        self.tx_queues
            .iter()
            .find(|x| x.config.queue_index == index)
    }
}

/// A start error and the still-stopped device.
#[derive(Debug, thiserror::Error)]
#[error("failed to start device {}: {error}", self.dev.info.index())]
pub struct DevStartFailure {
    /// The error that caused the start to fail.
    #[source]
    pub error: ErrorCode,
    /// The device, still in its [`Stopped`] state.
    pub dev: Dev<Stopped>,
}

/// A stop error and the still-running device.
#[derive(Debug, thiserror::Error)]
#[error("failed to stop device {}: {error}", self.dev.info.index())]
pub struct DevStopFailure {
    /// The error that caused the stop to fail.
    #[source]
    pub error: ErrorCode,
    /// The device, still in its [`Started`] state.
    pub dev: Dev<Started>,
}

impl<S: DevState> Drop for Dev<S> {
    /// Stop the device if it is running.
    fn drop(&mut self) {
        if !S::RUNNING {
            return;
        }
        info!(
            "Closing DPDK ethernet device {port}",
            port = self.info.index()
        );
        let ret = unsafe { rte_eth_dev_stop(self.info.index().as_u16()) };
        if ret != 0 {
            error!(
                "Failed to stop device {port} on drop, error code: {ret}",
                port = self.info.index(),
            );
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SocketIdLookupError {
    #[error("Invalid port ID")]
    DevDoesNotExist(DevIndex),
    #[error("Unknown error code set")]
    UnknownErrno(ErrorCode),
}
