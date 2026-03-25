// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Ethernet device management.

use alloc::format;
use alloc::vec::Vec;
use core::ffi::{CStr, c_uint};
use core::fmt::{Debug, Display, Formatter};
use core::mem::ManuallyDrop;
use core::ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign};
use tracing::{debug, error, info};

use crate::eal::Eal;
use crate::queue;
use crate::queue::hairpin::{HairpinConfigFailure, HairpinQueue};
use crate::queue::rx::{RxQueue, RxQueueConfig, RxQueueIndex};
use crate::queue::tx::{TxQueue, TxQueueConfig, TxQueueIndex};
use crate::socket::SocketId;
use dpdk_sys::rte_eth_rx_mq_mode::RTE_ETH_MQ_RX_RSS;
use dpdk_sys::rte_eth_tx_mq_mode::RTE_ETH_MQ_TX_NONE;
use dpdk_sys::rte_eth_rx_offload;
use dpdk_sys::*;
use errno::{Errno, ErrorCode, StandardErrno};
use queue::{rx, tx};

/// Defaults for the RX queue
pub(crate) mod rx_queue_defaults {
    /// Default MTU of an RX queue
    pub(crate) const RX_MTU: u32 = 1514;
    /// Default max LRO packet size for RX queue
    pub(crate) const MAX_LRO: u32 = 8192;
}

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
    /// The receive offloads to be requested on the device.
    ///
    /// If `None`, the device will use all supported offloads.
    /// If `Some`, the device will use the intersection of the supported offloads and the requested
    /// offloads.
    pub rx_offloads: Option<RxOffloadConfig>,
}

#[derive(Debug)]
/// Errors that can occur when configuring a DPDK ethernet device.
pub enum DevConfigError {
    /// A driver-specific error occurred when configuring the ethernet device.
    DriverSpecificError(String),
}

impl DevConfig {
    /// Apply the configuration to the device.
    pub fn apply(&self, dev: DevInfo) -> Result<Dev, DevConfigError> {
        const ANY_SUPPORTED: u64 = u64::MAX;
        let eth_conf = rte_eth_conf {
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
                mtu: rx_queue_defaults::RX_MTU,
                mq_mode: RTE_ETH_MQ_RX_RSS,
                max_lro_pkt_size: rx_queue_defaults::MAX_LRO,
                offloads: {
                    let requested = self
                        .rx_offloads
                        .map_or(RxOffload(ANY_SUPPORTED), RxOffload::from);
                    let supported = dev.rx_offload_caps();
                    (requested & supported).0
                },
                ..Default::default()
            },
            ..Default::default()
        };

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
            //
            // We must copy the string into an owned String because rte_strerror
            // may return a pointer to a thread-local buffer that can be
            // overwritten by the next call to rte_strerror on this thread.
            let rte_error = unsafe { CStr::from_ptr(rte_strerror(ret)) }
                .to_string_lossy()
                .into_owned();
            return Err(DevConfigError::DriverSpecificError(rte_error));
        }
        Ok(Dev {
            info: dev,
            config: *self,
            rx_queues: Vec::with_capacity(self.num_rx_queues as usize),
            tx_queues: Vec::with_capacity(self.num_tx_queues as usize),
            hairpin_queues: Vec::with_capacity(self.num_hairpin_queues as usize),
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

// ---------------------------------------------------------------------------
// RxOffload — named constants, bitwise ops, and verbose config
// ---------------------------------------------------------------------------

impl RxOffload {
    /// VLAN tag stripping.
    pub const VLAN_STRIP: RxOffload = RxOffload(rte_eth_rx_offload::RX_OFFLOAD_VLAN_STRIP);
    /// IPv4 header checksum verification.
    pub const IPV4_CKSUM: RxOffload = RxOffload(rte_eth_rx_offload::RX_OFFLOAD_IPV4_CKSUM);
    /// UDP checksum verification.
    pub const UDP_CKSUM: RxOffload = RxOffload(rte_eth_rx_offload::RX_OFFLOAD_UDP_CKSUM);
    /// TCP checksum verification.
    pub const TCP_CKSUM: RxOffload = RxOffload(rte_eth_rx_offload::RX_OFFLOAD_TCP_CKSUM);
    /// TCP large receive offload.
    pub const TCP_LRO: RxOffload = RxOffload(rte_eth_rx_offload::RX_OFFLOAD_TCP_LRO);
    /// QinQ (double VLAN) stripping.
    pub const QINQ_STRIP: RxOffload = RxOffload(rte_eth_rx_offload::RX_OFFLOAD_QINQ_STRIP);
    /// Outer IPv4 checksum verification (tunnels).
    pub const OUTER_IPV4_CKSUM: RxOffload =
        RxOffload(rte_eth_rx_offload::RX_OFFLOAD_OUTER_IPV4_CKSUM);
    /// MACsec stripping.
    pub const MACSEC_STRIP: RxOffload = RxOffload(rte_eth_rx_offload::RX_OFFLOAD_MACSEC_STRIP);
    /// VLAN filtering.
    pub const VLAN_FILTER: RxOffload = RxOffload(rte_eth_rx_offload::RX_OFFLOAD_VLAN_FILTER);
    /// VLAN extension (QinQ recognition).
    pub const VLAN_EXTEND: RxOffload = RxOffload(rte_eth_rx_offload::RX_OFFLOAD_VLAN_EXTEND);
    /// Scatter-gather I/O (multi-segment receive).
    pub const SCATTER: RxOffload = RxOffload(rte_eth_rx_offload::RX_OFFLOAD_SCATTER);
    /// Hardware timestamping.
    pub const TIMESTAMP: RxOffload = RxOffload(rte_eth_rx_offload::RX_OFFLOAD_TIMESTAMP);
    /// Inline IPsec / security offload.
    pub const SECURITY: RxOffload = RxOffload(rte_eth_rx_offload::RX_OFFLOAD_SECURITY);
    /// Keep the CRC in the received packet data.
    pub const KEEP_CRC: RxOffload = RxOffload(rte_eth_rx_offload::RX_OFFLOAD_KEEP_CRC);
    /// SCTP checksum verification.
    pub const SCTP_CKSUM: RxOffload = RxOffload(rte_eth_rx_offload::RX_OFFLOAD_SCTP_CKSUM);
    /// Outer UDP checksum verification (tunnels).
    pub const OUTER_UDP_CKSUM: RxOffload =
        RxOffload(rte_eth_rx_offload::RX_OFFLOAD_OUTER_UDP_CKSUM);
    /// RSS hash computation in hardware.
    pub const RSS_HASH: RxOffload = RxOffload(rte_eth_rx_offload::RX_OFFLOAD_RSS_HASH);
    /// Receive buffer split.
    pub const BUFFER_SPLIT: RxOffload = RxOffload(rte_eth_rx_offload::RX_OFFLOAD_BUFFER_SPLIT);

    /// Union of all [`RxOffload`]s documented at the time of writing.
    pub const ALL_KNOWN: RxOffload = {
        use rte_eth_rx_offload::*;
        RxOffload(
            RX_OFFLOAD_VLAN_STRIP
                | RX_OFFLOAD_IPV4_CKSUM
                | RX_OFFLOAD_UDP_CKSUM
                | RX_OFFLOAD_TCP_CKSUM
                | RX_OFFLOAD_TCP_LRO
                | RX_OFFLOAD_QINQ_STRIP
                | RX_OFFLOAD_OUTER_IPV4_CKSUM
                | RX_OFFLOAD_MACSEC_STRIP
                | RX_OFFLOAD_VLAN_FILTER
                | RX_OFFLOAD_VLAN_EXTEND
                | RX_OFFLOAD_SCATTER
                | RX_OFFLOAD_TIMESTAMP
                | RX_OFFLOAD_SECURITY
                | RX_OFFLOAD_KEEP_CRC
                | RX_OFFLOAD_SCTP_CKSUM
                | RX_OFFLOAD_OUTER_UDP_CKSUM
                | RX_OFFLOAD_RSS_HASH
                | RX_OFFLOAD_BUFFER_SPLIT,
        )
    };
}

impl BitOr for RxOffload {
    type Output = Self;

    fn bitor(self, rhs: Self) -> RxOffload {
        RxOffload(self.0 | rhs.0)
    }
}

impl BitAnd for RxOffload {
    type Output = Self;

    fn bitand(self, rhs: Self) -> RxOffload {
        RxOffload(self.0 & rhs.0)
    }
}

impl BitXor for RxOffload {
    type Output = Self;

    fn bitxor(self, rhs: Self) -> RxOffload {
        RxOffload(self.0 ^ rhs.0)
    }
}

impl BitOrAssign for RxOffload {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl BitAndAssign for RxOffload {
    fn bitand_assign(&mut self, rhs: Self) {
        self.0 &= rhs.0;
    }
}

impl BitXorAssign for RxOffload {
    fn bitxor_assign(&mut self, rhs: Self) {
        self.0 ^= rhs.0;
    }
}

#[non_exhaustive]
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
/// Verbose configuration for receive offloads.
///
/// This struct mirrors [`TxOffloadConfig`] for the receive path, providing
/// a bool-per-flag view of the hardware rx offload capabilities.
pub struct RxOffloadConfig {
    /// Strip VLAN tags from received packets.
    pub vlan_strip: bool,
    /// Verify IPv4 header checksums in hardware.
    pub ipv4_cksum: bool,
    /// Verify UDP checksums in hardware.
    pub udp_cksum: bool,
    /// Verify TCP checksums in hardware.
    pub tcp_cksum: bool,
    /// Large receive offload (TCP coalescing).
    pub tcp_lro: bool,
    /// Strip QinQ (double VLAN) tags.
    pub qinq_strip: bool,
    /// Verify outer IPv4 checksum (tunnels).
    pub outer_ipv4_cksum: bool,
    /// Strip MACsec headers.
    pub macsec_strip: bool,
    /// VLAN filtering in hardware.
    pub vlan_filter: bool,
    /// VLAN extension (QinQ recognition).
    pub vlan_extend: bool,
    /// Scatter-gather I/O (multi-segment receive).
    pub scatter: bool,
    /// Hardware timestamping.
    pub timestamp: bool,
    /// Inline IPsec / security offload.
    pub security: bool,
    /// Keep the CRC in received packet data.
    pub keep_crc: bool,
    /// Verify SCTP checksums in hardware.
    pub sctp_cksum: bool,
    /// Verify outer UDP checksum (tunnels).
    pub outer_udp_cksum: bool,
    /// RSS hash computation in hardware.
    pub rss_hash: bool,
    /// Receive buffer split.
    pub buffer_split: bool,
    /// Any flags that are not known to map to a valid offload.
    pub unknown: u64,
}

impl Default for RxOffloadConfig {
    /// Defaults to enabling all known offloads.
    fn default() -> Self {
        RxOffloadConfig {
            vlan_strip: true,
            ipv4_cksum: true,
            udp_cksum: true,
            tcp_cksum: true,
            tcp_lro: true,
            qinq_strip: true,
            outer_ipv4_cksum: true,
            macsec_strip: true,
            vlan_filter: true,
            vlan_extend: true,
            scatter: true,
            timestamp: true,
            security: true,
            keep_crc: false,
            sctp_cksum: true,
            outer_udp_cksum: true,
            rss_hash: true,
            buffer_split: true,
            unknown: 0,
        }
    }
}

impl Display for RxOffloadConfig {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl From<RxOffloadConfig> for RxOffload {
    fn from(value: RxOffloadConfig) -> Self {
        use rte_eth_rx_offload::*;
        RxOffload(
            if value.vlan_strip {
                RX_OFFLOAD_VLAN_STRIP
            } else {
                0
            } | if value.ipv4_cksum {
                RX_OFFLOAD_IPV4_CKSUM
            } else {
                0
            } | if value.udp_cksum {
                RX_OFFLOAD_UDP_CKSUM
            } else {
                0
            } | if value.tcp_cksum {
                RX_OFFLOAD_TCP_CKSUM
            } else {
                0
            } | if value.tcp_lro {
                RX_OFFLOAD_TCP_LRO
            } else {
                0
            } | if value.qinq_strip {
                RX_OFFLOAD_QINQ_STRIP
            } else {
                0
            } | if value.outer_ipv4_cksum {
                RX_OFFLOAD_OUTER_IPV4_CKSUM
            } else {
                0
            } | if value.macsec_strip {
                RX_OFFLOAD_MACSEC_STRIP
            } else {
                0
            } | if value.vlan_filter {
                RX_OFFLOAD_VLAN_FILTER
            } else {
                0
            } | if value.vlan_extend {
                RX_OFFLOAD_VLAN_EXTEND
            } else {
                0
            } | if value.scatter {
                RX_OFFLOAD_SCATTER
            } else {
                0
            } | if value.timestamp {
                RX_OFFLOAD_TIMESTAMP
            } else {
                0
            } | if value.security {
                RX_OFFLOAD_SECURITY
            } else {
                0
            } | if value.keep_crc {
                RX_OFFLOAD_KEEP_CRC
            } else {
                0
            } | if value.sctp_cksum {
                RX_OFFLOAD_SCTP_CKSUM
            } else {
                0
            } | if value.outer_udp_cksum {
                RX_OFFLOAD_OUTER_UDP_CKSUM
            } else {
                0
            } | if value.rss_hash {
                RX_OFFLOAD_RSS_HASH
            } else {
                0
            } | if value.buffer_split {
                RX_OFFLOAD_BUFFER_SPLIT
            } else {
                0
            } | value.unknown,
        )
    }
}

impl From<RxOffload> for RxOffloadConfig {
    fn from(value: RxOffload) -> Self {
        use rte_eth_rx_offload::*;
        RxOffloadConfig {
            vlan_strip: value.0 & RX_OFFLOAD_VLAN_STRIP != 0,
            ipv4_cksum: value.0 & RX_OFFLOAD_IPV4_CKSUM != 0,
            udp_cksum: value.0 & RX_OFFLOAD_UDP_CKSUM != 0,
            tcp_cksum: value.0 & RX_OFFLOAD_TCP_CKSUM != 0,
            tcp_lro: value.0 & RX_OFFLOAD_TCP_LRO != 0,
            qinq_strip: value.0 & RX_OFFLOAD_QINQ_STRIP != 0,
            outer_ipv4_cksum: value.0 & RX_OFFLOAD_OUTER_IPV4_CKSUM != 0,
            macsec_strip: value.0 & RX_OFFLOAD_MACSEC_STRIP != 0,
            vlan_filter: value.0 & RX_OFFLOAD_VLAN_FILTER != 0,
            vlan_extend: value.0 & RX_OFFLOAD_VLAN_EXTEND != 0,
            scatter: value.0 & RX_OFFLOAD_SCATTER != 0,
            timestamp: value.0 & RX_OFFLOAD_TIMESTAMP != 0,
            security: value.0 & RX_OFFLOAD_SECURITY != 0,
            keep_crc: value.0 & RX_OFFLOAD_KEEP_CRC != 0,
            sctp_cksum: value.0 & RX_OFFLOAD_SCTP_CKSUM != 0,
            outer_udp_cksum: value.0 & RX_OFFLOAD_OUTER_UDP_CKSUM != 0,
            rss_hash: value.0 & RX_OFFLOAD_RSS_HASH != 0,
            buffer_split: value.0 & RX_OFFLOAD_BUFFER_SPLIT != 0,
            unknown: value.0 & !RxOffload::ALL_KNOWN.0,
        }
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
}

#[derive(Debug)]
/// A DPDK ethernet device.
pub struct Dev {
    /// The device info
    pub info: DevInfo,
    /// The configuration of the device.
    pub config: DevConfig,
    pub(crate) rx_queues: Vec<RxQueue>,
    pub(crate) tx_queues: Vec<TxQueue>,
    pub(crate) hairpin_queues: Vec<HairpinQueue>,
}

impl Dev {
    /// Configure a new [`RxQueue`].
    ///
    /// Returns the index of the newly created queue on success.
    pub fn new_rx_queue(&mut self, config: RxQueueConfig) -> Result<RxQueueIndex, rx::ConfigFailure> {
        let idx = config.queue_index;
        let rx_queue = RxQueue::setup(self, config)?;
        self.rx_queues.push(rx_queue);
        Ok(idx)
    }

    /// Configure a new [`TxQueue`].
    ///
    /// Returns the index of the newly created queue on success.
    pub fn new_tx_queue(&mut self, config: TxQueueConfig) -> Result<TxQueueIndex, tx::ConfigFailure> {
        let idx = config.queue_index;
        let tx_queue = TxQueue::setup(self, config)?;
        self.tx_queues.push(tx_queue);
        Ok(idx)
    }

    /// Configure a new [`HairpinQueue`].
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

    /// Start the device, transitioning to the [`StartedDev`] state.
    ///
    /// This consumes the [`Dev`].  On success a [`StartedDev`] is returned
    /// which provides queue access for packet processing.  On failure the
    /// original [`Dev`] is returned inside the error so it is not lost.
    ///
    /// # Errors
    ///
    /// Returns a [`DevStartError`] if DPDK is unable to start the device.
    pub fn start(self) -> Result<StartedDev, Box<DevStartError>> {
        let port = self.info.index();
        let ret = unsafe { rte_eth_dev_start(port.as_u16()) };

        if ret != 0 {
            error!(
                "Failed to start port {port}, error code: {code}",
                port = port,
                code = ret
            );
            return Err(Box::new(DevStartError {
                dev: self,
                code: ErrorCode::parse_i32(ret),
            }));
        }

        info!("Device {port} started");
        Ok(StartedDev {
            info: self.info,
            config: self.config,
            rx_queues: self.rx_queues,
            tx_queues: self.tx_queues,
            hairpin_queues: self.hairpin_queues,
        })
    }
}

/// A DPDK ethernet device in the **started** (running) state.
///
/// Provides queue access for packet I/O.  Call [`StartedDev::stop`] to
/// transition back to [`Dev`] for reconfiguration, or let the [`Drop`]
/// implementation stop the device automatically.
#[derive(Debug)]
pub struct StartedDev {
    /// The device info.
    pub info: DevInfo,
    /// The configuration of the device.
    pub config: DevConfig,
    pub(crate) rx_queues: Vec<RxQueue>,
    pub(crate) tx_queues: Vec<TxQueue>,
    pub(crate) hairpin_queues: Vec<HairpinQueue>,
}

impl StartedDev {
    /// Look up a receive queue by index.
    #[tracing::instrument(level = "trace")]
    pub fn rx_queue(&self, index: RxQueueIndex) -> Option<&RxQueue> {
        self.rx_queues
            .iter()
            .find(|x| x.config.queue_index == index)
    }

    /// Look up a transmit queue by index.
    #[tracing::instrument(level = "trace")]
    pub fn tx_queue(&self, index: TxQueueIndex) -> Option<&TxQueue> {
        self.tx_queues
            .iter()
            .find(|x| x.config.queue_index == index)
    }

    /// Stop the device, transitioning back to the [`Dev`] state.
    ///
    /// This consumes the [`StartedDev`].  On success a [`Dev`] that can
    /// be reconfigured or dropped is returned.  On failure the
    /// [`StartedDev`] is returned inside the error (the device may still
    /// be running).
    ///
    /// # Errors
    ///
    /// Returns a [`DevStopError`] if DPDK is unable to stop the device.
    pub fn stop(self) -> Result<Dev, Box<DevStopError>> {
        let port = self.info.index();
        info!("Stopping device {port}");
        let ret = unsafe { rte_eth_dev_stop(port.as_u16()) };

        if ret != 0 {
            error!(
                "Failed to stop port {port}, error code: {code}",
                port = port,
                code = ret
            );
            return Err(Box::new(DevStopError {
                dev: self,
                code: ErrorCode::parse_i32(ret),
            }));
        }

        info!("Device {port} stopped");

        // Suppress the `StartedDev` Drop (we already stopped the device
        // above) and move each field into the new `Dev`.
        let this = ManuallyDrop::new(self);

        // SAFETY: `this` will not be dropped (`ManuallyDrop`), so we can
        // safely move each field out via `ptr::read` without double-free.
        unsafe {
            Ok(Dev {
                info: core::ptr::read(&this.info),
                config: core::ptr::read(&this.config),
                rx_queues: core::ptr::read(&this.rx_queues),
                tx_queues: core::ptr::read(&this.tx_queues),
                hairpin_queues: core::ptr::read(&this.hairpin_queues),
            })
        }
    }
}

impl Drop for StartedDev {
    fn drop(&mut self) {
        info!(
            "Stopping DPDK ethernet device {port} (drop)",
            port = self.info.index()
        );
        let ret = unsafe { rte_eth_dev_stop(self.info.index().as_u16()) };
        if ret != 0 {
            error!(
                "Failed to stop device {port} during drop: error {ret}",
                port = self.info.index(),
            );
        }
    }
}

/// Error returned when [`Dev::start`] fails.
///
/// Contains the original [`Dev`] so the caller can retry or reconfigure.
#[derive(Debug, thiserror::Error)]
#[error("failed to start device: {code}")]
pub struct DevStartError {
    /// The device that failed to start (still in stopped state).
    pub dev: Dev,
    /// The error code from DPDK.
    pub code: ErrorCode,
}

/// Error returned when [`StartedDev::stop`] fails.
///
/// Contains the [`StartedDev`] so the caller can retry or let [`Drop`]
/// handle cleanup.
#[derive(Debug, thiserror::Error)]
#[error("failed to stop device: {code}")]
pub struct DevStopError {
    /// The device that failed to stop (still in started state).
    pub dev: StartedDev,
    /// The error code from DPDK.
    pub code: ErrorCode,
}

#[derive(Debug, thiserror::Error)]
pub enum SocketIdLookupError {
    #[error("Invalid port ID")]
    DevDoesNotExist(DevIndex),
    #[error("Unknown error code set")]
    UnknownErrno(ErrorCode),
}
