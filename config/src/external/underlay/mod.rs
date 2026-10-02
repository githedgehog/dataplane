// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Underlay configuration

use crate::internal::interfaces::interface::{InterfaceConfig, InterfaceType};
use crate::internal::routing::bgp::{BgpNeighType, BgpUpdateSource};
use crate::internal::routing::evpn::VtepConfig;
use crate::internal::routing::vrf::VrfConfig;
use crate::{ConfigError, ConfigResult};

use net::eth::mac::SourceMac;
use net::ipv4::UnicastIpv4Addr;
use std::net::IpAddr;

use tracing::debug;

#[derive(Clone, Default, Debug)]
pub struct Underlay {
    pub vrf: VrfConfig, /* default vrf */
    pub vtep: Option<VtepConfig>,
}

impl TryFrom<&InterfaceConfig> for VtepConfig {
    type Error = ConfigError;
    fn try_from(intf: &InterfaceConfig) -> Result<Self, Self::Error> {
        match &intf.iftype {
            InterfaceType::Vtep(vtep) => {
                let mac = match vtep.mac {
                    Some(mac) => SourceMac::new(mac).map_err(|_| {
                        ConfigError::BadVtepMacAddress(mac, "VTEP mac is not a valid source mac")
                    }),
                    None => {
                        return Err(ConfigError::MissingParameter("VTEP MAC address"));
                    }
                }?;
                let ip = UnicastIpv4Addr::new(vtep.local).map_err(|e| {
                    ConfigError::BadVtepLocalAddress(IpAddr::V4(e), "Invalid address")
                })?;
                Ok(VtepConfig::new(ip.into(), mac))
            }
            _ => Err(ConfigError::InternalFailure(format!(
                "Attempted to get vtep config from non-vtep interface {}",
                intf.name
            ))),
        }
    }
}

impl Underlay {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    /// Look for a vtep interface in the list of interfaces of the underlay VRF
    /// and, if found, build a `VtepConfig` out of it. We accept at most one VTEP
    /// interface and it has to have valid ip and mac. No Vtep interface is valid
    /// if not VPCs are configured. This is checked elsewhere.
    fn get_vtep_info(&self) -> Result<Option<VtepConfig>, ConfigError> {
        let vteps: Vec<&InterfaceConfig> = self
            .vrf
            .interfaces
            .values()
            .filter(|config| matches!(config.iftype, InterfaceType::Vtep(_)))
            .collect();
        match vteps.len() {
            0 => Ok(None),
            1 => Ok(Some(VtepConfig::try_from(vteps[0])?)),
            _ => Err(ConfigError::TooManyInstances(
                "Vtep interfaces",
                vteps.len(),
            )),
        }
    }

    /// Check that every BGP neighbor agrees with the addressing of the interface
    /// it names.
    fn validate_bgp_neighbor_addressing(&self) -> ConfigResult {
        let Some(bgp) = &self.vrf.bgp else {
            return Ok(());
        };

        for neigh in &bgp.neighbors {
            match &neigh.ntype {
                BgpNeighType::Interface(ifname) => {
                    let iface = self.vrf.interfaces.get(ifname).ok_or_else(|| {
                        ConfigError::Invalid(format!(
                            "BGP neighbor peers over interface '{ifname}', which is not configured"
                        ))
                    })?;
                    if iface.has_ipv4_address() {
                        return Err(ConfigError::Invalid(format!(
                            "BGP neighbor over interface '{ifname}' has no address, requesting \
                             BGP unnumbered, but '{ifname}' has an IPv4 address: unnumbered \
                             requires an interface with no IPv4 addressing"
                        )));
                    }
                }
                BgpNeighType::Host(addr) => {
                    if let Some(BgpUpdateSource::Interface(ifname)) = &neigh.update_source
                        && let Some(iface) = self.vrf.interfaces.get(ifname)
                        && !iface.has_ipv4_address()
                    {
                        return Err(ConfigError::Invalid(format!(
                            "BGP neighbor {addr} is sourced from interface '{ifname}', which has \
                             no IPv4 address"
                        )));
                    }
                }
                BgpNeighType::PeerGroup(_) | BgpNeighType::Unset => {}
            }
        }
        Ok(())
    }

    /// Validate the underlay configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if any interface is invalid, VTEP configuration is wrong,
    /// or a BGP neighbor disagrees with the addressing of the interface it names.
    pub fn validate(&self) -> Result<Self, ConfigError> {
        debug!("Validating underlay configuration...");

        // validate interfaces
        self.vrf
            .interfaces
            .values()
            .try_for_each(InterfaceConfig::validate)?;

        self.validate_bgp_neighbor_addressing()?;

        Ok(Self {
            vrf: self.vrf.clone(),
            // set vtep information if a vtep interface has been specified in the config
            vtep: self.get_vtep_info()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::internal::interfaces::interface::{IfEthConfig, InterfaceConfig};
    use crate::internal::routing::bgp::{BgpConfig, BgpNeighbor};
    use std::net::IpAddr;
    use std::str::FromStr;

    /// An underlay with the given ethernet interfaces (name, addresses) and BGP
    /// neighbors.
    fn underlay_with(ifaces: &[(&str, &[&str])], neighs: Vec<BgpNeighbor>) -> Underlay {
        let mut vrf = VrfConfig::new("default", None, true);

        for (name, ips) in ifaces {
            let mut iface = InterfaceConfig::new(
                name,
                InterfaceType::Ethernet(IfEthConfig { mac: None }),
                false,
            );
            for ip in *ips {
                let (addr, len) = ip.split_once('/').expect("test address needs a mask");
                iface = iface.add_address(
                    IpAddr::from_str(addr).expect("bad test address"),
                    len.parse().expect("bad test mask"),
                );
            }
            vrf.add_interface_config(iface);
        }

        let mut bgp = BgpConfig::new(65000);
        for neigh in neighs {
            bgp.add_neighbor(neigh);
        }
        vrf.set_bgp(bgp);

        Underlay { vrf, vtep: None }
    }

    /// Parse a neighbor address written as a plain literal in a test.
    fn host(addr: &str) -> IpAddr {
        IpAddr::from_str(addr).expect("bad test address")
    }

    /// The valid unnumbered shape: no neighbor address, no IPv4 on the link.
    #[test]
    fn test_unnumbered_over_unaddressed_interface_is_valid() {
        let underlay = underlay_with(
            &[("enp2s1np0", &[])],
            vec![BgpNeighbor::new_interface("enp2s1np0").set_remote_as(65100)],
        );
        assert!(underlay.validate().is_ok());
    }

    /// IPv6 on the link does not interfere: FRR's IPv4 peer derivation only looks
    /// at `AF_INET`, so link-local peering still happens.
    #[test]
    fn test_unnumbered_over_ipv6_only_interface_is_valid() {
        let underlay = underlay_with(
            &[("enp2s1np0", &["2001:db8::1/64"])],
            vec![BgpNeighbor::new_interface("enp2s1np0").set_remote_as(65100)],
        );
        assert!(underlay.validate().is_ok());
    }

    /// A /31 on the link would make FRR derive the far end and peer over IPv4
    /// rather than link-local, so the combination is refused.
    #[test]
    fn test_unnumbered_over_ipv4_interface_is_rejected() {
        let underlay = underlay_with(
            &[("enp2s1np0", &["172.30.128.23/31"])],
            vec![BgpNeighbor::new_interface("enp2s1np0").set_remote_as(65100)],
        );
        let err = underlay
            .validate()
            .expect_err("IPv4 on an unnumbered link must be rejected");
        assert!(
            err.to_string().contains("enp2s1np0"),
            "error should name the interface: {err}"
        );
    }

    /// Any IPv4 prefix length is refused, not just the /30 and /31 FRR would
    /// derive a peer from: the rule is "no IPv4 on an unnumbered link".
    #[test]
    fn test_unnumbered_over_non_p2p_ipv4_interface_is_rejected() {
        let underlay = underlay_with(
            &[("enp2s1np0", &["10.0.0.1/24"])],
            vec![BgpNeighbor::new_interface("enp2s1np0").set_remote_as(65100)],
        );
        assert!(underlay.validate().is_err());
    }

    /// An unnumbered peer must name an interface that exists, since that name is
    /// what gets rendered as `neighbor <ifname> interface`.
    #[test]
    fn test_unnumbered_over_unknown_interface_is_rejected() {
        let underlay = underlay_with(
            &[("enp2s1np0", &[])],
            vec![BgpNeighbor::new_interface("eth0").set_remote_as(65100)],
        );
        assert!(underlay.validate().is_err());
    }

    /// The ordinary fabric case: numbered neighbor, /31 on the link.
    #[test]
    fn test_numbered_over_ipv4_interface_is_valid() {
        let neigh = BgpNeighbor::new_host(host("172.30.128.22"))
            .set_remote_as(65100)
            .set_update_source_interface("enp2s1np0");
        let underlay = underlay_with(&[("enp2s1np0", &["172.30.128.23/31"])], vec![neigh]);
        assert!(underlay.validate().is_ok());
    }

    /// The mirror rule: a session to an explicit address cannot be sourced from
    /// an interface with no IPv4 address.
    #[test]
    fn test_numbered_over_unaddressed_interface_is_rejected() {
        let neigh = BgpNeighbor::new_host(host("172.30.128.22"))
            .set_remote_as(65100)
            .set_update_source_interface("enp2s1np0");
        let underlay = underlay_with(&[("enp2s1np0", &[])], vec![neigh]);
        let err = underlay
            .validate()
            .expect_err("an unaddressed update-source must be rejected");
        assert!(
            err.to_string().contains("enp2s1np0"),
            "error should name the interface: {err}"
        );
    }

    /// An update-source naming an interface this VRF does not hold is left alone:
    /// it may be one created elsewhere, such as the `lo` carrying the VTEP address.
    #[test]
    fn test_numbered_with_foreign_update_source_is_left_alone() {
        let neigh = BgpNeighbor::new_host(host("172.30.128.22"))
            .set_remote_as(65100)
            .set_update_source_interface("lo");
        let underlay = underlay_with(&[("enp2s1np0", &["172.30.128.23/31"])], vec![neigh]);
        assert!(underlay.validate().is_ok());
    }
}
