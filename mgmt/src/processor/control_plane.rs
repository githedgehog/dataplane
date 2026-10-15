// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! What the control-plane traffic classes need to know about an applied config.

use std::net::IpAddr;

use config::ValidatedGwConfig;
use config::external::underlay::Underlay;
use config::internal::routing::bfd::BfdPeer;
use config::internal::routing::bgp::{BgpNeighType, BgpUpdateSource};
use traffic_control::ControlPlane;

/// The addresses and peers of the gateway `config` describes.
pub(crate) fn of_config(config: &ValidatedGwConfig) -> ControlPlane {
    let bfd_peers = config
        .internal()
        .map_or(&[][..], |internal| internal.get_bfd_peers().as_slice());
    of_underlay(config.external().underlay(), bfd_peers)
}

/// The addresses and peers of the gateway with this `underlay` and these `bfd_peers`.
///
/// Local addresses are those of the underlay's interfaces, the BGP update sources and BFD sources
/// given as addresses, and the VTEP's. Neighbours are the BGP neighbours given by address and the
/// BFD peers. Neighbours a listen range admits are not known in advance; their sessions count as
/// other local traffic.
pub(crate) fn of_underlay(underlay: &Underlay, bfd_peers: &[BfdPeer]) -> ControlPlane {
    let vrf = &underlay.vrf;
    let bgp_neighbours = vrf.bgp.iter().flat_map(|bgp| &bgp.neighbors);
    let interface_addresses = vrf
        .interfaces
        .values()
        .flat_map(|interface| interface.addresses.iter().map(|a| a.address));
    let update_sources =
        bgp_neighbours
            .clone()
            .filter_map(|neighbour| match neighbour.update_source {
                Some(BgpUpdateSource::Address(address)) => Some(address),
                Some(BgpUpdateSource::Interface(_)) | None => None,
            });
    let bfd_sources = bfd_peers.iter().filter_map(|peer| peer.source);
    let local = interface_addresses.chain(update_sources).chain(bfd_sources);

    let neighbours = bgp_neighbours
        .filter_map(|neighbour| match neighbour.ntype {
            BgpNeighType::Host(address) => Some(address),
            BgpNeighType::PeerGroup(_) | BgpNeighType::Unset => None,
        })
        .chain(bfd_peers.iter().map(|peer| peer.address));

    let vtep = underlay
        .vtep
        .as_ref()
        .map(|vtep| -> IpAddr { vtep.address.inner() });
    ControlPlane::new(local, vtep, neighbours)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::net::{IpAddr, Ipv4Addr};

    use config::external::underlay::Underlay;
    use config::internal::interfaces::interface::{InterfaceConfig, InterfaceType};
    use config::internal::routing::bfd::BfdPeer;
    use config::internal::routing::bgp::{BgpConfig, BgpNeighbor};
    use config::internal::routing::evpn::VtepConfig;
    use net::eth::mac::{Mac, SourceMac};
    use net::ip::UnicastIpAddr;

    use super::of_underlay;

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn an_underlay_names_its_addresses_vtep_and_neighbours() {
        let mut underlay = Underlay::default();
        underlay.vrf.add_interface_config(
            InterfaceConfig::new("eth0", InterfaceType::Loopback, false)
                .add_address(v4(10, 0, 0, 1), 31),
        );
        let mut bgp = BgpConfig::new(65000);
        bgp.add_neighbor(
            BgpNeighbor::new_host(v4(10, 0, 0, 0)).set_update_source_address(v4(172, 16, 0, 1)),
        );
        bgp.add_neighbor(BgpNeighbor::new_peer_group("spines"));
        underlay.vrf.set_bgp(bgp);
        underlay.vtep = Some(VtepConfig::new(
            UnicastIpAddr::try_from(v4(172, 16, 0, 2)).unwrap(),
            SourceMac::new(Mac([0x02, 0, 0, 0, 0, 1])).unwrap(),
        ));
        let bfd = [BfdPeer {
            address: v4(10, 0, 1, 0),
            multihop: true,
            source: Some(v4(10, 0, 1, 1)),
        }];

        let control = of_underlay(&underlay, &bfd);

        let set = |addrs: &[IpAddr]| addrs.iter().copied().collect::<BTreeSet<_>>();
        assert_eq!(
            *control.local(),
            set(&[
                v4(10, 0, 0, 1),
                v4(172, 16, 0, 1),
                v4(10, 0, 1, 1),
                v4(172, 16, 0, 2)
            ])
        );
        assert_eq!(control.vtep(), Some(v4(172, 16, 0, 2)));
        assert_eq!(
            *control.neighbours(),
            set(&[v4(10, 0, 0, 0), v4(10, 0, 1, 0)])
        );
    }
}
