// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

pub(crate) mod allocation;
mod allocator_writer;
pub mod apalloc;
pub(crate) mod flows;
pub(crate) mod icmp_handling;
mod natip;
mod nf;
mod state;
mod test;

// re exports
pub use allocator_writer::NatAllocatorWriter;
pub use allocator_writer::StatefulNatConfig;
pub use nf::StatefulNat;

#[allow(unused)]
use tracing::{debug, error, warn};

use tracectl::trace_target;
trace_target!("stateful-nat", LevelFilter::INFO, &["nat", "pipeline"]);

#[cfg(test)]
mod tests {
    use crate::NatPort;
    use net::headers::Transport;
    use net::tcp::Tcp;
    use net::tcp::port::TcpPort;
    use net::udp::Udp;
    use net::udp::port::UdpPort;

    #[test]
    fn test_set_tcp_ports() {
        let mut transport = Transport::Tcp(Tcp::new(
            TcpPort::try_from(80).expect("Invalid port"),
            TcpPort::try_from(443).expect("Invalid port"),
        ));
        let target_port = NatPort::new_port_checked(1234).expect("Invalid port");

        transport
            .try_set_source(target_port.try_into().unwrap())
            .unwrap();
        let Transport::Tcp(ref mut tcp) = transport else {
            unreachable!()
        };
        assert_eq!(tcp.source(), TcpPort::try_from(1234).unwrap());

        transport
            .try_set_destination(target_port.try_into().unwrap())
            .unwrap();
        let Transport::Tcp(ref mut tcp) = transport else {
            unreachable!()
        };
        assert_eq!(tcp.destination(), TcpPort::try_from(1234).unwrap());
    }

    #[test]
    fn test_set_udp_port() {
        let mut transport = Transport::Udp(Udp::new(
            UdpPort::try_from(80).expect("Invalid port"),
            UdpPort::try_from(443).expect("Invalid port"),
        ));
        let target_port = NatPort::new_port_checked(1234).expect("Invalid port");

        transport
            .try_set_source(target_port.try_into().unwrap())
            .unwrap();
        let Transport::Udp(ref mut udp) = transport else {
            unreachable!()
        };
        assert_eq!(udp.source(), UdpPort::try_from(1234).unwrap());

        transport
            .try_set_destination(target_port.try_into().unwrap())
            .unwrap();
        let Transport::Udp(ref mut udp) = transport else {
            unreachable!()
        };
        assert_eq!(udp.destination(), UdpPort::try_from(1234).unwrap());
    }
}
