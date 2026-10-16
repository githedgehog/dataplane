// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Letting the control plane's multicast through the NIC's filter.

use std::os::unix::io::AsFd;

use nix::libc;
use nix::net::if_::if_nametoindex;
use nix::sys::socket::setsockopt;
use nix::{setsockopt_impl, sockopt_impl};

sockopt_impl!(
    PacketAddMembership,
    SetOnly,
    libc::SOL_PACKET,
    libc::PACKET_ADD_MEMBERSHIP,
    libc::packet_mreq
);

/// Have the interface named `if_name` accept every multicast frame, for as long as `fd` is open.
///
/// The control plane's groups are joined on its taps, not here: nobody joins the LLDP group
/// (`01:80:c2:00:00:0e`) or the taps' IPv6 solicited-node groups on the real interface, so its
/// multicast filter drops those frames before any socket sees them. A membership belongs to the
/// socket, so the kernel counts it and withdraws it when the last socket holding it closes.
///
/// `if_name` is looked up in the calling thread's namespace, where the real interface is.
pub(super) fn receive_all_multicast<Fd: AsFd>(fd: Fd, if_name: &str) -> nix::Result<()> {
    let index = if_nametoindex(if_name)?;
    let request = libc::packet_mreq {
        mr_ifindex: i32::try_from(index).map_err(|_| nix::Error::EINVAL)?,
        mr_type: u16::try_from(libc::PACKET_MR_ALLMULTI).map_err(|_| nix::Error::EINVAL)?,
        mr_alen: 0,
        mr_address: [0; 8],
    };
    setsockopt(&fd, PacketAddMembership, &request)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use caps::Capability;
    use fixin::wrap;
    use hardware::netns::NetworkNamespace;
    use nix::sys::socket::{AddressFamily, SockFlag, SockProtocol, SockType, socket};
    use rtnetlink::LinkVeth;
    use test_utils::with_caps;

    /// Whether the kernel has `name` accepting all multicast, as `ip link` would show it.
    fn allmulti(name: &str) -> bool {
        const IFF_ALLMULTI: u32 = 0x200;
        let flags = std::fs::read_to_string(format!("/sys/class/net/{name}/flags")).unwrap();
        let flags = u32::from_str_radix(flags.trim().trim_start_matches("0x"), 16).unwrap();
        flags & IFF_ALLMULTI != 0
    }

    #[n_vm::test]
    #[wrap(with_caps([Capability::CAP_NET_ADMIN, Capability::CAP_SYS_ADMIN]))]
    fn the_interface_accepts_all_multicast_while_the_socket_is_open() {
        std::thread::spawn(|| {
            let netns = NetworkNamespace::create().unwrap();
            netns.enter_with_sysfs().unwrap();
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    let (connection, handle, _) = rtnetlink::new_connection().unwrap();
                    let connection = tokio::spawn(connection);
                    handle
                        .link()
                        .add(LinkVeth::new("mc0", "mc1").build())
                        .execute()
                        .await
                        .unwrap();
                    connection.abort();
                });

            assert!(
                !allmulti("mc0"),
                "a new veth should not accept all multicast"
            );
            let sock = socket(
                AddressFamily::Packet,
                SockType::Raw,
                SockFlag::SOCK_CLOEXEC,
                SockProtocol::EthAll,
            )
            .unwrap();
            receive_all_multicast(&sock, "mc0").unwrap();
            assert!(
                allmulti("mc0"),
                "the membership did not reach the interface"
            );
            assert!(!allmulti("mc1"), "only the named interface should change");
            drop(sock);
            assert!(
                !allmulti("mc0"),
                "closing the socket should withdraw its membership"
            );
            assert!(
                receive_all_multicast(
                    socket(
                        AddressFamily::Packet,
                        SockType::Raw,
                        SockFlag::SOCK_CLOEXEC,
                        SockProtocol::EthAll,
                    )
                    .unwrap(),
                    "no-such-if"
                )
                .is_err(),
                "an interface that does not exist is an error"
            );
        })
        .join()
        .unwrap();
    }
}
