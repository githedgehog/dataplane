//! Network interface management tools for the dataplane

#![deny(
    unsafe_code,
    missing_docs,
    clippy::all,
    clippy::pedantic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]
#![allow(clippy::should_panic_without_expect)] // we panic in contract checks with simple unwrap()
#![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)] // TODO(blocking)

use netlink_sys::AsyncSocket;
use std::ffi::OsString;
use std::os::fd::{AsRawFd, BorrowedFd};
use std::path::Path;

mod interface;
mod name;

pub use interface::*;
pub use name::*;

// SPDX-License-Identifier: MIT

use std::str::FromStr;

use futures::stream::TryStreamExt;
use net::headers::TryVxlan;
use netlink_packet_route::link::{InfoBridge, InfoData, LinkAttribute, LinkInfo};
use nix::fcntl::OFlag;
use nix::libc::exit;
use nix::sched::CloneFlags;
use nix::sys::stat::Mode;
use nix::unistd::ForkResult;
use rtnetlink::{Handle, new_connection};

#[tokio::test(flavor = "current_thread")]
async fn biscuit() -> Result<(), String> {
    let Ok((mut connection, handle, recv)) = new_connection() else {
        panic!("failed to create connection");
    };
    connection
        .socket_mut()
        .socket_mut()
        .set_rx_buf_sz(212_992)
        .unwrap();

    tokio::spawn(connection);

    create_bridge(handle).await.map_err(|e| format!("{e}"))?;
    // create_vtep(handle).await.map_err(|e| format!("{e}"))?;
    Ok(())
    // create_macvlan(handle, link_name.to_string(), Some(mac_address.as_bytes().to_vec()))
    //     .await
    //     .map_err(|e| format!("{e}"))
}

async fn create_netns<T: AsRef<str>>(name: T) -> Result<(), rtnetlink::Error> {
    let name = name.as_ref().to_string();
    rtnetlink::NetworkNamespace::add(name).await
}

async fn create_bridge(handle: Handle) -> Result<(), rtnetlink::Error> {
    let netns_path_name = OsString::from(rtnetlink::NETNS_PATH.to_string() + "/br_biscuit");
    let netns_path = std::path::Path::new(&netns_path_name);
    match rtnetlink::NetworkNamespace::del("br_biscuit".to_string()).await {
        Ok(()) => { /* ok */ }
        Err(e) => {
            eprintln!("{e:?}");
        }
    }
    let netns_file = match std::fs::File::open(netns_path) {
        Ok(file) => file,
        Err(e) => {
            eprintln!("{e:?}");
            rtnetlink::NetworkNamespace::add("br_biscuit".to_string()).await?;
            std::fs::File::open(netns_path).unwrap()
        }
    };

    let mut req = handle.link().add().bridge("br_biscuit".to_string());
    req.message_mut().attributes.iter_mut().for_each(|x| {
        if let LinkAttribute::LinkInfo(link_info) = x {
            link_info.push(LinkInfo::Data(InfoData::Bridge(vec![
                InfoBridge::VlanProtocol(0x8100),
                InfoBridge::VlanFiltering(1),
                InfoBridge::VlanDefaultPvid(0),
                InfoBridge::NfCallArpTables(0),
                InfoBridge::NfCallIpTables(0),
                InfoBridge::NfCallIp6Tables(0),
            ])));
        }
    });
    if req.message_mut().attributes.iter().any(|x| {
        matches!(
            *x,
            LinkAttribute::NetNsFd(_) | LinkAttribute::NetnsId(_) | LinkAttribute::NetNsPid(_)
        )
    }) {
        panic!("netns already set");
    }
    req.message_mut()
        .attributes
        .push(LinkAttribute::NetNsFd(netns_file.as_raw_fd()));

    req.execute().await?;

    in_netns(
        netns_path.as_os_str().to_str().unwrap(),
        |handle| async move {
            let req = handle.link().get();

            let mut req = req.execute();
            while let Some(link) = req.try_next().await? {
                if !link.attributes.iter().any(|x| match x {
                    LinkAttribute::IfName(x) => {
                        println!("{x:?} ?== br_biscuit");
                        x == "br_biscuit"
                    }
                    _ => false,
                }) {
                    continue;
                }
                println!("science!");
                // if let Some(other_link) = req.try_next().await? {
                //     unreachable!(
                //         "multiple links with same name: {other_link:?}",
                //         other_link = other_link
                //     );
                // }
                println!("{header:?}", header = link.header);
                for attr in &link.attributes {
                    println!("\t{attr:?}");
                }
                let mut req2 = handle.link().del(link.header.index);
                return req2.execute().await;
            }
            panic!("biscuits")
        },
    )
    .await
}

async fn create_vtep(handle: Handle) -> Result<(), rtnetlink::Error> {
    handle
        .link()
        .add()
        .vxlan("biscuit".to_string(), 0)
        .local("192.168.99.3".parse().unwrap())
        .udp_csum(false)
        .learning(false)
        .up()
        .port(4789)
        .ttl(64)
        .collect_metadata(true)
        .execute()
        .await?;

    let mut ret = handle.link().get().execute();

    if ret.try_next().await?.is_some() {
        if let Some(other_link) = ret.try_next().await? {
            unreachable!(
                "multiple links with same name: {other_link:?}",
                other_link = other_link
            );
        }
        Ok(())
    } else {
        Err(rtnetlink::Error::RequestFailed)
    }
}

async fn in_netns<
    F: Future<Output = Result<(), rtnetlink::Error>> + Send,
    Exec: FnOnce(Handle) -> F,
>(
    netns: impl AsRef<str> + Sync,
    exec: Exec,
) -> Result<(), rtnetlink::Error> {
    let netns = netns.as_ref();
    #[allow(unsafe_code)]
    match unsafe { nix::unistd::fork() } {
        Ok(ForkResult::Parent { child: child_pid }) => {
            rtnetlink::NetworkNamespace::parent_process(child_pid)?;
        }
        Ok(ForkResult::Child) => {
            swap_to_netns(&netns.to_string())?;
            let Ok((mut connection, handle, recv)) = new_connection() else {
                panic!("failed to create connection");
            };
            connection
                .socket_mut()
                .socket_mut()
                .set_rx_buf_sz(212_992)
                .unwrap();

            tokio::spawn(connection);
            match exec(handle).await {
                Ok(()) => {
                    #[allow(unsafe_code)]
                    unsafe {
                        exit(0)
                    };
                }
                Err(e) => {
                    eprintln!("{e:?}");
                    #[allow(unsafe_code)]
                    unsafe {
                        exit(1)
                    };
                }
            }
        }
        Err(e) => {
            panic!("fork failed: {e:?}");
        }
    }
    Ok(())
}

// async fn create_macvlan(
//     handle: Handle,
//     link_name: String,
//     mac_address: Option<Vec<u8>>,
// ) -> Result<(), rtnetlink::Error> {
//     let mut parent_links = handle.link().get().match_name(link_name.clone()).execute();
//     if let Some(parent) = parent_links.try_next().await? {
//         let mut request = handle.link().add().macvlan(
//             "my-macvlan".to_string(),
//             parent.header.index,
//         );
//         if let Some(mac) = mac_address {
//             request = request.address(mac);
//         }
//         request.execute().await
//     } else {
//         panic!("no link {link_name} found");
//     }
// }

fn swap_to_netns(netns_path: &String) -> Result<(), rtnetlink::Error> {
    let setns_flags = CloneFlags::CLONE_NEWNET;
    let mut open_flags = OFlag::empty();
    let ns_path = Path::new(netns_path);

    // unshare to the new network namespace
    if let Err(e) = nix::sched::unshare(CloneFlags::CLONE_NEWNET) {
        eprintln!("unshare error: {}", e);
        let err_msg = format!("unshare error: {e}");
        let _ = nix::unistd::unlink(ns_path);
        return Err(rtnetlink::Error::NamespaceError(err_msg));
    }

    open_flags = OFlag::empty();
    open_flags.insert(OFlag::O_RDONLY);
    open_flags.insert(OFlag::O_CLOEXEC);

    let fd = match nix::fcntl::open(Path::new(netns_path), open_flags, Mode::empty()) {
        Ok(raw_fd) => raw_fd,
        Err(e) => {
            eprintln!("open error: {e}");
            let err_msg = format!("open error: {e}");
            return Err(rtnetlink::Error::NamespaceError(err_msg));
        }
    };

    if let Err(e) = nix::sched::setns(
        #[allow(unsafe_code)]
        unsafe {
            BorrowedFd::borrow_raw(fd)
        },
        setns_flags,
    ) {
        eprintln!("setns error: {e}");
        let err_msg = format!("setns error: {e}");
        let _ = nix::unistd::unlink(ns_path);
        return Err(rtnetlink::Error::NamespaceError(err_msg));
    }

    Ok(())
}
