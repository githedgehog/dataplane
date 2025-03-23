// SPDX-License-Identifier: MIT
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
#![allow(unsafe_code)] // we panic in contract checks with simple unwrap()
#![allow(missing_docs)] // we panic in contract checks with simple unwrap()
#![allow(clippy::should_panic_without_expect)] // we panic in contract checks with simple unwrap()
#![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)] // TODO(blocking)

use nix::unistd::ForkResult;
use std::ffi::OsString;
use std::os::fd::{AsRawFd, BorrowedFd};
use std::path::Path;

mod actor;
mod interface;
mod message;
mod name;
mod reconcile;
mod resource;

pub use interface::*;
pub use name::*;

use futures::stream::TryStreamExt;
use nix::fcntl::OFlag;
use nix::libc::exit;
use nix::sched::CloneFlags;
use nix::sys::stat::Mode;
use rtnetlink::packet_route::link::{InfoBridge, InfoData, LinkAttribute, LinkInfo};
use rtnetlink::sys::AsyncSocket;
use rtnetlink::{Handle, LinkBridge, LinkUnspec, LinkVrf, new_connection};

#[tokio::test(flavor = "current_thread")]
async fn biscuit() -> Result<(), String> {
    let Ok((mut connection, handle, _recv)) = new_connection() else {
        panic!("failed to create connection");
    };
    connection
        .socket_mut()
        .socket_mut()
        .set_rx_buf_sz(212_992)
        .unwrap();

    tokio::spawn(connection);

    create_bridge(handle).await.map_err(|e| format!("{e}"))?;
    Ok(())
}

#[allow(clippy::too_many_lines)]
async fn create_bridge(handle: Handle) -> Result<(), rtnetlink::Error> {
    let netns_path_name = OsString::from(rtnetlink::NETNS_PATH.to_string() + "/br_biscuit");
    let netns_path = Path::new(&netns_path_name);
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

    handle
        .link()
        .add(
            LinkVrf::new("science", 119)
                .setns_by_fd(netns_file.as_raw_fd())
                .up()
                .build(),
        )
        .execute()
        .await?;

    let req = handle.link().add(
        LinkBridge::new("br_biscuit")
            .setns_by_fd(netns_file.as_raw_fd())
            .append_extra_attribute(LinkAttribute::LinkInfo(vec![LinkInfo::Data(
                InfoData::Bridge(vec![
                    InfoBridge::VlanProtocol(0x8100),
                    InfoBridge::VlanFiltering(true),
                    InfoBridge::VlanDefaultPvid(0),
                    InfoBridge::NfCallArpTables(0),
                    InfoBridge::NfCallIpTables(0),
                    InfoBridge::NfCallIp6Tables(0),
                ]),
            )]))
            .build(),
    );

    req.execute().await?;
    in_netns2(netns_path, |handle| async move {
        let mut bridge_query = handle
            .link()
            .get()
            .match_name("br_biscuit".to_string())
            .execute();

        let Ok(Some(bridge)) = bridge_query.try_next().await else {
            panic!("WRONG");
        };

        let Ok(None) = bridge_query.try_next().await else {
            panic!("VERY WRONG");
        };

        let mut vrf_query = handle
            .link()
            .get()
            .match_name("science".to_string())
            .execute();

        let Ok(Some(vrf)) = vrf_query.try_next().await else {
            panic!("WRONG");
        };

        let Ok(None) = vrf_query.try_next().await else {
            panic!("VERY WRONG");
        };

        let controller_request = handle.link().set(
            LinkUnspec::new_with_index(bridge.header.index)
                .controller(vrf.header.index)
                .build(),
        );

        controller_request.execute().await
    })?;

    let mut links = handle.link().get().execute();

    while let Some(link) = links.try_next().await? {
        println!("link: ");
        for attr in &link.attributes {
            println!("\t{attr:?}");
        }
    }

    Ok(())
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
            let Ok((mut connection, handle, _recv)) = new_connection() else {
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

fn in_netns2<
    T: Send + 'static,
    F: Future<Output = Result<T, rtnetlink::Error>> + Send,
    Exec: 'static + Send + FnOnce(Handle) -> F,
>(
    netns: &Path,
    exec: Exec,
) -> Result<T, rtnetlink::Error> {
    let netns_str = netns
        .to_str()
        .expect("netns path not legal unicode")
        .to_string()
        .clone();
    std::thread::scope(|scope| {
        std::thread::Builder::new()
            .name(netns_str.clone())
            .spawn_scoped(scope, || {
                swap_to_netns(&netns_str)?;
                let tokio_runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_io()
                    .enable_time()
                    .thread_name(netns_str)
                    .build()
                    .unwrap();
                tokio_runtime.block_on(async move {
                    let Ok((mut connection, handle, _recv)) = new_connection() else {
                        panic!("failed to create connection");
                    };
                    connection
                        .socket_mut()
                        .socket_mut()
                        .set_rx_buf_sz(212_992)
                        .unwrap();
                    tokio::spawn(connection);
                    exec(handle).await
                })
            })
            .expect("unable to spawn thread")
            .join()
            .unwrap()
    })
}

fn in_netns3<
    'scope,
    'env: 'scope,
    Req: Send + 'scope,
    Resp: Send + 'scope,
    Fut: Future<Output = Resp> + Send + 'scope,
    Exec: (FnMut(&Handle, Req) -> Fut) + Send + 'scope,
>(
    scope: &'scope std::thread::Scope<'scope, 'env>,
    netns: &Path,
    mut exec: Exec,
) -> (
    std::thread::ScopedJoinHandle<'scope, ()>,
    tokio::sync::mpsc::Sender<Req>,
    tokio::sync::mpsc::Receiver<Resp>,
) {
    const BUFFER: usize = 16_384; // TODO: adjust to something reasonable
    let netns_str = netns
        .to_str()
        .expect("netns path not legal unicode")
        .to_string()
        .clone();
    let (tx_request, mut rx_request) = tokio::sync::mpsc::channel(BUFFER);
    let (tx_response, rx_response) = tokio::sync::mpsc::channel(BUFFER);
    let thread_name = format!("netns-{netns_str}");
    let handle = std::thread::Builder::new()
        .name(thread_name)
        .spawn_scoped(scope, move || {
            swap_to_netns(&netns_str).expect("failed to swap to netns");
            let tokio_runtime = tokio::runtime::Builder::new_current_thread()
                .enable_io()
                .enable_time()
                .build()
                .unwrap();
            tokio_runtime.block_on(async move {
                let Ok((mut connection, handle, _recv)) = new_connection() else {
                    panic!("failed to create connection");
                };
                connection
                    .socket_mut()
                    .socket_mut()
                    .set_rx_buf_sz(212_992)
                    .unwrap();
                tokio::spawn(connection);
                while let Some(request) = rx_request.recv().await {
                    let resp = exec(&handle, request).await;
                    tx_response.send(resp).await.unwrap();
                }
            });
        })
        .unwrap();
    (handle, tx_request, rx_response)
}

fn swap_to_netns(netns_path: &String) -> Result<(), rtnetlink::Error> {
    let setns_flags = CloneFlags::CLONE_NEWNET;
    let mut open_flags = OFlag::empty();
    let ns_path = Path::new(netns_path);

    // unshare to the new network namespace
    if let Err(e) = nix::sched::unshare(CloneFlags::CLONE_NEWNET) {
        eprintln!("unshare error: {e}");
        let err_msg = format!("unshare error: {e}");
        let _ = nix::unistd::unlink(ns_path);
        return Err(rtnetlink::Error::NamespaceError(err_msg));
    }

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
