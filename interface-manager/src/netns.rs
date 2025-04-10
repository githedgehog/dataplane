// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use nix::fcntl::OFlag;
use nix::sched::CloneFlags;
use nix::sys::stat::Mode;
use rtnetlink::sys::AsyncSocket;
use rtnetlink::{Handle, new_connection};
use std::future::Future;
use std::os::fd::BorrowedFd;
use std::path::Path;
use tracing::error;

fn in_netns<
    'scope,
    'env: 'scope,
    Exec: (FnMut(&Handle, Req) -> Fut) + Send + 'scope,
    Req: Send + 'scope,
    Resp: Send + 'scope,
    Fut: Future<Output = Resp> + Send + 'scope,
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
    #[allow(clippy::expect_used)] // not called with end-user controlled data
    let netns_str = netns
        .to_str()
        .expect("netns path not legal unicode")
        .to_string()
        .clone();
    let (tx_request, mut rx_request) = tokio::sync::mpsc::channel(BUFFER);
    let (tx_response, rx_response) = tokio::sync::mpsc::channel(BUFFER);
    let thread_name = format!("netns-{netns_str}");
    #[allow(clippy::unwrap_used)] // the inability to join the thread is fatal
    let handle = std::thread::Builder::new()
        .name(thread_name)
        .spawn_scoped(scope, move || {
            #[allow(clippy::expect_used)] // the inability to swap to the other netns is fatal
            unsafe { swap_thread_to_netns(&netns_str) }.expect("failed to swap to netns");
            #[allow(clippy::unwrap_used)] // the inability to start tokio is fatal
            let tokio_runtime = tokio::runtime::Builder::new_current_thread()
                .enable_io()
                .enable_time()
                .build()
                .unwrap();
            tokio_runtime.block_on(async move {
                let (mut connection, handle, _recv) = new_connection().unwrap();
                #[allow(clippy::unwrap_used)] // the inability to open the netlink socket is fatal
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

unsafe fn swap_thread_to_netns(netns_path: &String) -> Result<(), rtnetlink::Error> {
    let ns_path = Path::new(netns_path);

    if let Err(e) = nix::sched::unshare(CloneFlags::CLONE_NEWNET) {
        error!("{e}");
        if let Err(err) = nix::unistd::unlink(ns_path) {
            error!("{msg}", msg = err.desc());
        }
        return Err(rtnetlink::Error::NamespaceError(format!("{e}")));
    }

    let file_descriptor = match nix::fcntl::open(
        Path::new(netns_path),
        OFlag::O_RDONLY | OFlag::O_CLOEXEC,
        Mode::empty(),
    ) {
        Ok(raw_fd) => raw_fd,
        Err(e) => {
            error!("open error: {e}");
            let err_msg = format!("open error: {e}");
            return Err(rtnetlink::Error::NamespaceError(err_msg));
        }
    };

    if let Err(e) = nix::sched::setns(
        #[allow(unsafe_code)]
        unsafe {
            BorrowedFd::borrow_raw(file_descriptor)
        },
        CloneFlags::CLONE_NEWNET,
    ) {
        error!("setns error: {e}");
        let err_msg = format!("setns error: {e}");
        error!("{err_msg}");
        if let Err(err) = nix::unistd::unlink(ns_path) {
            error!("{msg}", msg = err.desc());
        }
        return Err(rtnetlink::Error::NamespaceError(err_msg));
    }
    Ok(())
}
