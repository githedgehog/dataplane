// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Network namespace manipulation

#![allow(missing_docs)]

use nix::fcntl::OFlag;
use nix::sched::CloneFlags;
use nix::sys::stat::Mode;
use std::future::Future;
use std::os::fd::{AsRawFd, BorrowedFd};
use std::path::Path;
use tracing::error;

/// Run an (async) function or closure in another network namespace.
///
/// This method will spawn a new thread and create a thread local tokio runtime to execute the
/// provided method.
///
/// # Panics
///
/// * If we are unable to spawn a new thread
/// * If we are unable to create a tokio runtime
/// * If the provided function / closure panics
/// * If the provided netns path is not legal Unicode
pub fn in_netns<
    Exec: (FnOnce() -> Fut) + Send + 'static,
    Fut: Future<Output = Out> + Send,
    Out: Send + 'static,
>(
    netns: &Path,
    exec: Exec,
) -> Out {
    #[allow(clippy::expect_used)] // documented error case
    let netns_str = netns
        .to_str()
        .expect("netns path not legal unicode")
        .to_string();
    let thread_name = format!("netns-{netns_str}");
    #[allow(clippy::expect_used)]
    std::thread::Builder::new()
        .name(thread_name)
        .spawn(move || {
            #[allow(clippy::expect_used)] // the inability to swap to the other netns is fatal
            #[allow(unsafe_code)] // uses external linux FFI
            unsafe { swap_thread_to_netns(&netns_str) }.expect("failed to swap to netns");
            #[allow(clippy::expect_used)] // the inability to start tokio is fatal
            let tokio_runtime = tokio::runtime::Builder::new_current_thread()
                .enable_io()
                .enable_time()
                .build()
                .expect("failed to build tokio runtime");
            tokio_runtime.block_on(exec())
        })
        .expect("failed to spawn netns thread")
        .join()
        .expect("failed to join netns thread")
}

/// Move the current thread to the (extant) network namespace located at `netns_path`.
///
/// # Errors
///
/// Returns a [`rtnetlink::Error`] in an `Err` variant in the event that
///
/// 1. the `unshare` syscall fails
/// 2. `open` fails on the `netns_path`
/// 3. the call to `setns` fails
///
/// Not that the current thread needs the `CAP_SYS_ADMIN` and `CAP_NET_ADMIN` capability in order to
/// run this method successfully.
///
/// # Safety
///
/// If the current thread is bound to network resources (e.g., open sockets), then this method will
/// exhibit undefined behavior.
#[allow(unsafe_code)] // documented rational
pub unsafe fn swap_thread_to_netns(netns_path: &String) -> Result<(), rtnetlink::Error> {
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
            BorrowedFd::borrow_raw(file_descriptor.as_raw_fd())
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
