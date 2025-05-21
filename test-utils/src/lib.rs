// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Testing utilities for the dataplane

use caps::{CapSet, Capability};
use rtnetlink::NetworkNamespace;
use std::panic::{RefUnwindSafe, UnwindSafe, catch_unwind};
use tracing::error;

use nix::fcntl::OFlag;
use nix::sched::CloneFlags;
use nix::sys::stat::Mode;
use std::future::Future;
use std::os::fd::{AsRawFd, BorrowedFd};
use std::path::Path;

/// Fixture which runs the test in a network namespace of the given name.
pub fn run_in_netns<F: UnwindSafe + Send + FnOnce() -> T, T>(
    netns_name: impl AsRef<str>,
) -> impl FnOnce(F) -> T
where
    T: Send,
{
    move |f: F| {
        let netns_path = format!("/run/netns/{netns_name}", netns_name = netns_name.as_ref());
        std::thread::scope(|scope| {
            std::thread::Builder::new()
                .name(netns_name.as_ref().to_string())
                .spawn_scoped(scope, || {
                    with_caps([Capability::CAP_SYS_ADMIN])(|| unsafe {
                        swap_thread_to_netns(&netns_path)
                    })
                    .unwrap_or_else(|e| panic!("{e}"));
                    catch_unwind(f).unwrap()
                })
                .unwrap()
                .join()
                .unwrap()
        })
    }
}

/// Fixture which creates and cleans up a network namespace with the given name.
fn with_netns<F: 'static + Send + RefUnwindSafe + UnwindSafe + Send + FnOnce() -> T, T>(
    netns_name: impl 'static + Send + UnwindSafe + RefUnwindSafe + AsRef<str>,
) -> impl FnOnce(F) -> T
where
    T: Send,
{
    move |f: F| {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .unwrap();
        with_caps([Capability::CAP_SYS_ADMIN])(|| {
            runtime.block_on(async {
                let netns_name_copy = netns_name.as_ref().to_string();
                let Ok((connection, _, _)) = rtnetlink::new_connection() else {
                    panic!("failed to create connection");
                };
                tokio::spawn(connection);
                match NetworkNamespace::add(netns_name_copy).await {
                    Ok(()) => {}
                    Err(err) => {
                        let netns_name = netns_name.as_ref();
                        panic!("failed to create network namespace {netns_name}: {err}");
                    }
                }
            });
        });
        let ret = catch_unwind(f);
        with_caps([Capability::CAP_SYS_ADMIN])(|| {
            runtime.block_on(async {
                match NetworkNamespace::del(netns_name.as_ref().to_string()).await {
                    Ok(()) => {}
                    Err(err) => {
                        let netns_name = netns_name.as_ref();
                        panic!("failed to remove network namespace {netns_name}: {err}");
                    }
                }
            });
        });
        ret.unwrap()
    }
}

/// Fixture which creates and runs a test in the network namespace of the given name.
pub fn in_scoped_netns<F: 'static + Send + RefUnwindSafe + UnwindSafe + Send + FnOnce() -> T, T>(
    netns_name: impl 'static + Sync + UnwindSafe + RefUnwindSafe + AsRef<str>,
) -> impl FnOnce(F) -> T
where
    T: Send + UnwindSafe + RefUnwindSafe,
{
    let netns_name_copy = netns_name.as_ref().to_string();
    |f: F| with_netns(netns_name_copy.clone())(|| run_in_netns(netns_name_copy)(f))
}

/// Fixture which runs the supplied function with _additional_ granted capabilities.
pub fn with_caps<F: UnwindSafe + FnOnce() -> T, T>(
    caps: impl IntoIterator<Item = Capability>,
) -> impl FnOnce(F) -> T {
    move |f: F| {
        let current_caps = match caps::read(None, CapSet::Effective) {
            Ok(current_caps) => current_caps,
            Err(err) => {
                error!("caps error: {}", err);
                panic!("caps error: {err}");
            }
        };
        let needed_caps: Vec<_> = caps
            .into_iter()
            .filter(|cap| !current_caps.contains(cap))
            .collect();
        for cap in &needed_caps {
            caps::raise(None, CapSet::Effective, *cap)
                .unwrap_or_else(|err| panic!("unable to raise capability to {cap}: {err}"));
        }
        let ret = catch_unwind(f);
        for cap in &needed_caps {
            caps::drop(None, CapSet::Effective, *cap)
                .unwrap_or_else(|err| panic!("unable to drop capability to {cap}: {err}"));
        }
        ret.unwrap()
    }
}

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
