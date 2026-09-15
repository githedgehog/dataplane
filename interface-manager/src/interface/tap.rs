// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Tap devices: the kernel's end of an interface the dataplane proxies.
//!
//! A tap is how the control plane sees a port the dataplane owns.  In DPDK mode the kernel has no
//! netdev for the physical port at all -- it was moved into the datapath's own network namespace --
//! so every frame the control plane sends or receives on that port travels through one of these.
//!
//! # Lifetime
//!
//! A tap exists for exactly as long as somebody holds a descriptor for it, unless it has been made
//! persistent, which the dataplane deliberately declines to do.  [`TapRegistry`] is the holder.

use concurrency::sync::Arc;
use concurrency::sync::Mutex;
use net::interface::InterfaceName;
use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Write};
use tokio::io::unix::AsyncFd;
use tracing::{info, warn};

/// One end of a tap device, held open.
///
/// # Why this is readiness-based rather than a [`tokio::fs::File`]
///
/// A tap is a character device, not a file: a read blocks until a frame arrives, which may be
/// never.  `tokio::fs::File` services reads on the blocking pool, so a tap read parks a pool thread
/// for as long as the link is quiet -- and it needs `&mut self`, which would force the read and
/// write halves of one device apart.  [`AsyncFd`] registers the descriptor with the reactor
/// instead, so both directions borrow immutably and an idle tap costs nothing.
#[derive(Debug)]
pub struct TapDevice {
    fd: AsyncFd<File>,
}

mod helper {
    /// This is a validated type around a value which is regrettably fragile.
    ///
    /// 1. Passed directly to the kernel.
    /// 2. By a privileged thread.
    /// 3. In an ioctl.
    /// 4. By an implicitly null terminated pointer.
    ///
    /// As a result, strict checks are in place to ensure memory integrity.
    ///
    /// <div class=warning>
    ///
    /// It is essential that this type remains transparent.
    /// Only zero-sized types may be added to this structure as we don't control the ABI.
    /// We are subject to a contract with the kernel.
    /// </div>
    #[repr(transparent)]
    #[derive(Debug)]
    struct InterfaceRequestInner(libc::ifreq);

    /// This is a validated type around a value which is regrettably fragile.
    ///
    /// 1. Passed directly to the kernel.
    /// 2. By a privileged thread.
    /// 3. In an ioctl.
    /// 4. By an implicitly null terminated pointer.
    ///
    /// As a result, strict checks are in place to ensure memory integrity.
    #[derive(Debug)]
    #[non_exhaustive]
    pub(super) struct InterfaceRequest {
        pub(super) name: InterfaceName,
        request: Pin<Box<InterfaceRequestInner>>,
    }

    #[allow(unsafe_code)]
    unsafe impl Send for InterfaceRequest {}

    use super::TapDevice;
    use net::interface::InterfaceName;
    use nix::libc;
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::OpenOptionsExt;
    use std::pin::Pin;
    use tokio::io::unix::AsyncFd;
    use tracing::{trace, warn};

    nix::ioctl_write_ptr_bad!(
        /// Create a tap device
        make_tap_device,
        libc::TUNSETIFF,
        InterfaceRequestInner
    );

    impl InterfaceRequestInner {
        /// Create a new `InterfaceRequestInner`.
        #[tracing::instrument(level = "trace")]
        fn new(name: &InterfaceName) -> Self {
            // we cannot support any platform for which this condition does not hold
            static_assertions::const_assert_eq!(libc::IF_NAMESIZE, InterfaceName::MAX_LEN + 1);
            let mut ifreq = libc::ifreq {
                ifr_name: [0; libc::IF_NAMESIZE],
                ifr_ifru: libc::__c_anonymous_ifr_ifru {
                    ifru_ifindex: libc::IFF_TAP | libc::IFF_NO_PI,
                },
            };
            for (i, byte) in name.as_ref().as_bytes().iter().enumerate() {
                // already confirmed that we are ASCII in the InterfaceName contract
                #[allow(clippy::cast_possible_wrap)]
                {
                    ifreq.ifr_name[i] = *byte as libc::c_char;
                }
            }
            InterfaceRequestInner(ifreq)
        }
    }

    impl InterfaceRequest {
        /// Create a new `InterfaceRequest`.
        #[cold]
        #[tracing::instrument(level = "trace")]
        pub fn new(name: InterfaceName) -> Self {
            let request = Box::pin(InterfaceRequestInner::new(&name));
            Self { name, request }
        }

        /// Create the tap device this request describes, and hand back the descriptor which
        /// keeps it alive.
        ///
        /// The device is created in the network namespace of the calling thread, and stays in
        /// that namespace for as long as it exists.  That is what places the dataplane's taps:
        /// they land wherever the thread which opened them was, and no later `setns` moves them.
        ///
        /// The descriptor is opened non-blocking because it is about to be registered with the
        /// tokio reactor, and a reactor-registered descriptor which blocks stalls every other task
        /// on that runtime thread.
        pub fn create(self) -> Result<TapDevice, std::io::Error> {
            let name = self.name;
            trace!("opening /dev/net/tun");
            let tap_file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(libc::O_NONBLOCK)
                .open("/dev/net/tun")?;
            trace!("attempting to create tap device {name}");
            #[allow(unsafe_code, clippy::borrow_as_ptr)] // well-checked constraints
            let ret = unsafe { make_tap_device(tap_file.as_raw_fd(), &*self.request)? };
            if ret < 0 {
                let err = std::io::Error::last_os_error();
                warn!("failed to create tap device {name}: {err}");
                return Err(err);
            }
            Ok(TapDevice {
                fd: AsyncFd::new(tap_file)?,
            })
        }
    }

    #[cfg(any(test, feature = "bolero"))]
    mod contract {
        use crate::interface::tap::helper::InterfaceRequestInner;
        use bolero::{Driver, TypeGenerator};

        impl TypeGenerator for InterfaceRequestInner {
            fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
                Some(Self::new(&driver.produce()?))
            }
        }
    }

    #[cfg(test)]
    mod test {
        use crate::interface::tap::helper::InterfaceRequestInner;
        use net::interface::InterfaceName;
        use std::ffi::CStr;

        #[test]
        fn interface_request_new_contract() {
            bolero::check!()
                .with_type()
                .for_each(|name: &InterfaceName| {
                    let name_str = name.to_string();
                    let ifreq = InterfaceRequestInner::new(name);
                    assert_eq!(ifreq.0.ifr_name[ifreq.0.ifr_name.len() - 1], 0);
                    assert_eq!(ifreq.0.ifr_name[name_str.len()], 0);
                    #[allow(unsafe_code)] // test code
                    let as_cstr = unsafe { CStr::from_ptr(ifreq.0.ifr_name.as_ptr()) };
                    assert_eq!(
                        name_str.len(),
                        as_cstr.to_bytes().len(),
                        "memory integrity error"
                    );
                    assert_eq!(name_str.as_bytes(), as_cstr.to_bytes());
                    assert_eq!(name_str.as_bytes(), as_cstr.to_str().unwrap().as_bytes());
                    let name_parse_back =
                        InterfaceName::try_from(as_cstr.to_str().unwrap()).unwrap();
                    assert_eq!(*name, name_parse_back);
                    assert_eq!(
                        ifreq.0.ifr_name,
                        InterfaceRequestInner::new(&name_parse_back).0.ifr_name
                    );
                });
        }

        #[test]
        fn interface_request_contract() {
            bolero::check!()
                .with_type()
                .for_each(|req: &InterfaceRequestInner| {
                    #[allow(unsafe_code)] // test code
                    let as_cstr = unsafe { CStr::from_ptr(req.0.ifr_name.as_ptr()) };
                    let as_ifname = InterfaceName::try_from(as_cstr.to_str().unwrap()).unwrap();
                    assert_eq!(
                        req.0.ifr_name,
                        InterfaceRequestInner::new(&as_ifname).0.ifr_name
                    );
                });
        }
    }
}

impl TapDevice {
    /// The largest frame this module will move across a tap in one go.
    ///
    /// Sized for a jumbo frame plus ethernet and VLAN headers, which is more than any port the
    /// dataplane drives is configured for.  A read is a single `read(2)` on a character device and
    /// returns exactly one frame, so a buffer shorter than the frame silently truncates it rather
    /// than returning the remainder on the next call -- which is why this is generous rather than
    /// tuned.
    pub const MAX_FRAME: usize = 9216;

    /// Create a tap device with the provided name.
    ///
    /// The device exists for exactly as long as the returned [`TapDevice`] does: dropping it
    /// removes the device from the kernel.  Callers who want the device to outlive the call have
    /// to keep the value; [`TapRegistry`] is what does that for the dataplane.
    ///
    /// The device is created in the network namespace of the *calling thread*, and stays there.
    ///
    /// # Errors
    ///
    /// If the tap device cannot be created, an `io::Error` is returned.
    ///
    /// # Panics
    ///
    /// Panics if called outside a tokio runtime: the descriptor is registered with the reactor,
    /// and there is no reactor to register it with otherwise.
    #[cold]
    #[tracing::instrument(level = "info")]
    pub fn open(name: &InterfaceName) -> Result<TapDevice, std::io::Error> {
        helper::InterfaceRequest::new(name.clone()).create()
    }

    /// Wait for one frame to arrive on the tap and copy it into `buf`.
    ///
    /// Returns how many bytes the frame occupies.  A frame longer than `buf` is truncated by the
    /// kernel and its remainder is lost, so `buf` should be at least [`Self::MAX_FRAME`].
    ///
    /// Takes `&self`, which is the point of the readiness-based implementation: one task can hold
    /// the tap and await both directions without splitting the descriptor in two.
    ///
    /// # Errors
    ///
    /// Returns the underlying `io::Error` if the read fails.
    pub async fn read(&self, buf: &mut [u8]) -> Result<usize, std::io::Error> {
        loop {
            let mut ready = self.fd.readable().await?;
            // `try_io` clears the readiness on `WouldBlock` rather than trusting it, which is what
            // makes the retry terminate: a spurious wakeup goes back to waiting instead of
            // spinning on a descriptor that has nothing to give.
            if let Ok(result) = ready.try_io(|inner| {
                // Bound to a `&File` first: `Read` is implemented for `&File`, so the receiver has
                // to be that rather than the `File` it points at.
                let mut file: &File = inner.get_ref();
                file.read(buf)
            }) {
                return result;
            }
        }
    }

    /// Hand one frame to the kernel through the tap.
    ///
    /// # Errors
    ///
    /// Returns the underlying `io::Error` if the write fails, and
    /// [`std::io::ErrorKind::WriteZero`] if the kernel accepted only part of the frame -- which for
    /// a tap it does not do, but a short write must not be reported as a success.
    pub async fn write(&self, frame: &[u8]) -> Result<(), std::io::Error> {
        loop {
            let mut ready = self.fd.writable().await?;
            let attempt = ready.try_io(|inner| {
                let mut file: &File = inner.get_ref();
                file.write(frame)
            });
            match attempt {
                Ok(Ok(written)) if written == frame.len() => return Ok(()),
                Ok(Ok(written)) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        format!("tap accepted {written} of {} bytes", frame.len()),
                    ));
                }
                Ok(Err(err)) => return Err(err),
                // Not ready after all; wait for the next edge.
                Err(_would_block) => {}
            }
        }
    }
}

/// The tap devices this process created, and which it keeps alive by holding them open.
///
/// A tap device exists for exactly as long as somebody holds a descriptor for it, unless it has
/// been marked persistent.  The dataplane deliberately declines to persist its taps, so that they
/// vanish when the dataplane does, however it dies.
///
/// The alternative is worse than it looks.  A persisted tap outlives the process which made it,
/// and the dataplane's taps stand in for physical devices which the packet path moved into a
/// network namespace of its own.  When that namespace goes away those devices come back to the
/// host under their kernel names, and udev renames them into their configured names.  A leftover
/// tap sitting on one of those names would make that rename fail, which strands the real device
/// under a name nothing is looking for.  Nothing recovers from that but an operator.
///
/// Declining to persist means somebody has to hold the descriptors, and this is that somebody.
/// It belongs to the control-plane bridge, so the taps live as long as the bridge which carries
/// their traffic and no longer.
///
/// # Why the devices come back inside an [`Arc`]
///
/// The bridge runs one task per tap, and that task needs the device for the whole run.  A borrow
/// out of the map cannot outlive the lock, so the registry hands out shared ownership instead.
/// That does not weaken the lifetime property: the tasks holding those clones belong to the
/// bridge which owns this registry, and they are joined before it is dropped.
///
/// # Namespaces
///
/// A tap is created in the network namespace of the thread which opens it, and stays there.  The
/// dataplane opens its taps from the management runtime, which runs in the *control* namespace --
/// the one the whole process was launched into -- rather than the datapath namespace the packet
/// path moved the physical devices into.  That is the point: a tap is the kernel's end of a device
/// the dataplane proxies, and the kernel is the side which stayed behind.
#[derive(Debug)]
pub struct TapRegistry {
    held: Mutex<HashMap<InterfaceName, Arc<TapDevice>>>,
}

impl Default for TapRegistry {
    fn default() -> Self {
        Self {
            held: Mutex::new(HashMap::new()),
        }
    }
}

impl TapRegistry {
    /// Create the tap device named `name` and hold it open until [`Self::close`] removes it, or
    /// until this registry is dropped.
    ///
    /// Asking for a tap this registry already holds replaces the descriptor, which removes the
    /// device the old one named.  Nothing asks for a tap it already has, so this means something
    /// outside the dataplane destroyed the original; replacing it is the repair.
    ///
    /// # Errors
    ///
    /// If the tap device cannot be created, an `io::Error` is returned.
    pub fn open(&self, name: &InterfaceName) -> Result<Arc<TapDevice>, std::io::Error> {
        let tap = Arc::new(TapDevice::open(name)?);
        if self.held.lock().insert(name.clone(), tap.clone()).is_some() {
            warn!("replaced our descriptor for tap device {name}: something else removed it");
        } else {
            info!("created tap device {name}");
        }
        Ok(tap)
    }

    /// Share the tap device named `name`, if this registry holds it.
    #[must_use]
    pub fn get(&self, name: &InterfaceName) -> Option<Arc<TapDevice>> {
        self.held.lock().get(name).cloned()
    }

    /// Close this process's descriptor for the tap device named `name`, which removes the device
    /// once every other holder has let go of it too.
    ///
    /// Returns `false` if this registry does not hold that tap, in which case removing it is still
    /// the caller's problem.  That happens for a tap which outlived the process which made it,
    /// which is what an upgrade from a build that persisted its taps leaves behind.
    #[must_use]
    pub fn close(&self, name: &InterfaceName) -> bool {
        let Some(tap) = self.held.lock().remove(name) else {
            return false;
        };
        drop(tap);
        info!("released tap device {name}");
        true
    }

    /// The names of the tap devices this registry is holding open.
    #[must_use]
    pub fn names(&self) -> Vec<InterfaceName> {
        self.held.lock().keys().cloned().collect()
    }

    /// The number of tap devices this registry is holding open.
    #[must_use]
    pub fn len(&self) -> usize {
        self.held.lock().len()
    }

    /// True if this registry is holding no tap devices open.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.held.lock().is_empty()
    }
}
