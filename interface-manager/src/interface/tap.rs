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
use net::interface::{InterfaceIndex, InterfaceName};
use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Write};
use std::num::NonZero;
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
    name: InterfaceName,
    index: InterfaceIndex,
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
    use net::interface::{InterfaceIndex, InterfaceName};
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
            // Asked for now, on the thread that created the device: the lookup resolves in the
            // calling thread's network namespace, which is the one the device was created in.
            let index = nix::net::if_::if_nametoindex(name.as_ref())
                .map_err(std::io::Error::from)
                .and_then(|raw| InterfaceIndex::try_new(raw).map_err(std::io::Error::other))
                .inspect_err(|err| {
                    warn!("failed to learn the interface index of tap device {name}: {err}");
                })?;
            trace!("tap device {name} is interface index {index}");
            // SAFETY: the `File` owns the descriptor, and the `AsyncFd` owns the `File`, so the
            // descriptor stays open and names the same tap for as long as it is registered.
            #[allow(unsafe_code)]
            let fd = unsafe { AsyncFd::register(tap_file) }?;
            Ok(TapDevice { fd, name, index })
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
    /// The largest frame a tap can hand over: the largest MTU a tap accepts, plus an ethernet
    /// header and a VLAN tag.
    ///
    /// An interface's MTU excludes its link-layer header, so a tap whose MTU is `m` can produce
    /// frames of `m + 18` bytes. A read is a single `read(2)` on a character device and returns
    /// exactly one frame, so a buffer shorter than the frame silently truncates it rather than
    /// returning the remainder on the next call. Sizing for the largest possible MTU, rather than
    /// the one configured, means no MTU can cause that.
    pub const MAX_FRAME: usize = u16::MAX as usize + Self::ETH_HLEN + Self::VLAN_HLEN;

    /// A zeroed buffer for [`Self::read`], on the heap: at 64 KiB it is too large to want on a
    /// stack.
    #[must_use]
    pub fn frame_buffer() -> Box<[u8; Self::MAX_FRAME]> {
        vec![0u8; Self::MAX_FRAME]
            .into_boxed_slice()
            .try_into()
            .unwrap_or_else(|_| unreachable!("the vector has exactly MAX_FRAME elements"))
    }

    /// Length of an ethernet header.
    const ETH_HLEN: usize = 14;

    /// Length of an 802.1Q tag.
    const VLAN_HLEN: usize = 4;

    /// Create a tap device with the provided name.
    ///
    /// The device exists for exactly as long as the returned [`TapDevice`] does: dropping it
    /// removes the device from the kernel.  Callers who want the device to outlive the call have
    /// to keep the value; [`TapRegistry`] is what does that for the dataplane.
    ///
    /// The device is created in the network namespace of the *calling thread*, and stays there.
    /// Its interface index, available through [`Self::index`], is the one in that namespace.
    ///
    /// # Errors
    ///
    /// If the tap device cannot be created, or its interface index cannot be learned, an
    /// `io::Error` is returned.
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

    /// The name of this tap.
    #[must_use]
    pub fn name(&self) -> &InterfaceName {
        &self.name
    }

    /// The kernel's interface index for this tap, in the network namespace it was created in.
    #[must_use]
    pub fn index(&self) -> InterfaceIndex {
        self.index
    }

    /// Wait for one frame to arrive on the tap and copy it into `buf`.
    ///
    /// Returns how many bytes the frame occupies. `buf` holds the largest frame a tap can produce,
    /// so no frame is truncated.
    ///
    /// A tap has no end-of-file: a tap whose device has gone away reports an error instead, so
    /// the length is never zero.
    ///
    /// Takes `&self`, which is the point of the readiness-based implementation: one task can hold
    /// the tap and await both directions without splitting the descriptor in two.
    ///
    /// # Errors
    ///
    /// Returns the underlying `io::Error` if the read fails, and
    /// [`std::io::ErrorKind::UnexpectedEof`] if the kernel returns an empty frame, which a tap
    /// does not do.
    pub async fn read(
        &self,
        buf: &mut [u8; Self::MAX_FRAME],
    ) -> Result<NonZero<usize>, std::io::Error> {
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
                return NonZero::new(result?).ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        format!("tap {} returned an empty frame", self.name),
                    )
                });
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

/// Holds nonpersistent tap descriptors for the control-plane bridge.
///
/// Taps disappear when their last descriptor closes, including after a crash. This
/// prevents stale taps from taking names needed by physical devices returning to
/// the host namespace. Pump tasks share ownership through [`Arc`]; the taps remain until those tasks
/// release their descriptors too.
///
/// Create taps on a thread in the control namespace; later `setns` calls do not move them.
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

#[cfg(test)]
mod tests {
    use super::TapDevice;
    use net::interface::InterfaceName;
    use nix::libc;
    use rtnetlink::LinkUnspec;
    use std::time::Duration;

    /// An experimental ethertype, so the test can tell its frame from the kernel's own traffic.
    const ETHERTYPE: u16 = 0x88b5;

    /// Send `frame` out of the interface at `index` with a raw packet socket.
    fn send_raw(index: u32, frame: &[u8]) {
        #[allow(unsafe_code)] // test code: plain socket calls on a descriptor owned here
        unsafe {
            let fd = libc::socket(libc::AF_PACKET, libc::SOCK_RAW, 0);
            assert!(fd >= 0, "{}", std::io::Error::last_os_error());
            let mut address: libc::sockaddr_ll = std::mem::zeroed();
            address.sll_family = u16::try_from(libc::AF_PACKET).unwrap();
            address.sll_ifindex = i32::try_from(index).unwrap();
            address.sll_halen = 6;
            let sent = libc::sendto(
                fd,
                frame.as_ptr().cast(),
                frame.len(),
                0,
                (&raw const address).cast(),
                u32::try_from(size_of::<libc::sockaddr_ll>()).unwrap(),
            );
            let error = std::io::Error::last_os_error();
            libc::close(fd);
            assert_eq!(usize::try_from(sent).ok(), Some(frame.len()), "{error}");
        }
    }

    /// A full-size frame at a jumbo MTU arrives whole: the MTU excludes the ethernet header, so
    /// the frame is longer than the MTU.
    #[n_vm::test]
    fn a_full_size_jumbo_frame_is_read_whole() {
        const MTU: u16 = 9216;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let tap = TapDevice::open(&InterfaceName::try_from("jumbo0").unwrap()).unwrap();
            let (connection, handle, _) = rtnetlink::new_connection().unwrap();
            tokio::spawn(connection);
            handle
                .link()
                .set(
                    LinkUnspec::new_with_index(tap.index().to_u32())
                        .mtu(u32::from(MTU))
                        .up()
                        .build(),
                )
                .execute()
                .await
                .unwrap();

            let mut frame = vec![0xa5u8; usize::from(MTU) + 14];
            frame[..6].fill(0xff);
            frame[6..12].copy_from_slice(&[0x02, 0, 0, 0, 0, 1]);
            frame[12..14].copy_from_slice(&ETHERTYPE.to_be_bytes());
            send_raw(tap.index().to_u32(), &frame);

            // The kernel sends its own traffic (IPv6 neighbour discovery) once the tap is up.
            let mut buf = TapDevice::frame_buffer();
            let read = tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    let len = tap.read(&mut buf).await.unwrap().get();
                    if buf[12..14] == ETHERTYPE.to_be_bytes() {
                        return len;
                    }
                }
            })
            .await
            .expect("the frame reached the tap");
            assert_eq!(read, frame.len());
            assert_eq!(buf[..read], frame[..]);
        });
    }
}
