// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use derive_builder::Builder;
use multi_index_map::MultiIndexMap;
use net::buffer::{PacketBuffer, PacketBufferMut};
use net::interface::InterfaceName;
use serde::{Deserialize, Serialize};
use std::num::NonZero;
use std::os::fd::AsFd;
use tokio::io::unix::AsyncFd;
#[allow(unused)]
use tracing::error;

/// The planned properties of a dummy interface.
#[derive(
    Builder,
    Clone,
    Debug,
    Eq,
    Hash,
    MultiIndexMap,
    Ord,
    PartialEq,
    PartialOrd,
    Deserialize,
    Serialize,
)]
#[multi_index_derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "bolero"), derive(bolero::TypeGenerator))]
pub struct TapDevicePropertiesSpec {}

#[derive(Debug)]
pub struct TapDevice {
    name: InterfaceName,
    async_fd: AsyncFd<std::fs::File>,
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

    use net::interface::InterfaceName;
    use nix::fcntl::{FcntlArg, OFlag, fcntl};
    use nix::libc;
    use std::fs::File;
    use std::os::fd::{AsFd, AsRawFd};
    use std::pin::Pin;
    use tokio::io::unix::AsyncFd;
    use tracing::{info, trace, warn};

    nix::ioctl_write_ptr_bad!(
        /// Create a tap device
        make_tap_device,
        libc::TUNSETIFF,
        InterfaceRequestInner
    );

    nix::ioctl_write_ptr_bad!(
        /// Keep the tap device after the program ends
        persist_tap_device,
        libc::TUNSETPERSIST,
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

        fn set_nonblocking(file: &File) -> Result<(), std::io::Error> {
            let fd = file.as_fd();
            let flags = OFlag::from_bits_truncate(
                fcntl(fd, FcntlArg::F_GETFL)
                    .map_err(|e| std::io::Error::from_raw_os_error(e as i32))?,
            );
            fcntl(fd, FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK))
                .map_err(|e| std::io::Error::from_raw_os_error(e as i32))?;
            Ok(())
        }

        pub fn create(self) -> Result<AsyncFd<std::fs::File>, std::io::Error> {
            let name = self.name;
            trace!("opening /dev/net/tun");
            let tap_file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(false)
                .truncate(false)
                .open("/dev/net/tun")?;

            let fd = tap_file.as_raw_fd();
            Self::set_nonblocking(&tap_file)?;

            trace!("attempting to create tap device {name}");
            #[allow(unsafe_code, clippy::borrow_as_ptr)] // well-checked constraints
            let ret = unsafe { make_tap_device(fd, &*self.request)? };
            if ret < 0 {
                let err = std::io::Error::last_os_error();
                warn!("failed to create tap device {name}: {err}");
                return Err(err);
            }
            info!("created tap device {name}");
            trace!("attempting to persist tap device");
            #[allow(unsafe_code, clippy::borrow_as_ptr)] // well-checked constraints
            let ret = unsafe { persist_tap_device(fd, &*self.request)? };
            if ret < 0 {
                let err = std::io::Error::last_os_error();
                warn!("failed to persist tap device: {err}");
                return Err(err);
            }
            info!("persisted tap device: {name}");
            AsyncFd::new(tap_file)
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
    /// Open (or create) a persisted Tap device with the provided name.
    ///
    /// # Errors
    ///
    /// If the tap device cannot be opened or created, an `io::Error` is returned.
    #[cold]
    #[tracing::instrument(level = "info")]
    pub async fn open(name: &InterfaceName) -> Result<Self, std::io::Error> {
        let async_fd = helper::InterfaceRequest::new(name.clone()).create()?;
        Ok(TapDevice {
            name: name.clone(),
            async_fd,
        })
    }

    /// Get a reference to the name of a `TapDevice
    pub fn name(&self) -> &InterfaceName {
        &self.name
    }

    /// Get a reference to the name of a `TapDevice`
    #[must_use]
    pub fn ifindex(&self) -> InterfaceIndex {
        self.ifindex
    }

    /// Read a packet from the tap and store it in the provided buffer. In principle, a single read
    /// operation should suffice to get an entire packet. This method will not return until that
    /// happens or an error occurs.
    ///
    /// # Errors
    ///
    /// If the file descriptor of the tap device cannot be read, a [`tokio::io::Error`] is returned.
    async fn do_read<Buf: PacketBufferMut>(&self, buf: &mut Buf) -> tokio::io::Result<usize> {
        let fd = self.async_fd.as_fd();
        loop {
            let mut guard = self.async_fd.readable().await?;
            match nix::unistd::read(fd, buf.as_mut()) {
                Ok(n) => return Ok(n),
                Err(e) if e == nix::errno::Errno::EINTR => continue,
                Err(e) if e == nix::errno::Errno::EWOULDBLOCK => guard.clear_ready(),
                Err(e) => {
                    error!("Error reading from tap {}: {e:?}", self.name);
                    return Err(e.into());
                }
            }
        }
    }

    /// Write the provided buffer to the tap. In principle, a single write operation should suffice to
    /// write a buffer. This method will not return until that happens or an error occurs.
    ///
    /// # Errors
    ///
    /// If the file descriptor of the tap device cannot be written to, a [`tokio::io::Error`] is returned.
    async fn do_write<Buf: PacketBuffer>(&self, buf: Buf) -> tokio::io::Result<usize> {
        let fd = self.async_fd.as_fd();
        let data = buf.as_ref();
        let len = data.len();
        let mut w = 0;
        loop {
            let mut guard = self.async_fd.writable().await?;
            match nix::unistd::write(fd, &data[w..]) {
                Ok(n) => {
                    w += n;
                    if w == len {
                        return Ok(w);
                    }
                }
                Err(e) if e == nix::errno::Errno::EINTR => continue,
                Err(e) if e == nix::errno::Errno::EWOULDBLOCK => guard.clear_ready(),
                Err(e) => {
                    error!("Error writing to tap {}: {e:?}", self.name);
                    return Err(e.into());
                }
            }
        }
    }

    /// Read a packet from the tap, filling out the provided buffer with the contents of the packet.
    ///
    /// # Errors
    ///
    /// If the tap device cannot be read, a [`tokio::io::Error`] is returned.
    ///
    /// # Panics
    ///
    /// This method should not panic assuming that all types involved uphold required invariants.
    #[tracing::instrument(level = "trace")]
    pub async fn read<Buf: PacketBufferMut>(
        &self,
        buf: &mut Buf,
    ) -> Result<NonZero<u16>, tokio::io::Error> {
        let bytes_read = self.do_read(buf).await?;
        let bytes_read = match u16::try_from(bytes_read) {
            Ok(bytes_read) => bytes_read,
            Err(err) => {
                error!("nonsense packet length received: {err}");
                return Err(tokio::io::Error::other(err));
            }
        };
        let Some(bytes_read) = NonZero::new(bytes_read) else {
            return Err(tokio::io::Error::new(
                tokio::io::ErrorKind::UnexpectedEof,
                "unexpected EOF on tap device",
            ));
        };
        let orig_len = match u16::try_from(buf.as_ref().len()) {
            Ok(orig_len) => orig_len,
            Err(err) => {
                error!("nonsense sized buffer: {}", buf.as_ref().len());
                return Err(tokio::io::Error::other(err));
            }
        };
        if orig_len < bytes_read.get() {
            error!("buffer too small: {orig_len} < {bytes_read}");
            return Err(tokio::io::Error::new(
                tokio::io::ErrorKind::InvalidInput,
                "buffer too small to hold received data",
            ));
        }
        #[allow(clippy::expect_used)] // memory integrity requirement already checked
        buf.trim_from_end(orig_len - bytes_read.get())
            .expect("failed to trim buffer: illegal memory manipulation");
        Ok(bytes_read)
    }

    /// Write the provided buffer to the tap.
    ///
    /// # Errors
    ///
    /// If the tap device cannot be written to, a [`tokio::io::Error`] is returned.
    #[tracing::instrument(level = "trace")]
    pub async fn write<Buf: PacketBuffer>(&self, buf: Buf) -> Result<(), tokio::io::Error> {
        let len = buf.as_ref().len();
        let written = self.do_write(buf).await?;
        debug_assert!(written == len);
        Ok(())
    }
}
