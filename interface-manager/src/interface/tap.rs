// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use net::buffer::{PacketBuffer, PacketBufferMut};
use net::interface::InterfaceName;
use std::num::NonZero;
use std::os::fd::AsRawFd;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, error, info};

#[derive(Debug)]
#[repr(transparent)]
pub struct TapDevice {
    file: tokio::fs::File,
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
    #[derive(Debug, Copy, Clone)]
    pub(super) struct InterfaceRequest(libc::ifreq);

    use net::interface::InterfaceName;
    use nix::libc;

    nix::ioctl_write_ptr_bad!(
        /// Create a tap device
        make_tap_device,
        libc::TUNSETIFF,
        InterfaceRequest
    );

    nix::ioctl_write_ptr_bad!(
        /// Keep the tap device after the program ends
        persist_tap_device,
        libc::TUNSETPERSIST,
        InterfaceRequest
    );

    impl InterfaceRequest {
        /// Create a new `InterfaceRequest`.
        #[cold]
        #[tracing::instrument(level = "trace")]
        pub(super) fn new(name: &InterfaceName) -> Self {
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
            InterfaceRequest(ifreq)
        }
    }

    #[cfg(any(test, feature = "bolero"))]
    mod contract {
        use crate::interface::tap::helper::InterfaceRequest;
        use bolero::{Driver, TypeGenerator};

        impl TypeGenerator for InterfaceRequest {
            fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
                Some(Self::new(&driver.produce()?))
            }
        }
    }

    #[cfg(test)]
    mod test {
        use crate::interface::tap::helper::InterfaceRequest;
        use net::interface::InterfaceName;
        use std::ffi::CStr;

        #[test]
        fn interface_request_new_contract() {
            bolero::check!()
                .with_type()
                .for_each(|name: &InterfaceName| {
                    let name_str = name.to_string();
                    let ifreq = InterfaceRequest::new(name);
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
                        InterfaceRequest::new(&name_parse_back).0.ifr_name
                    );
                });
        }

        #[test]
        fn interface_request_contract() {
            bolero::check!()
                .with_type()
                .for_each(|req: &InterfaceRequest| {
                    #[allow(unsafe_code)] // test code
                    let as_cstr = unsafe { CStr::from_ptr(req.0.ifr_name.as_ptr()) };
                    let as_ifname = InterfaceName::try_from(as_cstr.to_str().unwrap()).unwrap();
                    assert_eq!(req.0.ifr_name, InterfaceRequest::new(&as_ifname).0.ifr_name);
                });
        }
    }
}

impl TapDevice {
    /// Open (or create) a persisted Tap device with the provided name.
    ///
    /// # Errors
    ///
    /// If the tap device cannot be opened or created, an io::Error is returned.
    #[cold]
    #[tracing::instrument(level = "info")]
    pub async fn open(name: &InterfaceName) -> Result<Self, std::io::Error> {
        let ifreq = helper::InterfaceRequest::new(name);
        debug!("opening /dev/net/tun");
        let tap_file = tokio::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(false)
            .truncate(false)
            .open("/dev/net/tun")
            .await?;
        debug!("attempting to create tap device: {name}");
        #[allow(unsafe_code, clippy::borrow_as_ptr)] // well-checked constraints
        let ret = unsafe { helper::make_tap_device(tap_file.as_raw_fd(), &ifreq)? };
        if ret < 0 {
            let err = std::io::Error::last_os_error();
            error!("failed to create tap device {name}: {err}");
            return Err(err);
        }
        info!("created tap device: {name}");
        debug!("attempting to persist tap device: {name}");
        #[allow(unsafe_code, clippy::borrow_as_ptr)] // well-checked constraints
        let ret = unsafe { helper::persist_tap_device(tap_file.as_raw_fd(), &ifreq)? };
        if ret < 0 {
            let err = std::io::Error::last_os_error();
            error!("failed to persist tap device {name}: {err}");
            return Err(err);
        }
        info!("persisted tap device: {name}");
        Ok(Self { file: tap_file })
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
        &mut self,
        buf: &mut Buf,
    ) -> Result<NonZero<u16>, tokio::io::Error> {
        let bytes_read = self.file.read(buf.as_mut()).await?;
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
    pub async fn write<Buf: PacketBuffer>(&mut self, buf: Buf) -> Result<(), tokio::io::Error> {
        self.file.write_all(buf.as_ref()).await
    }
}
