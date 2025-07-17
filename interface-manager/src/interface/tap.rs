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
            assert_eq!(
                libc::IF_NAMESIZE,
                InterfaceName::MAX_LEN + 1,
                "unsupported platform"
            );
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
