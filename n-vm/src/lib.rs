// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![deny(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]

//! Runtime support for `#[in_vm]` tests.
//!
//! The host tier starts a Docker container, the container tier boots a VM
//! through a [`HypervisorBackend`], and the guest tier runs under `n-it`.
//! This crate also re-exports the macro attributes and protocol constants
//! used by generated code.

pub mod backend;
pub mod cloud_hypervisor;
pub mod config;
pub mod dispatch;
pub mod error;
pub mod qemu;

pub mod abort_on_drop;
mod container;
mod test_identity;
mod vm;

pub use abort_on_drop::AbortOnDrop;
pub use backend::{HypervisorBackend, HypervisorVerdict, LaunchedHypervisor};
pub use cloud_hypervisor::CloudHypervisor;
pub use config::{GuestHugePageConfig, GuestHugePageSize, HostPageSize, NicModel, VmConfig};
pub use container::{ContainerTestResult, run_test_in_vm};
pub use dispatch::{
    block_on_in_guest, block_on_in_guest_multi_thread, is_in_test_container, is_in_vm,
    run_container_tier, run_host_tier,
};
pub use error::{ContainerError, VmError};
pub use n_vm_macros::{guest, hypervisor, in_vm, network};
pub use n_vm_protocol::{
    CLOUD_HYPERVISOR_BINARY_PATH, CONTAINER_PLATFORM, ENV_IN_TEST_CONTAINER, ENV_IN_VM,
    ENV_MARKER_VALUE, ENV_TEST_ROOT, ENV_VM_ROOT, HYPERVISOR_API_SOCKET_PATH, INIT_BINARY_PATH,
    KERNEL_CONSOLE_SOCKET_PATH, KERNEL_IMAGE_PATH, QEMU_BINARY_PATH, ScratchRootError,
    ScratchRoots, VHOST_VSOCK_SOCKET_PATH, VIRTIOFS_ROOT_TAG, VIRTIOFSD_BINARY_PATH,
    VIRTIOFSD_SOCKET_PATH, VM_GUEST_CID, VM_ROOT_SHARE_PATH, VM_RUN_DIR, VM_TEST_BIN_DIR,
    VsockAllocation, VsockChannel, VsockCid, VsockPort,
};
pub use qemu::Qemu;
pub use vm::{ProcessOutput, TestVm, TestVmParams, VmTestOutput, run_in_vm};
