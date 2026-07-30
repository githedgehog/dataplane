// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use std::io::Write;

use parking_lot::{Mutex, MutexGuard};
use tracing_subscriber::fmt::MakeWriter;

/// A [`MakeWriter`] implementation that writes tracing output to a vsock stream.
///
/// This is used by the init system to stream structured tracing data back to
/// the host (container tier) over a vsock connection, where it is collected as
/// part of [`VmTestOutput::init_trace`](n_vm::VmTestOutput).
///
/// The inner stream is protected by a [`Mutex`] so that the type is
/// naturally `Send + Sync` without requiring `unsafe`.
///
/// This uses `parking_lot` rather than `std::sync` (which the workspace
/// clippy config disallows) directly rather than via `concurrency::sync`:
/// `n-it` is the in-guest init binary and deliberately carries no
/// dataplane-internal dependencies, and it does not participate in the
/// loom/shuttle model checking that the `concurrency` facade exists to
/// route.  `concurrency::sync` re-exports `parking_lot` by default anyway.
pub struct VsockWriter(Mutex<vsock::VsockStream>);

impl VsockWriter {
    pub fn new(stream: vsock::VsockStream) -> Self {
        Self(Mutex::new(stream))
    }
}

/// RAII guard returned by [`VsockWriter::make_writer`] that implements
/// [`std::io::Write`] by delegating to the locked vsock stream.
pub struct VsockWriterGuard<'a>(MutexGuard<'a, vsock::VsockStream>);

impl Write for VsockWriterGuard<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

impl<'a> MakeWriter<'a> for VsockWriter {
    type Writer = VsockWriterGuard<'a>;

    fn make_writer(&'a self) -> Self::Writer {
        VsockWriterGuard(self.0.lock())
    }
}
