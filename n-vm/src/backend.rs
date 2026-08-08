// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Shared interface for cloud-hypervisor, QEMU, and future VM backends.

use n_vm_protocol::VsockChannel;

use crate::abort_on_drop::AbortOnDrop;
use crate::config::Accel;
use crate::error::VmError;
use crate::vm::TestVmParams;

/// Normalized result of a hypervisor event stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HypervisorVerdict {
    /// The VM shut down cleanly.
    CleanShutdown,
    /// The event stream reported a panic, an error, or no clean shutdown.
    Failure,
}

impl HypervisorVerdict {
    /// Returns `true` if the VM shut down cleanly.
    #[must_use]
    pub fn is_success(self) -> bool {
        matches!(self, Self::CleanShutdown)
    }
}

/// Resources produced by a successful hypervisor launch.
pub struct LaunchedHypervisor<B: HypervisorBackend> {
    /// The hypervisor child process handle.
    pub(crate) child: tokio::process::Child,

    /// Background task monitoring hypervisor lifecycle events.
    pub(crate) event_watcher: AbortOnDrop<(B::EventLog, HypervisorVerdict)>,

    /// Backend-specific handle for lifecycle control.
    pub(crate) controller: B::Controller,
}

/// Hypervisor-specific VM lifecycle operations.
///
/// Implementations translate [`TestVmParams`] into backend-native config,
/// spawn the VMM, watch lifecycle events, and provide best-effort shutdown.
#[expect(
    async_fn_in_trait,
    reason = "this trait is only used within the crate; auto-trait bounds on the \
              returned futures are not required"
)]
pub trait HypervisorBackend: Send + Sized + 'static {
    /// Human-readable backend name for logs and diagnostics.
    const NAME: &str;

    /// Whether this backend can run a guest whose architecture differs
    /// from the host's, via software emulation (TCG).
    ///
    /// KVM-only backends (cloud-hypervisor) return `false`; such tests are
    /// skipped when the guest architecture does not match the host.  The
    /// QEMU backend returns `true` and falls back to TCG for cross-arch
    /// guests.  This is the per-backend capability behind
    /// [`RequestedBackend::resolve`].
    const CAN_EMULATE: bool;

    /// The collected event log produced by the backend's event monitor.
    type EventLog: std::fmt::Display + std::fmt::Debug + Default + Send + 'static;

    /// Backend-specific handle for VM lifecycle control.
    type Controller: Send + 'static;

    /// Spawns the hypervisor process, boots the VM, and starts event monitoring.
    ///
    /// # Errors
    ///
    /// Returns [`VmError`] if any step of the launch sequence fails.
    async fn launch(params: &TestVmParams<'_>) -> Result<LaunchedHypervisor<Self>, VmError>;

    /// Performs best-effort graceful shutdown of the VM and VMM.
    async fn shutdown(controller: &Self::Controller);

    /// Binds a listener for the given [`VsockChannel`] and spawns a
    /// background task that accepts a single connection and reads it to
    /// EOF, returning the contents as a `String`.
    ///
    /// # Errors
    ///
    /// Returns [`VmError::VsockBind`] if the listener cannot be bound.
    fn spawn_vsock_reader(channel: &VsockChannel) -> Result<AbortOnDrop<String>, VmError>;
}

/// The backend a test *requested* (via `#[n_vm::test]`), before resolving it
/// against the host architecture.
///
/// [`Default`](Self::Default) means the test did not name a backend; it
/// prefers cloud-hypervisor but tolerates falling back to QEMU under
/// emulation.  The explicit variants mean the author named that backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestedBackend {
    /// No backend named: prefer cloud-hypervisor, fall back to QEMU/TCG
    /// for a cross-arch guest.
    Default,
    /// Explicitly `#[n_vm::test(cloud_hypervisor)]`: cannot emulate, so skipped
    /// for a cross-arch guest.
    CloudHypervisor,
    /// Explicitly `#[n_vm::test(qemu)]`: emulates a cross-arch guest via TCG.
    Qemu,
}

/// The backend the container tier will actually boot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EffectiveBackend {
    /// Boot cloud-hypervisor.
    CloudHypervisor,
    /// Boot QEMU.
    Qemu,
}

impl EffectiveBackend {
    /// The wire value used in the [`ENV_BACKEND`](n_vm_protocol::ENV_BACKEND)
    /// environment variable.
    #[must_use]
    pub const fn as_env(self) -> &'static str {
        match self {
            Self::CloudHypervisor => "cloud_hypervisor",
            Self::Qemu => "qemu",
        }
    }

    /// Whether this backend can run a guest of a foreign architecture.
    ///
    /// Mirrors [`HypervisorBackend::CAN_EMULATE`], reachable from the value
    /// rather than only from the type, because the host tier decides this
    /// before it has monomorphised anything.
    #[must_use]
    pub const fn can_emulate(self) -> bool {
        match self {
            Self::Qemu => true,
            Self::CloudHypervisor => false,
        }
    }

    /// Parses an [`ENV_BACKEND`](n_vm_protocol::ENV_BACKEND) value,
    /// defaulting to cloud-hypervisor for an absent or unrecognised value
    /// (the historical default backend).
    #[must_use]
    pub fn from_env(value: Option<&str>) -> Self {
        match value {
            Some("qemu") => Self::Qemu,
            _ => Self::CloudHypervisor,
        }
    }
}

/// The outcome of resolving a [`RequestedBackend`] against the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackendResolution {
    /// Boot the given backend with the given acceleration mode.
    Run {
        /// The backend to boot.
        backend: EffectiveBackend,
        /// The acceleration mode.
        accel: Accel,
    },
    /// Skip the test; it requires a backend that cannot run here.
    Skip {
        /// Human-readable explanation, logged to the developer.
        reason: String,
    },
}

impl RequestedBackend {
    /// Resolves the requested backend against whether the guest is
    /// cross-architecture relative to the host.
    ///
    /// Policy (mirrors each backend's
    /// [`CAN_EMULATE`](HypervisorBackend::CAN_EMULATE)):
    ///
    /// - Same-arch: honour the request, use KVM.  cloud-hypervisor works.
    /// - Cross-arch + [`Default`](Self::Default) or [`Qemu`](Self::Qemu):
    ///   run under QEMU/TCG (the test still runs).
    /// - Cross-arch + explicit [`CloudHypervisor`](Self::CloudHypervisor):
    ///   skip -- cloud-hypervisor cannot emulate.
    ///
    /// `needs_qemu` reports whether the test's configuration asks for
    /// something only QEMU provides (today: an emulated Intel NIC).
    ///
    /// `profile` is the hypervisor the selected kernel profile runs on.
    /// When the test expressed no preference -- [`Default`](Self::Default),
    /// which is the overwhelming majority -- the profile decides.  That is
    /// the point: an unpinned test means "anywhere", so it should run in
    /// whichever environment is selected rather than in one particular one.
    ///
    /// Resolving `Default` to a *fixed* backend was the reason a Flatcar run
    /// reported 16 passes while booting four VMs: every unpinned test landed
    /// on cloud-hypervisor, which no QEMU profile has, and skipped.
    ///
    /// `None` means the profile could not be determined -- an unreadable
    /// manifest -- in which case this falls back to the historical fixed
    /// resolution and lets the container tier report the real problem with a
    /// better message than a skip would give.
    #[must_use]
    pub fn resolve(
        self,
        cross_arch: bool,
        needs_qemu: bool,
        profile: Option<EffectiveBackend>,
    ) -> BackendResolution {
        use BackendResolution::{Run, Skip};

        if let Some(profile) = profile {
            // What the test actually requires, if anything at all.
            let required = if needs_qemu {
                Some(EffectiveBackend::Qemu)
            } else {
                match self {
                    Self::Default => None,
                    Self::CloudHypervisor => Some(EffectiveBackend::CloudHypervisor),
                    Self::Qemu => Some(EffectiveBackend::Qemu),
                }
            };

            if let Some(required) = required
                && required != profile
            {
                return Skip {
                    reason: format!(
                        "test requires {required:?}, but the selected kernel profile \
                         runs on {profile:?}",
                    ),
                };
            }

            if cross_arch && !profile.can_emulate() {
                return Skip {
                    reason: "the selected profile's hypervisor cannot emulate a \
                             foreign-architecture guest"
                        .to_owned(),
                };
            }

            return Run {
                backend: profile,
                accel: if cross_arch { Accel::Tcg } else { Accel::Kvm },
            };
        }

        self.resolve_without_profile(cross_arch, needs_qemu)
    }

    /// The pre-profile resolution, kept for the case where the manifest
    /// cannot be read.
    #[must_use]
    fn resolve_without_profile(self, cross_arch: bool, needs_qemu: bool) -> BackendResolution {
        use BackendResolution::{Run, Skip};
        use EffectiveBackend::{CloudHypervisor, Qemu};

        // Only QEMU can satisfy the request, whatever the architecture says.
        if needs_qemu {
            return match self {
                Self::Default | Self::Qemu => Run {
                    backend: Qemu,
                    accel: if cross_arch { Accel::Tcg } else { Accel::Kvm },
                },
                Self::CloudHypervisor => Skip {
                    reason: "the configured NIC model is emulated only by QEMU, \
                             but the test pinned cloud-hypervisor"
                        .to_owned(),
                },
            };
        }

        match (self, cross_arch) {
            (Self::Default | Self::CloudHypervisor, false) => Run {
                backend: CloudHypervisor,
                accel: Accel::Kvm,
            },
            (Self::Qemu, false) => Run {
                backend: Qemu,
                accel: Accel::Kvm,
            },
            (Self::Default | Self::Qemu, true) => Run {
                backend: Qemu,
                accel: Accel::Tcg,
            },
            (Self::CloudHypervisor, true) => Skip {
                reason: "cloud-hypervisor cannot emulate a foreign-architecture \
                         guest (host arch differs from the test's target arch)"
                    .to_owned(),
            },
        }
    }
}

/// Normalises an architecture name to a canonical form so that the Docker
/// daemon's reporting (`x86_64`, `aarch64`) and Rust's
/// [`std::env::consts::ARCH`] (`x86_64`, `aarch64`) -- and the Go-style
/// `amd64` / `arm64` some tools emit -- compare equal.
#[must_use]
fn normalize_arch(arch: &str) -> &str {
    match arch {
        "amd64" | "x86_64" | "x86-64" => "x86_64",
        "arm64" | "aarch64" => "aarch64",
        other => other,
    }
}

/// Returns `true` if the guest (`target_arch`, i.e. the test binary's
/// compile-time architecture) differs from the host the Docker daemon
/// runs on (`daemon_arch`).
///
/// Both are normalised first.  qemu-user fakes `uname`, so the daemon's
/// self-reported architecture -- not `uname` inside the emulated process
/// -- is the reliable host signal.
#[must_use]
pub fn is_cross_arch(daemon_arch: &str, target_arch: &str) -> bool {
    normalize_arch(daemon_arch) != normalize_arch(target_arch)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_honours_request_with_kvm() {
        for req in [
            RequestedBackend::Default,
            RequestedBackend::CloudHypervisor,
            RequestedBackend::Qemu,
        ] {
            match req.resolve(false, false, None) {
                BackendResolution::Run { accel, .. } => assert_eq!(accel, Accel::Kvm),
                BackendResolution::Skip { .. } => panic!("native run must not skip: {req:?}"),
            }
        }
    }

    #[test]
    fn cross_default_falls_back_to_qemu_tcg() {
        assert_eq!(
            RequestedBackend::Default.resolve(true, false, None),
            BackendResolution::Run {
                backend: EffectiveBackend::Qemu,
                accel: Accel::Tcg,
            },
        );
    }

    #[test]
    fn cross_qemu_uses_tcg() {
        assert_eq!(
            RequestedBackend::Qemu.resolve(true, false, None),
            BackendResolution::Run {
                backend: EffectiveBackend::Qemu,
                accel: Accel::Tcg,
            },
        );
    }

    #[test]
    fn cross_explicit_cloud_hypervisor_skips() {
        assert!(matches!(
            RequestedBackend::CloudHypervisor.resolve(true, false, None),
            BackendResolution::Skip { .. },
        ));
    }

    // -- QEMU-only configurations -------------------------------------

    /// An unpinned test that asks for something only QEMU provides is not a
    /// contradiction -- it is a test that wants QEMU.  Selecting it beats
    /// making the author restate the backend they already implied.
    #[test]
    fn unpinned_qemu_only_config_selects_qemu() {
        assert_eq!(
            RequestedBackend::Default.resolve(false, true, None),
            BackendResolution::Run {
                backend: EffectiveBackend::Qemu,
                accel: Accel::Kvm,
            },
        );
    }

    /// Needing QEMU must not cost hardware acceleration when the guest
    /// architecture matches the host; only a cross-arch guest falls to TCG.
    #[test]
    fn qemu_only_config_keeps_kvm_when_not_cross_arch() {
        for req in [RequestedBackend::Default, RequestedBackend::Qemu] {
            match req.resolve(false, true, None) {
                BackendResolution::Run { backend, accel } => {
                    assert_eq!(backend, EffectiveBackend::Qemu);
                    assert_eq!(accel, Accel::Kvm, "{req:?} should keep KVM natively");
                }
                BackendResolution::Skip { .. } => panic!("{req:?} should run"),
            }
        }
        assert_eq!(
            RequestedBackend::Qemu.resolve(true, true, None),
            BackendResolution::Run {
                backend: EffectiveBackend::Qemu,
                accel: Accel::Tcg,
            },
        );
    }

    // -- Profile-driven resolution -----------------------------------

    /// The fix for the coverage hole: a test that named no backend must run
    /// on whatever the selected profile provides, not on one fixed choice.
    ///
    /// Resolving `Default` to cloud-hypervisor regardless was why a Flatcar
    /// run reported 16 passes while booting four VMs -- every unpinned test
    /// landed on a hypervisor no QEMU profile has, and skipped.
    #[test]
    fn unpinned_test_adopts_the_profile_hypervisor() {
        for profile in [EffectiveBackend::Qemu, EffectiveBackend::CloudHypervisor] {
            assert_eq!(
                RequestedBackend::Default.resolve(false, false, Some(profile)),
                BackendResolution::Run {
                    backend: profile,
                    accel: Accel::Kvm,
                },
                "an unpinned test should run on the profile's hypervisor ({profile:?})",
            );
        }
    }

    /// A test that *did* name a backend still skips where it does not fit --
    /// that is a real mismatch rather than an absence of preference.
    #[test]
    fn pinned_test_skips_on_a_profile_it_does_not_match() {
        assert!(matches!(
            RequestedBackend::CloudHypervisor.resolve(false, false, Some(EffectiveBackend::Qemu)),
            BackendResolution::Skip { .. },
        ));
        assert!(matches!(
            RequestedBackend::Qemu.resolve(false, false, Some(EffectiveBackend::CloudHypervisor)),
            BackendResolution::Skip { .. },
        ));
    }

    /// A config needing an emulated NIC is a requirement like any other, so
    /// it skips a cloud-hypervisor profile even when the test named nothing.
    #[test]
    fn qemu_only_config_skips_a_cloud_hypervisor_profile() {
        assert!(matches!(
            RequestedBackend::Default.resolve(false, true, Some(EffectiveBackend::CloudHypervisor)),
            BackendResolution::Skip { .. },
        ));
    }

    /// A cross-arch guest needs an emulating hypervisor; a profile whose
    /// hypervisor cannot emulate is a skip rather than a doomed boot.
    #[test]
    fn cross_arch_skips_a_profile_that_cannot_emulate() {
        assert!(matches!(
            RequestedBackend::Default.resolve(true, false, Some(EffectiveBackend::CloudHypervisor)),
            BackendResolution::Skip { .. },
        ));
        assert_eq!(
            RequestedBackend::Default.resolve(true, false, Some(EffectiveBackend::Qemu)),
            BackendResolution::Run {
                backend: EffectiveBackend::Qemu,
                accel: Accel::Tcg,
            },
        );
    }

    /// An unreadable manifest must not masquerade as an environment
    /// mismatch: it falls back to the historical resolution and lets the
    /// container tier report the real problem.
    #[test]
    fn absent_profile_falls_back_to_the_historical_resolution() {
        assert_eq!(
            RequestedBackend::Default.resolve(false, false, None),
            BackendResolution::Run {
                backend: EffectiveBackend::CloudHypervisor,
                accel: Accel::Kvm,
            },
        );
    }

    /// Pinning cloud-hypervisor *and* asking for a QEMU-only NIC is a
    /// contradiction that `VmConfig::assert_valid_for` rejects at compile
    /// time.  `resolve` still has to answer, so it skips rather than
    /// silently booting a VM that cannot honour the request.
    #[test]
    fn pinned_cloud_hypervisor_with_qemu_only_config_skips() {
        for cross in [false, true] {
            assert!(
                matches!(
                    RequestedBackend::CloudHypervisor.resolve(cross, true, None),
                    BackendResolution::Skip { .. },
                ),
                "cross={cross} should skip",
            );
        }
    }

    #[test]
    fn arch_comparison_normalises() {
        assert!(!is_cross_arch("x86_64", "x86_64"));
        assert!(!is_cross_arch("amd64", "x86_64"));
        assert!(!is_cross_arch("arm64", "aarch64"));
        assert!(is_cross_arch("x86_64", "aarch64"));
        assert!(is_cross_arch("aarch64", "x86_64"));
    }

    #[test]
    fn backend_env_round_trip() {
        for b in [EffectiveBackend::CloudHypervisor, EffectiveBackend::Qemu] {
            assert_eq!(EffectiveBackend::from_env(Some(b.as_env())), b);
        }
        assert_eq!(
            EffectiveBackend::from_env(None),
            EffectiveBackend::CloudHypervisor,
        );
    }
}
