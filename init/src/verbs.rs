// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Give this process (and so the dataplane) the verbs command channel nodes that moving the
//! bifurcated (mlx5) functions into the datapath namespace creates.
//!
//! Each devlink reload registers the function's RDMA device and its verbs command channel anew,
//! some time after the reload returns (on a BlueField-3 in exclusive RDMA mode, up to about 2 s
//! when the functions had only just come back from a previous dataplane's namespace), and not
//! necessarily under the number (`uverbsN`) the channel had. A container's `/dev` is a copy of the
//! host's taken when the container was created, so the node libibverbs opens can be missing, or
//! name another channel, for as long as the container lives (see [`hardware::devnode`]). mlx5's
//! probe then fails ("Verbs device not found", "Failed to initialize device context").
//!
//! Init reloads a function only after a previous dataplane's namespace has returned it, so once
//! [`expose`] has seen each channel open, the numbers stay put for the dataplane.

use std::time::Duration;

use hardware::devnode::{NodeError, Outcome};
use hardware::pci::address::PciAddress;
use hardware::verbs::{self, Channel, Roots, Unreachable};
use tracing::info;

/// How long the moved functions have, together, to register their verbs command channels.
pub(crate) const SETTLE_TIMEOUT: Duration = Duration::from_secs(30);

/// How often [`expose`] looks again.
const POLL_INTERVAL: Duration = Duration::from_millis(100);

/// The permissions rdma-core's udev rules give `/dev/infiniband/uverbs*` on the host.
pub(crate) const PERMISSIONS: u32 = 0o666;

/// Why a function's verbs command channel is not reachable.
#[derive(Debug, thiserror::Error)]
pub(crate) enum VerbsNodeError {
    /// It is not, and waiting will not change that.
    #[error("libibverbs cannot reach {address}: {source}")]
    Unreachable {
        /// The function.
        address: PciAddress,
        /// How far it gets.
        source: Unreachable,
    },
    /// Its node could not be made.
    #[error("cannot make the verbs command channel node of {address}: {source}")]
    Node {
        /// The function.
        address: PciAddress,
        /// Why.
        source: NodeError,
    },
    /// The kernel had not registered it by the deadline.
    #[error(
        "libibverbs still cannot reach {address} after {waited:?}: {last}. Is RDMA enabled on \
         the function, and is the host in exclusive RDMA mode (ib_core.netns_mode=0)?"
    )]
    TimedOut {
        /// The function.
        address: PciAddress,
        /// How long it was waited for.
        waited: Duration,
        /// How far it got.
        last: Unreachable,
    },
}

/// Wait until libibverbs can open the verbs command channel of each of `addresses` from `roots`,
/// making (with `make`) any node `/dev` lacks or has on another device, or until `deadline`.
///
/// A node is made again whenever the channel it is for no longer has its number.
///
/// # Errors
///
/// One [`VerbsNodeError`] per function that is not reachable.
pub(crate) fn expose(
    roots: &Roots,
    addresses: &[PciAddress],
    deadline: clock::Instant,
    mut make: impl FnMut(&Channel) -> Result<Outcome, NodeError>,
) -> Result<(), Vec<VerbsNodeError>> {
    let started = clock::now();
    let mut pending: Vec<PciAddress> = addresses.to_vec();
    let mut failed = Vec::new();
    let mut waiting = false;
    loop {
        let mut still = Vec::new();
        for address in pending {
            match reach(roots, address, &mut make) {
                Ok(()) => {
                    if waiting {
                        info!(
                            "the verbs command channel of {address} is reachable after {:?}",
                            clock::elapsed(started)
                        );
                    }
                }
                Err(Step::Wait(last)) => still.push((address, last)),
                Err(Step::Fail(e)) => failed.push(e),
            }
        }
        if still.is_empty() {
            break;
        }
        if clock::now() >= deadline {
            let waited = clock::elapsed(started);
            failed.extend(
                still
                    .into_iter()
                    .map(|(address, last)| VerbsNodeError::TimedOut {
                        address,
                        waited,
                        last,
                    }),
            );
            break;
        }
        if !waiting {
            for (address, last) in &still {
                info!("waiting for the verbs command channel of {address}: {last}");
            }
            waiting = true;
        }
        pending = still.into_iter().map(|(address, _)| address).collect();
        std::thread::sleep(POLL_INTERVAL);
    }
    if failed.is_empty() {
        Ok(())
    } else {
        Err(failed)
    }
}

/// What [`expose`] does next with a function that is not reachable yet.
enum Step {
    /// Look again: the kernel may still register it.
    Wait(Unreachable),
    /// Give up on it.
    Fail(VerbsNodeError),
}

/// One look at `address`, making its node if that is what it lacks.
fn reach(
    roots: &Roots,
    address: PciAddress,
    make: &mut impl FnMut(&Channel) -> Result<Outcome, NodeError>,
) -> Result<(), Step> {
    let channel = match verbs::reachable(roots, address) {
        Ok(_) => return Ok(()),
        Err(Unreachable::NoNode { channel }) => channel,
        Err(e) if e.is_pending() => return Err(Step::Wait(e)),
        Err(source) => return Err(Step::Fail(VerbsNodeError::Unreachable { address, source })),
    };
    info!(
        "making {} ({}) for {address}: this container's /dev lacks it, or has it on another device",
        channel.node.display(),
        channel.number
    );
    make(&channel).map_err(|source| Step::Fail(VerbsNodeError::Node { address, source }))?;
    match verbs::open(channel) {
        Ok(_) => Ok(()),
        // The channel was numbered anew since it was looked at; the next look makes it again.
        Err(e @ Unreachable::NoNode { .. }) => Err(Step::Wait(e)),
        Err(source) => Err(Step::Fail(VerbsNodeError::Unreachable { address, source })),
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;
    use std::path::{Path, PathBuf};

    use hardware::devnode::DeviceNumberError;
    use hardware::verbs::fake::Fake;

    use super::*;

    /// Make `node` a link to `target`.
    fn link(node: &Path, target: &str) {
        let _ = std::fs::remove_file(node);
        symlink(target, node).unwrap();
    }

    /// Makes nodes as links: `/dev/null` for 1:3, `/dev/zero` (1:5) for anything else.
    fn linker(made: &mut Vec<Channel>) -> impl FnMut(&Channel) -> Result<Outcome, NodeError> + '_ {
        |channel| {
            let target = match (channel.number.major, channel.number.minor) {
                (1, 3) => "/dev/null",
                _ => "/dev/zero",
            };
            link(&channel.node, target);
            made.push(channel.clone());
            Ok(Outcome::Made)
        }
    }

    fn soon() -> clock::Instant {
        clock::deadline(Duration::from_millis(300))
    }

    #[test]
    fn a_reachable_channel_is_left_alone() {
        let fake = Fake::new().rdma_device().channel("1:3").node();
        let mut made = Vec::new();
        expose(&fake.roots(), &[Fake::address()], soon(), linker(&mut made)).unwrap();
        assert_eq!(made, []);
    }

    #[test]
    fn a_missing_node_is_made() {
        let fake = Fake::new().rdma_device().channel("1:3");
        let mut made = Vec::new();
        expose(&fake.roots(), &[Fake::address()], soon(), linker(&mut made)).unwrap();
        assert_eq!(made.len(), 1);
        assert_eq!(made[0].node, fake.root.join("dev/infiniband/uverbs0"));
    }

    #[test]
    fn a_node_on_another_device_is_replaced() {
        let fake = Fake::new().rdma_device().channel("1:3");
        symlink("/dev/zero", fake.root.join("dev/infiniband/uverbs0")).unwrap();
        let mut made = Vec::new();
        expose(&fake.roots(), &[Fake::address()], soon(), linker(&mut made)).unwrap();
        assert_eq!(made.len(), 1);
    }

    /// A node that is still not the channel after it was made (the channel was numbered anew
    /// in between) is made again.
    #[test]
    fn a_node_that_does_not_check_out_is_made_again() {
        let fake = Fake::new().rdma_device().channel("1:3");
        let mut calls = 0;
        expose(
            &fake.roots(),
            &[Fake::address()],
            clock::deadline(Duration::from_secs(5)),
            |channel| {
                calls += 1;
                // The first node is made for the channel's previous number.
                link(
                    &channel.node,
                    if calls == 1 { "/dev/zero" } else { "/dev/null" },
                );
                Ok(Outcome::Made)
            },
        )
        .unwrap();
        assert_eq!(calls, 2);
        assert_eq!(
            std::fs::read_link(fake.root.join("dev/infiniband/uverbs0")).unwrap(),
            PathBuf::from("/dev/null")
        );
    }

    /// A device the kernel registers while this waits is waited for.
    #[test]
    fn a_device_registered_late_is_waited_for() {
        let fake = Fake::new();
        let roots = fake.roots();
        let mut made = Vec::new();
        std::thread::scope(|scope| {
            let waiter = scope.spawn(|| {
                expose(
                    &roots,
                    &[Fake::address()],
                    clock::deadline(Duration::from_secs(10)),
                    linker(&mut made),
                )
            });
            std::thread::sleep(Duration::from_millis(250));
            let _fake = fake.rdma_device().channel("1:3");
            waiter.join().unwrap().unwrap();
        });
        assert_eq!(made.len(), 1);
    }

    #[test]
    fn a_device_that_never_registers_times_out() {
        let fake = Fake::new();
        let mut made = Vec::new();
        let errors =
            expose(&fake.roots(), &[Fake::address()], soon(), linker(&mut made)).unwrap_err();
        assert!(
            matches!(
                errors.as_slice(),
                [VerbsNodeError::TimedOut {
                    last: Unreachable::NoDevice { .. },
                    ..
                }]
            ),
            "{errors:?}"
        );
    }

    /// Waiting will not fix a number sysfs gives garbled; the start fails at once.
    #[test]
    fn a_malformed_number_fails_without_waiting() {
        let fake = Fake::new().rdma_device().channel("garbage");
        let mut made = Vec::new();
        let errors = expose(
            &fake.roots(),
            &[Fake::address()],
            clock::deadline(Duration::from_secs(60)),
            linker(&mut made),
        )
        .unwrap_err();
        assert!(
            matches!(
                errors.as_slice(),
                [VerbsNodeError::Unreachable {
                    source: Unreachable::Number(DeviceNumberError::Malformed { .. }),
                    ..
                }]
            ),
            "{errors:?}"
        );
    }

    #[test]
    fn a_node_that_cannot_be_made_fails_without_waiting() {
        let fake = Fake::new().rdma_device().channel("1:3");
        let errors = expose(
            &fake.roots(),
            &[Fake::address()],
            clock::deadline(Duration::from_secs(60)),
            |channel| {
                Err(NodeError::Create {
                    path: channel.node.clone(),
                    source: nix::Error::EPERM,
                })
            },
        )
        .unwrap_err();
        assert!(
            matches!(errors.as_slice(), [VerbsNodeError::Node { .. }]),
            "{errors:?}"
        );
    }
}
