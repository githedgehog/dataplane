// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Which network interfaces the dataplane is allowed to manage.
//!
//! The dataplane does not own the network namespace it runs in.
//! It shares that namespace with other network managers: a kubernetes CNI (flannel creates
//! `flannel.1` and `cni0`), a container runtime (`docker0`), libvirt (`virbr0`), and whatever the
//! operator set up by hand.
//!
//! Reconciliation removes observed interfaces which are absent from the plan, so the dataplane
//! needs to distinguish "an interface I created for a plan which no longer exists" from "an
//! interface which was never mine."
//! It makes that distinction by name: every interface the dataplane creates is named
//! `<base><suffix>` where the suffix is fixed by the [`ManagedInterfaceKind`] of the interface.
//! An interface whose name does not fit that scheme is _foreign_, and the dataplane must leave it
//! strictly alone.
//!
//! The naming scheme is defined here (and only here) so that the code which _generates_ these
//! names and the code which _recognizes_ them cannot drift apart.
//!
//! Note that this rule is deliberately asymmetric in its failure modes.
//! Failing to recognize one of our own interfaces leaks that interface, which is bad but bounded
//! and self correcting (the next plan which uses that name adopts it).
//! Mistaking somebody else's interface for one of ours destroys their network, which is much
//! worse and is not correctable by us at all.

use net::interface::{IllegalInterfaceName, InterfaceName};
use serde::{Deserialize, Serialize};

/// The kinds of network interface which the dataplane creates, and which it therefore manages.
#[derive(Copy, Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum ManagedInterfaceKind {
    /// A VRF: the routing domain of a VPC.
    Vrf,
    /// A bridge: the broadcast domain of a VPC.
    Bridge,
    /// A VTEP: the vxlan device which terminates a VPC's tunnels.
    Vtep,
    /// A tap device: the kernel's end of an interface which the dataplane proxies.
    Tap,
}

impl ManagedInterfaceKind {
    /// Every kind of network interface which the dataplane manages.
    pub const ALL: [ManagedInterfaceKind; 4] = [Self::Vrf, Self::Bridge, Self::Vtep, Self::Tap];

    /// The name suffix which marks an interface as being of this kind (and thus as belonging to
    /// the dataplane).
    ///
    /// # Invariant
    ///
    /// No suffix may be a suffix of any other suffix; classification would otherwise be ambiguous.
    #[must_use]
    pub const fn suffix(self) -> &'static str {
        match self {
            ManagedInterfaceKind::Vrf => "-vrf",
            ManagedInterfaceKind::Bridge => "-bri",
            ManagedInterfaceKind::Vtep => "-vtp",
            ManagedInterfaceKind::Tap => "-tap",
        }
    }

    /// Classify the interface with this name.
    ///
    /// Returns `None` if the interface is foreign, i.e., if the dataplane did not create it and
    /// therefore must not modify or destroy it.
    #[must_use]
    pub fn of(name: &InterfaceName) -> Option<ManagedInterfaceKind> {
        ManagedInterfaceKind::ALL.into_iter().find(|kind| {
            name.as_ref()
                .strip_suffix(kind.suffix())
                .is_some_and(|base| !base.is_empty())
        })
    }
}

/// The name of a network interface which the dataplane created, and which the dataplane may
/// therefore modify or destroy.
///
/// The only way to get one of these is to build a name from the dataplane's naming scheme, or to
/// recognize a name as having come from that scheme.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ManagedInterfaceName {
    name: InterfaceName,
    kind: ManagedInterfaceKind,
}

/// An [`InterfaceName`] which does not belong to the dataplane.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, thiserror::Error)]
#[error("interface {0} is foreign: its name does not follow the dataplane's naming scheme")]
pub struct ForeignInterfaceName(pub(crate) InterfaceName);

impl ManagedInterfaceName {
    /// The longest base name which can be extended into a legal managed interface name.
    ///
    /// Every suffix is the same length, so this bound does not depend on the
    /// [`ManagedInterfaceKind`].
    pub const MAX_BASE_LEN: usize =
        InterfaceName::MAX_LEN - ManagedInterfaceKind::Vrf.suffix().len();

    /// Name an interface of the supplied `kind` after `base`.
    ///
    /// # Errors
    ///
    /// Returns an error if `base` is empty, or if `base` extended by the suffix of `kind` is not a
    /// legal interface name (most commonly because `base` is longer than [`Self::MAX_BASE_LEN`]).
    pub fn new(kind: ManagedInterfaceKind, base: &str) -> Result<Self, IllegalInterfaceName> {
        if base.is_empty() {
            return Err(IllegalInterfaceName::Empty);
        }
        let name = InterfaceName::try_from(format!("{base}{suffix}", suffix = kind.suffix()))?;
        Ok(Self { name, kind })
    }

    /// The kind of interface this name describes.
    #[must_use]
    pub fn kind(&self) -> ManagedInterfaceKind {
        self.kind
    }

    /// The interface name proper.
    #[must_use]
    pub fn name(&self) -> &InterfaceName {
        &self.name
    }

    /// The portion of the name which precedes the [`ManagedInterfaceKind`] suffix.
    #[must_use]
    pub fn base(&self) -> &str {
        self.name
            .as_ref()
            .strip_suffix(self.kind.suffix())
            .unwrap_or_else(|| unreachable!("managed name is missing its suffix"))
    }
}

impl TryFrom<&InterfaceName> for ManagedInterfaceName {
    type Error = ForeignInterfaceName;

    fn try_from(name: &InterfaceName) -> Result<Self, ForeignInterfaceName> {
        match ManagedInterfaceKind::of(name) {
            None => Err(ForeignInterfaceName(name.clone())),
            Some(kind) => Ok(Self {
                name: name.clone(),
                kind,
            }),
        }
    }
}

impl TryFrom<InterfaceName> for ManagedInterfaceName {
    type Error = ForeignInterfaceName;

    fn try_from(name: InterfaceName) -> Result<Self, ForeignInterfaceName> {
        match ManagedInterfaceKind::of(&name) {
            None => Err(ForeignInterfaceName(name)),
            Some(kind) => Ok(Self { name, kind }),
        }
    }
}

impl From<ManagedInterfaceName> for InterfaceName {
    fn from(managed: ManagedInterfaceName) -> Self {
        managed.name
    }
}

impl AsRef<InterfaceName> for ManagedInterfaceName {
    fn as_ref(&self) -> &InterfaceName {
        &self.name
    }
}

impl std::fmt::Display for ManagedInterfaceName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.name, f)
    }
}

#[cfg(any(test, feature = "bolero"))]
mod contract {
    use crate::interface::{ManagedInterfaceKind, ManagedInterfaceName};
    use bolero::{Driver, TypeGenerator};
    use net::interface::InterfaceName;

    impl TypeGenerator for ManagedInterfaceKind {
        fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
            let index = driver.produce::<u8>()? as usize % ManagedInterfaceKind::ALL.len();
            Some(ManagedInterfaceKind::ALL[index])
        }
    }

    impl TypeGenerator for ManagedInterfaceName {
        fn generate<D: Driver>(driver: &mut D) -> Option<Self> {
            let base = driver.produce::<InterfaceName>()?;
            let base = &base.as_ref()[..base.as_ref().len().min(Self::MAX_BASE_LEN)];
            ManagedInterfaceName::new(driver.produce()?, base).ok()
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::interface::{ForeignInterfaceName, ManagedInterfaceKind, ManagedInterfaceName};
    use net::interface::InterfaceName;

    /// Names created by network managers which are not us.
    ///
    /// The flannel entries are the reason this module exists: flannel's vxlan device parses as a
    /// perfectly ordinary VTEP and its `cni0` parses as a perfectly ordinary bridge, so nothing
    /// but the name distinguishes them from interfaces of ours which have fallen out of the plan.
    const FOREIGN: [&str; 14] = [
        "flannel.1",
        "flannel.4096",
        "flannel-v6.1",
        "flannel-wg",
        "cni0",
        "docker0",
        "veth3a2b1c9",
        "vxlan.calico",
        "kube-ipvs0",
        "virbr0",
        "tunl0",
        "eth0",
        "enp1s0f0",
        "lo",
    ];

    #[test]
    fn foreign_interfaces_are_not_managed() {
        for name in FOREIGN {
            let name = InterfaceName::try_from(name).unwrap_or_else(|e| unreachable!("{e}"));
            assert_eq!(
                ManagedInterfaceKind::of(&name),
                None,
                "{name} must not be treated as an interface of ours"
            );
            assert_eq!(
                ManagedInterfaceName::try_from(&name),
                Err(ForeignInterfaceName(name.clone()))
            );
        }
    }

    #[test]
    fn managed_interfaces_are_classified() {
        let cases = [
            ("abcde-vrf", ManagedInterfaceKind::Vrf),
            ("abcde-bri", ManagedInterfaceKind::Bridge),
            ("abcde-vtp", ManagedInterfaceKind::Vtep),
            ("eth0-tap", ManagedInterfaceKind::Tap),
        ];
        for (name, expected) in cases {
            let name = InterfaceName::try_from(name).unwrap_or_else(|e| unreachable!("{e}"));
            assert_eq!(ManagedInterfaceKind::of(&name), Some(expected));
            let managed =
                ManagedInterfaceName::try_from(&name).unwrap_or_else(|e| unreachable!("{e}"));
            assert_eq!(managed.kind(), expected);
            assert_eq!(managed.name(), &name);
        }
    }

    /// A name which is nothing but a suffix was never generated by us, so it is foreign.
    #[test]
    fn bare_suffixes_are_not_managed() {
        for kind in ManagedInterfaceKind::ALL {
            let name =
                InterfaceName::try_from(kind.suffix()).unwrap_or_else(|e| unreachable!("{e}"));
            assert_eq!(ManagedInterfaceKind::of(&name), None);
        }
    }

    /// Classification is only well defined if no suffix ends with another suffix.
    #[test]
    fn suffixes_are_unambiguous() {
        for a in ManagedInterfaceKind::ALL {
            for b in ManagedInterfaceKind::ALL {
                if a == b {
                    continue;
                }
                assert!(
                    !a.suffix().ends_with(b.suffix()),
                    "{a:?} and {b:?} have ambiguous suffixes"
                );
            }
        }
    }

    /// `MAX_BASE_LEN` is only correct if every suffix is the same length.
    #[test]
    fn suffixes_are_the_same_length() {
        for kind in ManagedInterfaceKind::ALL {
            assert_eq!(
                kind.suffix().len(),
                InterfaceName::MAX_LEN - ManagedInterfaceName::MAX_BASE_LEN
            );
        }
    }

    /// Every name we generate must be recognized as ours, with the kind and base it was built
    /// from.
    #[test]
    fn generated_names_are_recognized() {
        bolero::check!().with_type().for_each(
            |(kind, base): &(ManagedInterfaceKind, InterfaceName)| {
                let base =
                    &base.as_ref()[..base.as_ref().len().min(ManagedInterfaceName::MAX_BASE_LEN)];
                let managed = ManagedInterfaceName::new(*kind, base)
                    .unwrap_or_else(|e| unreachable!("{base} is a legal base name: {e}"));
                assert_eq!(managed.kind(), *kind);
                assert_eq!(managed.base(), base);
                assert_eq!(ManagedInterfaceKind::of(managed.name()), Some(*kind));
                assert_eq!(
                    ManagedInterfaceName::try_from(managed.name()),
                    Ok(managed.clone())
                );
            },
        );
    }

    /// Whatever else classification does, it must never claim a name which does not end in one of
    /// our suffixes.
    #[test]
    fn only_our_suffixes_are_claimed() {
        bolero::check!().with_type().for_each(
            |name: &InterfaceName| match ManagedInterfaceKind::of(name) {
                None => {}
                Some(kind) => {
                    assert!(name.as_ref().ends_with(kind.suffix()));
                    assert!(name.as_ref().len() > kind.suffix().len());
                }
            },
        );
    }

    /// A managed name is exactly its base followed by the suffix of its kind.
    #[test]
    fn base_and_suffix_reconstruct_the_name() {
        bolero::check!()
            .with_type()
            .for_each(|managed: &ManagedInterfaceName| {
                assert_eq!(
                    format!("{}{}", managed.base(), managed.kind().suffix()),
                    managed.name().to_string()
                );
            });
    }
}
