// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! How much of the overlay configuration the operation algebra can express.
//!
//! The algebra builds configurations by construction, so every configuration it produces is valid.
//! The converse is the open question, and it is the one that decides what a green fuzzing run is
//! worth: a configuration outside the algebra's image is invisible to every property built on it,
//! and nothing about the run says so. [`algebra`](super::algebra) states this as its own property
//! and does not check it.
//!
//! # Why not compare against real configurations
//!
//! The obvious check is the one the design note proposes: take configurations from CI and from the
//! field and assert each is expressible as an operation sequence. It would answer a slightly
//! different question than the one asked, and answer it misleadingly.
//!
//! The algebra's address plan is a *function of the handles*: peering `p`, side `s`, slot `n` has
//! one private prefix and one public prefix, and nothing can be told to use different ones. So no
//! real configuration is expressible, essentially all of them fail on the address plan alone, and
//! the report is "0% reachable" -- which is true, useless, and hides the differences that matter.
//!
//! # What is measured instead
//!
//! Each *degree of freedom* of the configuration schema, separately, with its own verdict. That
//! separates "the algebra picks one address plan out of many" -- deliberate, and harmless to every
//! property that states its claims relative to the configuration rather than against constants --
//! from "no operation can produce a port-forwarding expose", which is a hole.
//!
//! The evidence is statistical and comes from the fuzzer: draw sequences, survey what comes out,
//! and check the observed values against what each field is recorded to reach. That makes the
//! record falsifiable in both directions. A field recorded as reaching two values that only ever
//! shows one is a generator that has stopped exploring it -- the failure mode the design note
//! documents at length for connected components, where the useful bias took four attempts to
//! find. A field recorded as fixed that starts varying is a vocabulary that grew without the
//! record following it.
//!
//! # The ratchet
//!
//! [`survey`] destructures every config struct exhaustively and matches every enum exhaustively,
//! so a field or variant added to the schema does not compile until it is surveyed, and
//! [`every_surveyed_field_is_classified`] then fails until it is classified. The point is that a
//! new configuration feature cannot quietly become unreachable: the schema and this record move
//! together or the build stops.
//!
//! Both halves were break-tested and both fire. Deleting one row of [`REACH`] fails
//! `every_surveyed_field_is_classified` naming the orphaned field. Adding a `hairpin` field to
//! `VpcExposeMasquerade` does not compile: `pattern does not mention field hairpin`, pointing at
//! [`survey_nat`]. The second is the one that matters -- it stops the build rather than a test, so
//! it cannot be reached by a green run that nobody read.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};

use lpm::prefix::with_ports::{L4Protocol, PrefixPortsSet};

use super::Overlay;
use super::algebra::Sequence;
use super::vpc::Vpc;
use super::vpcpeering::{
    VpcExpose, VpcExposeMasquerade, VpcExposeNat, VpcExposeNatConfig, VpcExposePortForwarding,
    VpcExposeStaticNat, VpcManifest, VpcPeering,
};

/// How far the algebra's image reaches into one degree of freedom.
#[derive(Debug)]
enum Reach {
    /// Every value the schema offers here is reachable, and these are all of them.
    ///
    /// Only stated for fields whose value set is small enough to write down. A field with an
    /// unbounded set that the algebra genuinely spans would need a different kind of evidence.
    Spans(&'static [&'static str]),
    /// Varies, but as a function of the handles rather than as a choice the generator makes.
    ///
    /// Not a hole. It is what "preconditions are unrepresentable" costs: a peering names vpcs by
    /// handle, so a vpc's name, id and vni fall out of the handle rather than being drawn.
    Determined(&'static str),
    /// Assembled from elsewhere in the same configuration rather than chosen at all.
    Derived(&'static str),
    /// One value, always. This is the gap list.
    Fixed(&'static str),
}

/// What the algebra reaches, field by field, and where the fixed ones fall short.
///
/// The paths are the ones [`survey`] records, which is the ratchet: the two must agree exactly.
const REACH: &[(&str, Reach)] = &[
    (
        "Overlay.vpc_table",
        Reach::Determined("one vpc per `AddVpc`, in handle order"),
    ),
    (
        "Overlay.peering_table",
        Reach::Determined("one peering per `AddPeering`, in handle order"),
    ),
    ("Vpc.name", Reach::Determined("`VpcHandle::name`")),
    ("Vpc.id", Reach::Determined("`VpcHandle::id`")),
    ("Vpc.vni", Reach::Determined("`VpcHandle::vni`")),
    (
        "Vpc.interfaces",
        Reach::Fixed(
            "empty. No operation attaches an interface to a vpc, so no generated configuration \
             has one. Reaching the interface-bearing paths at all needs a new operation.",
        ),
    ),
    (
        "Vpc.peerings",
        Reach::Derived(
            "collected from the peering table by `Overlay::validate`, not by the algebra",
        ),
    ),
    (
        "VpcPeering.name",
        Reach::Determined("`PeeringHandle::name`"),
    ),
    (
        "VpcPeering.left",
        Reach::Determined("the peering's left handle"),
    ),
    (
        "VpcPeering.right",
        Reach::Determined("the peering's right handle"),
    ),
    (
        "VpcPeering.gwgroup",
        Reach::Fixed(
            "the default group. `with_default_group` is the only constructor the algebra calls, \
             so nothing generated ever splits vpcs across gateway groups.",
        ),
    ),
    (
        "VpcPeering.acl",
        Reach::Fixed(
            "absent. Peering-scoped ACLs are not in the vocabulary, so no generated configuration \
             carries one -- and an ACL is precisely a thing that changes a verdict, which is what \
             every property here asserts over.",
        ),
    ),
    (
        "VpcManifest.name",
        Reach::Determined("the side's vpc handle"),
    ),
    (
        "VpcManifest.exposes",
        Reach::Determined("one per `AddExpose`, in slot order"),
    ),
    (
        "VpcExpose.default",
        Reach::Fixed("false. `VpcExpose::empty` never sets it and no operation does either."),
    ),
    (
        "VpcExpose.ips",
        Reach::Determined("one prefix, from the expose's peering, side and slot"),
    ),
    (
        "VpcExpose.ips.ports",
        // Set only by `Flavour::PortForward`, which is the one flavour whose configuration
        // names ports at all. Every other expose still covers whole addresses, so both
        // answers appear and the difference between them is under test.
        Reach::Spans(&["set", "unset"]),
    ),
    (
        "VpcExpose.nots",
        Reach::Fixed(
            "empty -- the survey renders it as no prefixes at all. An expose that carves holes out of its own range is unreachable, which is a \
             real hole rather than a canonicalisation: an exclusion is what makes a prefix set \
             non-contiguous, and non-contiguous is where a matcher goes wrong.",
        ),
    ),
    ("VpcExpose.nat", Reach::Spans(&["absent", "present"])),
    (
        "VpcExposeNat.as_range",
        Reach::Determined("one prefix in the translated pool, from peering, side and slot"),
    ),
    (
        "VpcExposeNat.as_range.ports",
        Reach::Spans(&["set", "unset"]),
    ),
    (
        "VpcExposeNat.not_as",
        Reach::Fixed("empty, for the same reason as `VpcExpose.nots`."),
    ),
    (
        "VpcExposeNat.config",
        Reach::Spans(&["masquerade", "port-forwarding", "static"]),
    ),
    (
        "VpcExposeNat.proto",
        Reach::Fixed("`Any`. No operation narrows an expose to tcp or udp."),
    ),
    (
        "VpcExposeMasquerade.idle_timeout",
        Reach::Fixed(
            "absent. `make_masquerade(None)` is the only call, so the timeout paths -- and every \
             question about a flow ageing out under a configuration that set one -- are never \
             entered.",
        ),
    ),
    (
        "VpcExposeStaticNat",
        // `Spans` of a single value rather than `Determined`: the struct carries no
        // fields, so "it exists" is the whole of what there is to observe about one.
        // Recorded this way so that the algebra ceasing to build one fails here.
        Reach::Spans(&["constructed"]),
    ),
    (
        "VpcExposePortForwarding.idle_timeout",
        Reach::Fixed(
            "absent. `make_port_forwarding(None, ..)` is the only call, for the same reason \
             `VpcExposeMasquerade.idle_timeout` is absent: the flavour is reachable now, but \
             nothing asks for a timeout, so no flow ages out under a configuration that set one.",
        ),
    ),
];

/// Every distinct value seen for each surveyed field, across every configuration surveyed.
#[derive(Default)]
struct Observed(BTreeMap<&'static str, BTreeSet<String>>);

impl Observed {
    fn note(&mut self, field: &'static str, value: impl Into<String>) {
        self.0.entry(field).or_default().insert(value.into());
    }

    /// Note a container by its size, which is the degree of freedom the container contributes.
    ///
    /// Its contents are surveyed separately where they are themselves config structs. Where they
    /// are not -- a set of prefixes -- use [`Observed::prefixes`], because there the value *is* the
    /// degree of freedom and a count would hide it.
    fn count(&mut self, field: &'static str, n: usize) {
        self.note(field, n.to_string());
    }

    /// Note a prefix set by what is in it.
    ///
    /// Both the size and the prefixes, because the two are different claims: "always exactly one"
    /// and "always the same one" fail in different places and only the second would be a
    /// canonicalisation.
    fn prefixes(&mut self, field: &'static str, set: &PrefixPortsSet) {
        let listed: Vec<String> = set
            .into_iter()
            .map(|entry| entry.prefix().to_string())
            .collect();
        self.note(field, listed.join(", "));
    }

    /// Whether anything in a prefix set names ports.
    fn ports(&mut self, field: &'static str, set: &PrefixPortsSet) {
        self.note(
            field,
            if set.into_iter().any(|entry| entry.ports().is_some()) {
                "set"
            } else {
                "unset"
            },
        );
    }
}

/// Record what one configuration has in every field of the overlay schema.
///
/// Exhaustive by construction: every struct is destructured and every enum matched without a
/// wildcard, so the schema cannot grow a field or a variant without this failing to compile.
fn survey(overlay: &Overlay, seen: &mut Observed) {
    let Overlay {
        vpc_table,
        peering_table,
    } = overlay;
    seen.count("Overlay.vpc_table", vpc_table.len());
    seen.count("Overlay.peering_table", peering_table.len());

    for vpc in vpc_table.values() {
        let Vpc {
            name,
            id,
            vni,
            interfaces,
            peerings,
        } = vpc;
        seen.note("Vpc.name", name.clone());
        seen.note("Vpc.id", id.to_string());
        seen.note("Vpc.vni", vni.as_u32().to_string());
        seen.count("Vpc.interfaces", interfaces.values().count());
        seen.count("Vpc.peerings", peerings.len());
    }

    for peering in peering_table.values() {
        let VpcPeering {
            name,
            left,
            right,
            gwgroup,
            acl,
        } = peering;
        seen.note("VpcPeering.name", name.clone());
        seen.note("VpcPeering.gwgroup", gwgroup.clone());
        seen.note(
            "VpcPeering.acl",
            if acl.is_some() { "present" } else { "absent" },
        );
        for (side, manifest) in [("VpcPeering.left", left), ("VpcPeering.right", right)] {
            seen.note(side, manifest.name.clone());
            survey_manifest(manifest, seen);
        }
    }
}

fn survey_manifest(manifest: &VpcManifest, seen: &mut Observed) {
    let VpcManifest { name, exposes } = manifest;
    seen.note("VpcManifest.name", name.clone());
    seen.count("VpcManifest.exposes", exposes.len());
    for expose in exposes {
        let VpcExpose {
            default,
            ips,
            nots,
            nat,
        } = expose;
        seen.note("VpcExpose.default", default.to_string());
        seen.prefixes("VpcExpose.ips", ips);
        seen.ports("VpcExpose.ips.ports", ips);
        seen.prefixes("VpcExpose.nots", nots);
        seen.note(
            "VpcExpose.nat",
            if nat.is_some() { "present" } else { "absent" },
        );
        if let Some(nat) = nat {
            survey_nat(nat, seen);
        }
    }
}

fn survey_nat(nat: &VpcExposeNat, seen: &mut Observed) {
    let VpcExposeNat {
        as_range,
        not_as,
        config,
        proto,
    } = nat;
    seen.prefixes("VpcExposeNat.as_range", as_range);
    seen.ports("VpcExposeNat.as_range.ports", as_range);
    seen.prefixes("VpcExposeNat.not_as", not_as);
    seen.note(
        "VpcExposeNat.proto",
        match proto {
            L4Protocol::Tcp => "tcp",
            L4Protocol::Udp => "udp",
            L4Protocol::Any => "any",
        },
    );
    match config {
        VpcExposeNatConfig::Masquerade(VpcExposeMasquerade { idle_timeout }) => {
            seen.note("VpcExposeNat.config", "masquerade");
            seen.note(
                "VpcExposeMasquerade.idle_timeout",
                if idle_timeout.is_some() {
                    "present"
                } else {
                    "absent"
                },
            );
        }
        VpcExposeNatConfig::Static(VpcExposeStaticNat {}) => {
            seen.note("VpcExposeNat.config", "static");
            seen.note("VpcExposeStaticNat", "constructed");
        }
        VpcExposeNatConfig::PortForwarding(VpcExposePortForwarding { idle_timeout }) => {
            seen.note("VpcExposeNat.config", "port-forwarding");
            seen.note(
                "VpcExposePortForwarding.idle_timeout",
                if idle_timeout.is_some() {
                    "present"
                } else {
                    "absent"
                },
            );
        }
    }
}

/// Configurations drawn for the census.
///
/// Enough that a field the generator reaches only occasionally is still reached. The whole draw is
/// pure -- fold, assemble, walk -- so this is cheap next to anything that lowers a configuration
/// into tables.
const CASES: usize = 512;

/// Survey `CASES` drawn configurations into `seen`.
///
/// Returns nothing and fills a borrowed accumulator, because `bolero::check!` expands to a bare
/// `return` and so cannot appear in a function with a return type.
fn survey_drawn(seen: &RefCell<Observed>) {
    // `bolero` runs each case behind `catch_unwind`, across which a `RefCell` may not be borrowed.
    // Asserted rather than avoided: the accumulator is a map of strings with no invariant to break,
    // so the worst a panic mid-draw can leave is a partly filled census -- and the panic fails the
    // test that would have read it.
    let seen = std::panic::AssertUnwindSafe(seen);
    bolero::check!()
        .with_generator(Sequence::default())
        .with_iterations(CASES)
        .for_each(|ops| {
            let overlay = Sequence::fold(ops)
                .overlay()
                .unwrap_or_else(|e| panic!("{ops:?} does not assemble: {e}"));
            survey(&overlay, &mut seen.borrow_mut());
        });
}

/// What `CASES` drawn configurations exhibit.
fn census() -> Observed {
    let seen = RefCell::new(Observed::default());
    survey_drawn(&seen);
    seen.into_inner()
}

/// Every field [`survey`] visits has a verdict, and every verdict names a field it visits.
///
/// Half the ratchet. The compiler enforces that a new field is *surveyed*; this enforces that a
/// surveyed field is *classified*, and that a verdict left behind by a deleted field is removed.
#[test]
fn every_surveyed_field_is_classified() {
    let seen = census();
    let surveyed: BTreeSet<&str> = seen.0.keys().copied().collect();
    let classified: BTreeSet<&str> = REACH.iter().map(|(field, _)| *field).collect();

    let unclassified: Vec<&&str> = surveyed.difference(&classified).collect();
    assert!(
        unclassified.is_empty(),
        "the survey records fields with no verdict in `REACH`: {unclassified:?}. A field added to \
         the overlay schema is not reachable by the algebra until an operation produces it, so say \
         which it is -- `Fixed` is a perfectly good answer and is what most of the table already \
         says."
    );

    // Only the ones a drawn configuration can never exhibit: a `Fixed` verdict saying a variant is
    // never constructed is a claim about something the survey cannot see, so it has nothing to
    // reconcile against.
    let unreachable_by_construction: BTreeSet<&str> = REACH
        .iter()
        .filter(
            |(_, reach)| matches!(reach, Reach::Fixed(why) if why.contains("never constructed")),
        )
        .map(|(field, _)| *field)
        .collect();
    let missing: Vec<&&str> = classified
        .difference(&surveyed)
        .filter(|field| !unreachable_by_construction.contains(**field))
        .collect();
    assert!(
        missing.is_empty(),
        "`REACH` gives a verdict for fields the survey never records: {missing:?}. Either the \
         field was removed from the schema, or the survey stopped visiting it -- and a survey that \
         has stopped visiting a field is a ratchet that has come loose."
    );
}

/// The algebra reaches exactly what it is recorded to reach, measured over drawn configurations.
///
/// The other half. Each verdict predicts something falsifiable about the observed values, and this
/// is the fuzzer's statistical support for the whole record:
///
/// - `Spans` predicts the observed set is *exactly* the listed one. Short of a value is a
///   generator that stopped exploring; beyond it is a record left behind by a vocabulary that grew.
/// - `Determined` predicts more than one value, because a field that is a function of the handles
///   varies as the handles do. It does **not** predict which -- that claim is the doc string's,
///   and it is not checkable from here.
/// - `Derived` predicts nothing about the count. It is filled in downstream of the algebra, so
///   whatever it holds is not evidence about the algebra's reach either way.
/// - `Fixed` predicts exactly one value, which is the sharpest prediction in the table and the one
///   worth having: it is the gap list, and a gap that quietly closes should be recorded rather
///   than discovered again later.
#[test]
fn the_algebra_reaches_what_it_is_recorded_to_reach() {
    let seen = census();

    for (field, reach) in REACH {
        let Some(values) = seen.0.get(field) else {
            // Reconciled by the test above; nothing to measure here.
            continue;
        };
        let rendered: Vec<&str> = values.iter().map(String::as_str).collect();
        match reach {
            Reach::Spans(expected) => assert_eq!(
                rendered, *expected,
                "`{field}` is recorded as spanning {expected:?} and {CASES} drawn configurations \
                 show {rendered:?}"
            ),
            Reach::Determined(by) => assert!(
                values.len() > 1,
                "`{field}` is recorded as determined by {by}, which varies, and yet {CASES} drawn \
                 configurations all show {rendered:?}. Either it is fixed after all, or the \
                 generator has stopped varying what determines it"
            ),
            Reach::Derived(_) => {}
            Reach::Fixed(why) => assert_eq!(
                values.len(),
                1,
                "`{field}` is recorded as fixed -- {why} -- and yet {CASES} drawn configurations \
                 show {rendered:?}. If the vocabulary grew, say so here: this table is what tells \
                 a reader of a green run which configurations it did not cover"
            ),
        }
    }
}

/// What the algebra reaches and what it does not, printed rather than asserted.
///
/// Not a test of the code; a test that *reports*. The gap list is the answer to "what does a green
/// fuzzing run over this algebra not tell you", and it belongs somewhere a person will actually
/// read rather than only in a table that is consulted when something breaks.
#[test]
fn report_what_the_algebra_reaches() {
    let counted = |wanted: fn(&Reach) -> bool| -> usize {
        REACH.iter().filter(|(_, reach)| wanted(reach)).count()
    };
    eprintln!(
        "of {} degrees of freedom in the overlay schema, the algebra spans {}, determines {}, \
         leaves {} to be derived, and fixes {}:",
        REACH.len(),
        counted(|reach| matches!(reach, Reach::Spans(_))),
        counted(|reach| matches!(reach, Reach::Determined(_))),
        counted(|reach| matches!(reach, Reach::Derived(_))),
        counted(|reach| matches!(reach, Reach::Fixed(_))),
    );
    for (field, reach) in REACH {
        match reach {
            Reach::Spans(values) => eprintln!("  spans      {field}: {values:?}"),
            Reach::Determined(by) => eprintln!("  determined {field}: by {by}"),
            Reach::Derived(how) => eprintln!("  derived    {field}: {how}"),
            Reach::Fixed(why) => eprintln!("  FIXED      {field}: {why}"),
        }
    }
}
