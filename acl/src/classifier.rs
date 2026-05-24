// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Classifier -- the consumer-facing wrapper around the ACL cascade.
//!
//! Most code outside this crate should program against [`Classifier`]
//! rather than reaching into the cascade machinery directly.  The
//! cascade is plumbing; the classifier is the API.
//!
//! # Usage
//!
//! ```ignore
//! let classifier = Classifier::new(Action::Drop);  // default = deny
//!
//! classifier.install(AclRule::new(
//!     Priority(100),
//!     Match { dst_port: Some(80), ..Match::any() },
//!     Action::Allow,
//! ));
//! // `generation` comes from the pipeline manager's policy-gen allocator
//! // in production; tests carry a small local counter.
//! classifier.rotate(generation);  // make the install visible to readers
//!
//! let outcome: Action = classifier.classify(&headers);
//! ```
//!
//! # Removal semantics
//!
//! Removal is intentionally not exposed as a single method.  Per the
//! cascade design conversation, removing a rule from an ACL requires
//! synthesising a shadow rule that takes the default action at a
//! precedence that beats the rule being removed.  This logic
//! belongs in user code (where the default action is known) rather
//! than baked into the cascade or the classifier.  A future helper
//! may compose [`Classifier::snapshot`] and [`Classifier::install`]
//! to give a turnkey \"remove by priority\" operation; we are
//! deferring it until a real consumer demonstrates the shape it
//! wants.

use cascade::{Cascade, Generation, Snapshot};

use crate::layers::{AclFrozen, AclHead, AclOp, AclTail};
use crate::types::{AclRule, Action, Headers};

/// The consumer-facing ACL classifier.
///
/// Wraps a [`Cascade<AclHead, AclFrozen, AclTail>`] and adds the
/// ACL-specific surface: classify-by-headers, install, default
/// action, etc.
pub struct Classifier {
    cascade: Cascade<AclHead, AclFrozen, AclTail>,
    /// The action to apply when no rule matches.  Captured at
    /// construction; not mutable, because changing the default
    /// fate of an in-flight classifier is a semantically loaded
    /// operation that warrants its own API rather than a setter.
    default_action: Action,
}

impl Classifier {
    /// Construct a classifier with no rules and the given default
    /// action for packets that do not match any rule.
    #[must_use]
    pub fn new(default_action: Action) -> Self {
        Self {
            cascade: Cascade::new(AclHead::empty(), AclTail::empty()),
            default_action,
        }
    }

    /// The default action returned by [`classify`](Self::classify)
    /// for packets that do not match any rule.
    #[must_use]
    pub fn default_action(&self) -> Action {
        self.default_action
    }

    /// Classify a packet against the cascade.
    ///
    /// Walks head -> sealed -> tail and returns the matched rule's
    /// action, or the classifier's default action if no rule matches.
    ///
    /// Note: rules installed via [`install`](Self::install) are NOT
    /// visible until the next [`rotate`](Self::rotate).  This is a
    /// deliberate trade in the cascade design: the head's lookup
    /// returns Continue so that head writes do not contend on the
    /// read path.  Callers who want read-after-write within the
    /// same task should call `rotate` immediately after `install`.
    #[must_use]
    pub fn classify(&self, headers: &Headers) -> Action {
        self.cascade
            .snapshot()
            .lookup(headers)
            .map_or(self.default_action, |rule| rule.action)
    }

    /// Install a rule into the head buffer.
    ///
    /// Becomes visible to readers after the next
    /// [`rotate`](Self::rotate).  Concurrent installs at the same
    /// priority resolve via last-writer-wins (see the per-key
    /// `Upsert` impl on `AclRule`).
    pub fn install(&self, rule: AclRule) {
        self.cascade.write(AclOp::Install(rule));
    }

    /// Seal the current head into a sealed layer tagged with
    /// `generation` and install a fresh empty head.
    ///
    /// After this returns, rules installed prior to the call are
    /// visible to [`classify`](Self::classify); rules installed
    /// concurrently with this call may or may not be captured.
    ///
    /// `generation` is supplied by the caller (in production, the
    /// pipeline manager's policy-gen allocator).  Frozen layers in
    /// the cascade carry this generation so that
    /// [`Snapshot::lookup_at`](cascade::Snapshot::lookup_at) can
    /// filter the walk by horizon for per-packet-consistent slow-
    /// path classification.
    pub fn rotate(&self, generation: Generation) {
        self.cascade.rotate(generation, AclHead::empty);
    }

    /// Fold older sealed layers into the tail.
    ///
    /// `keep` sealed layers are retained at the front of the
    /// sealed vector; the rest are merged into the tail.  Passing
    /// `keep = 1` matches the cascade-depth-of-two invariant we
    /// want on the read hot path.
    ///
    /// For consumers requiring per-packet consistency with hardware
    /// offload, prefer [`compact_through`](Self::compact_through).
    pub fn compact(&self, keep: usize) {
        self.cascade.compact(keep);
    }

    /// Fold every frozen layer with `generation <= watermark` into
    /// the tail.
    ///
    /// Pass-through to
    /// [`Cascade::compact_through`](cascade::Cascade::compact_through).
    /// Used by per-packet-consistent consumers: the manager
    /// aggregates subscriber watermarks (e.g. "I have drained past
    /// generation N" from the hardware-offload programmer) and
    /// supplies the minimum as the watermark here.
    pub fn compact_through(&self, watermark: Generation) {
        self.cascade.compact_through(watermark);
    }

    /// Number of sealed layers currently in the cascade.  Diagnostic.
    #[must_use]
    pub fn frozen_depth(&self) -> usize {
        self.cascade.frozen_depth()
    }

    /// Take a snapshot of the classifier.
    ///
    /// Exposed for callers that need to walk the cascade
    /// themselves (typically to synthesise removal-shadow rules
    /// using existing rule contents, or to enumerate the active
    /// rule set for diagnostics).  Most callers should use
    /// [`classify`](Self::classify) instead.
    #[must_use]
    pub fn snapshot(&self) -> Snapshot<AclHead, AclFrozen, AclTail> {
        self.cascade.snapshot()
    }
}
