// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Trace capture that only speaks when something has already gone wrong.
//!
//! A test installs a [`Recording`] on its own thread, runs whatever it was going to run, and
//! forgets about it. Nothing is printed. If the test then panics, the recording notices on the way
//! out and dumps the spans and events that led up to it.
//!
//! That is the whole feature, and the restraint is the point.
//!
//! # Why there is no way to read what was captured
//!
//! The obvious next step -- let the test ask what was traced and assert on it -- is deliberately
//! not offered, and this module is shaped so that it cannot be bolted on from outside.
//!
//! Two reasons, and the first is the repo's own rule. `nat::masquerade::probe` states it as a
//! prerequisite: *"Projections, not state. Nothing here inspects the allocator or the flow table.
//! Every assertion is over what came out of the pipeline."* The design note in
//! `development/code/config-algebra-testing.md` says the same thing about configuration:
//! state the property over the observable projection, never over raw state. A trace statement is
//! internal state of the most volatile kind -- it is the line every refactor rewrites and nobody
//! thinks twice about deleting.
//!
//! The second reason is the build. The workspace sets `release_max_level_debug`, so `trace!` and
//! `#[instrument(level = "trace")]` are compiled out of release entirely. An assertion resting on
//! them could only hold in a binary that does not ship, which makes it a claim about a different
//! program than the one under test.
//!
//! So: evidence, never an oracle. The test the mechanism is scoped correctly is that **removing
//! every `Recording` must not change a single pass or fail**.
//!
//! # What it captures, and what it costs
//!
//! Spans as they open, events as they fire, both flattened to a line at capture time and held in a
//! bounded ring. Nothing is formatted for output until a dump actually happens, and on a passing
//! test that is never.
//!
//! Fields are read through [`tracing::field::Visit`]'s typed methods -- `record_u64`, `record_str`,
//! `record_bool` and the rest -- rather than falling back to `Debug` for everything. That is also
//! the answer to whether structured capture needs the `valuable` crate: it does not, unless the
//! fields are nested structs. `valuable` is gated behind the `tracing_unstable` cfg, which is a
//! *global* rustflag and so invalidates the build cache for the entire workspace. Keeping probe
//! fields scalar avoids the question.
//!
//! # Threads
//!
//! A recording is installed with [`tracing::subscriber::set_default`], which is **per thread**. A
//! worker thread that wants its own trace kept has to take out its own recording; one held by the
//! thread that spawned it will capture nothing the worker does. That is a deliberate consequence of
//! not touching the global default, which would collide with `tracing_test` and with anything a
//! binary installs for itself.
//!
//! It also gives the behaviour you want out of a panicking worker: the recording dumps on the
//! thread that failed, holding that thread's trace, rather than a merged log of everybody.
//!
//! # Under a model checker this does nothing, and cannot
//!
//! A recording installs itself with [`tracing::subscriber::set_default`], which keeps the scoped
//! dispatcher in a thread-local `RefCell`. Loom and shuttle do not use OS threads: their tasks are
//! continuations multiplexed onto one, so every task shares that thread-local. Two tasks each
//! taking out a recording then swap the same `RefCell` underneath each other, and `tracing-core`
//! panics with `RefCell already borrowed` from inside its own dispatcher -- turning a passing
//! property into a failure that has nothing to do with the code under test.
//!
//! Measured, not deduced: adding recordings to the two-worker properties in
//! `dataplane::packet_processor::fuzz::model` turned a 2 second green run into a 52 second failure
//! at `tracing-core-0.1.36/src/dispatcher.rs:845`.
//!
//! So under those backends [`Capture::start`] installs nothing and the recording stays empty. Very
//! little is lost. A model checker hands back a *replayable schedule*, which is a better artefact
//! than a trace: it reproduces the failure rather than describing one run of it. Trace evidence is
//! for the backends that have no such thing -- ordinary test runs, and the sanitizer builds.
//!
//! The buffer is a plain [`std::sync::Mutex`] rather than the workspace facade for a related
//! reason: the facade's primitives are instrumented under those backends, and a diagnostic that
//! joined the schedule under test would perturb what it is meant to report on.

// The buffer is `std::sync` on purpose -- see "Model checkers" above. `disallowed_types` exists to
// stop that happening by accident, and here it is the whole point: a diagnostic that joined the
// schedule under test would perturb what it is meant to report on.
#![allow(clippy::disallowed_types)]

use std::collections::VecDeque;
use std::fmt;
use std::fmt::Write as _;
use std::sync::Arc;

use tracing::field::{Field, Visit};
use tracing::span::Attributes;
use tracing::subscriber::DefaultGuard;
use tracing::{Event, Id, Level, Metadata, Subscriber};
use tracing_subscriber::layer::{Context, Layer, SubscriberExt};
use tracing_subscriber::registry::LookupSpan;

/// Lines kept before the oldest are dropped.
///
/// A packet through the whole pipeline is a few dozen lines at trace level, so this holds several
/// packets' worth. Large enough that the interesting part is still there when a burst fails, small
/// enough that a fuzz property running thousands of cases does not accumulate.
pub const DEFAULT_DEPTH: usize = 512;

/// One captured span or event, flattened at capture time.
struct Line {
    level: Level,
    target: &'static str,
    kind: Kind,
    /// The enclosing span names, outermost first, already joined.
    scope: String,
    message: String,
    fields: String,
    /// How many times this line occurred in a row. See [`Log::push`].
    repeats: usize,
}

impl Line {
    /// Everything except the count, which is what makes two occurrences the *same* line.
    fn same_as(&self, other: &Self) -> bool {
        self.level == other.level
            && self.target == other.target
            && self.kind == other.kind
            && self.scope == other.scope
            && self.message == other.message
            && self.fields == other.fields
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// A span opening. Its name is the last element of `scope`.
    Span,
    Event,
}

impl fmt::Display for Line {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let marker = match self.kind {
            Kind::Span => "span",
            Kind::Event => "    ",
        };
        write!(f, "{marker} {:>5} {}", self.level, self.target)?;
        if !self.scope.is_empty() {
            write!(f, " [{}]", self.scope)?;
        }
        if !self.message.is_empty() {
            write!(f, ": {}", self.message)?;
        }
        if !self.fields.is_empty() {
            write!(f, " {{{}}}", self.fields)?;
        }
        if self.repeats > 1 {
            write!(f, "  (x{})", self.repeats)?;
        }
        Ok(())
    }
}

/// The ring, plus what it has had to throw away.
struct Log {
    lines: VecDeque<Line>,
    depth: usize,
    dropped: usize,
}

impl Log {
    /// Append, collapsing a run of identical lines into a count.
    ///
    /// Not cosmetic. The ring is the scarce resource, and a stage that emits the same line per
    /// packet -- `Dropping TestBuffer`, say -- will otherwise evict everything that explains the
    /// failure before anyone reads it.
    fn push(&mut self, line: Line) {
        if let Some(last) = self.lines.back_mut()
            && last.same_as(&line)
        {
            last.repeats += 1;
            return;
        }
        if self.lines.len() == self.depth {
            self.lines.pop_front();
            self.dropped += 1;
        }
        self.lines.push_back(line);
    }
}

/// Reads a span's or event's fields without going through `Debug` for the ones that have a type.
///
/// The `record_*` methods below are what makes this structured capture rather than string
/// scraping, and they are why the `valuable` crate is not needed here. `record_debug` is the
/// fallback for everything that really is only `Debug`.
#[derive(Default)]
struct Fields {
    message: String,
    rest: String,
}

/// Longest a single field's rendering may be before it is cut short.
///
/// Not tidiness. `#[tracing::instrument]` captures every argument it is not told to skip, and on
/// the packet path that means whole `Packet` and `Ingress` values -- several kilobytes of `Debug`
/// per span, which buries the two lines that say where a packet actually went. A dump is for
/// reading; anything past this is not being read.
///
/// The right fix at the *source* is `skip(self, packet)` on those annotations. This is the
/// backstop, because a diagnostic that depends on every annotation in the tree being well behaved
/// is a diagnostic that will be unreadable exactly when it is needed.
const FIELD_LIMIT: usize = 160;

/// Append `value`, cut to [`FIELD_LIMIT`] on a character boundary.
fn push_clipped(out: &mut String, value: &dyn fmt::Display) {
    let rendered = value.to_string();
    if rendered.len() <= FIELD_LIMIT {
        out.push_str(&rendered);
        return;
    }
    let cut = rendered
        .char_indices()
        .map(|(at, _)| at)
        .take_while(|at| *at <= FIELD_LIMIT)
        .last()
        .unwrap_or(0);
    out.push_str(&rendered[..cut]);
    let _ = write!(out, "...<{} more bytes>", rendered.len() - cut);
}

impl Fields {
    fn put(&mut self, field: &Field, value: &dyn fmt::Display) {
        // `tracing` carries an event's message as a field named `message`, which reads far better
        // on its own than as one more `k=v`.
        if field.name() == "message" {
            push_clipped(&mut self.message, value);
            return;
        }
        if !self.rest.is_empty() {
            self.rest.push(' ');
        }
        let _ = write!(self.rest, "{}=", field.name());
        push_clipped(&mut self.rest, value);
    }
}

impl Visit for Fields {
    fn record_f64(&mut self, field: &Field, value: f64) {
        self.put(field, &value);
    }
    fn record_i64(&mut self, field: &Field, value: i64) {
        self.put(field, &value);
    }
    fn record_u64(&mut self, field: &Field, value: u64) {
        self.put(field, &value);
    }
    fn record_i128(&mut self, field: &Field, value: i128) {
        self.put(field, &value);
    }
    fn record_u128(&mut self, field: &Field, value: u128) {
        self.put(field, &value);
    }
    fn record_bool(&mut self, field: &Field, value: bool) {
        self.put(field, &value);
    }
    fn record_str(&mut self, field: &Field, value: &str) {
        self.put(field, &value);
    }
    fn record_error(&mut self, field: &Field, value: &(dyn std::error::Error + 'static)) {
        self.put(field, &value);
    }
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        self.put(field, &format_args!("{value:?}"));
    }
}

/// Targets whose trace is machinery rather than evidence, and is excluded by default.
///
/// Shuttle is the one that forces the issue. Under the model checker its own scheduling trace runs
/// to thousands of lines per execution -- every `try_with`, every semaphore poll -- and it will
/// evict the entire dataplane trace from the ring before anyone reads it. Measured: the first dump
/// from `packet_processor::fuzz::model` was a dozen dataplane lines followed by nothing but
/// `shuttle::runtime::execution`.
///
/// Matched as prefixes, so `shuttle` covers `shuttle::sync::mutex` and the rest.
pub const MACHINERY: &[&str] = &["shuttle", "tokio", "runtime", "mio", "hyper"];

/// Whether a target's trace is kept.
type Keep = Arc<dyn Fn(&str) -> bool + Send + Sync>;

concurrency::with_std! {
    /// Whether a recording can install itself on this backend. See the module docs.
    const RECORDS: bool = true;

    // The `Option` is uniform across backends rather than convenient here: the model-checker arms
    // have nothing to return.
    #[allow(clippy::unnecessary_wraps)]
    fn install<S: Subscriber + Send + Sync + 'static>(subscriber: S) -> Option<DefaultGuard> {
        Some(tracing::subscriber::set_default(subscriber))
    }
}

concurrency::with_loom! {
    /// See the module docs: loom's tasks share one OS thread, and so share the thread-local the
    /// scoped dispatcher lives in.
    const RECORDS: bool = false;

    fn install<S: Subscriber + Send + Sync + 'static>(_subscriber: S) -> Option<DefaultGuard> {
        None
    }
}

concurrency::with_shuttle! {
    /// See the module docs: shuttle's tasks share one OS thread, and so share the thread-local the
    /// scoped dispatcher lives in.
    const RECORDS: bool = false;

    fn install<S: Subscriber + Send + Sync + 'static>(_subscriber: S) -> Option<DefaultGuard> {
        None
    }
}

/// The layer itself. Not public: a recording is the only way to get one, so it cannot be installed
/// globally by accident.
struct EvidenceLayer {
    // nosemgrep: rust-no-direct-std-sync-import
    log: Arc<std::sync::Mutex<Log>>,
    keep: Keep,
}

impl EvidenceLayer {
    fn push(&self, line: Line) {
        // A poisoned diagnostic buffer is not worth a second panic during the first one.
        if let Ok(mut log) = self.log.lock() {
            log.push(line);
        }
    }
}

/// The enclosing span names, outermost first.
fn scope_of<S>(ctx: &Context<'_, S>, event: Option<&Event<'_>>, id: Option<&Id>) -> String
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    let scope = match (event, id) {
        (Some(event), _) => ctx.event_scope(event).map(from_root),
        (None, Some(id)) => ctx.span_scope(id).map(from_root),
        (None, None) => None,
    };
    scope.unwrap_or_default()
}

/// `Scope` iterates innermost-first; a reader wants the other order.
fn from_root<'a, S>(scope: tracing_subscriber::registry::Scope<'a, S>) -> String
where
    S: Subscriber + for<'lookup> LookupSpan<'lookup>,
{
    let mut names: Vec<&str> = scope.map(|span| span.name()).collect();
    names.reverse();
    names.join(" > ")
}

impl<S> Layer<S> for EvidenceLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    /// Rejected here rather than in `on_event`, so a filtered-out callsite costs a prefix
    /// comparison instead of a formatted line.
    fn enabled(&self, metadata: &Metadata<'_>, _ctx: Context<'_, S>) -> bool {
        (self.keep)(metadata.target())
    }

    fn on_new_span(&self, attrs: &Attributes<'_>, id: &Id, ctx: Context<'_, S>) {
        let mut fields = Fields::default();
        attrs.record(&mut fields);
        let metadata = attrs.metadata();
        self.push(Line {
            level: *metadata.level(),
            target: metadata.target(),
            kind: Kind::Span,
            scope: scope_of(&ctx, None, Some(id)),
            message: fields.message,
            fields: fields.rest,
            repeats: 1,
        });
    }

    fn on_event(&self, event: &Event<'_>, ctx: Context<'_, S>) {
        let mut fields = Fields::default();
        event.record(&mut fields);
        let metadata = event.metadata();
        self.push(Line {
            level: *metadata.level(),
            target: metadata.target(),
            kind: Kind::Event,
            scope: scope_of(&ctx, Some(event), None),
            message: fields.message,
            fields: fields.rest,
            repeats: 1,
        });
    }
}

/// A trace recording for the current thread, which reports itself if the thread panics.
///
/// Hold it for as long as the work you might need to explain. Dropping it normally discards
/// everything; dropping it while unwinding prints it.
#[must_use = "a recording that is dropped immediately captures nothing"]
pub struct Recording {
    // nosemgrep: rust-no-direct-std-sync-import
    log: Arc<std::sync::Mutex<Log>>,
    label: String,
    /// Restores the previous thread-local subscriber. Declared last so the recording is still the
    /// installed subscriber for as long as the fields above it are alive. `None` under a model
    /// checker, where nothing was installed -- see the module docs.
    _installed: Option<DefaultGuard>,
}

/// Start recording on this thread, keeping everything but [`MACHINERY`].
///
/// `label` names the recording in the dump, for a failure that happens on one of several threads.
/// Use [`Capture`] to change the depth or the filter.
#[must_use = "a recording that is dropped immediately captures nothing"]
pub fn capture(label: impl Into<String>) -> Recording {
    Capture::new(label).start()
}

/// How a [`Recording`] is configured, for the cases the [`capture`] shorthand does not cover.
///
/// ```no_run
/// # use dataplane_tracectl::evidence::Capture;
/// let _evidence = Capture::new("worker-0")
///     .depth(64)
///     .keeping(|target| target.starts_with("dataplane_nat"))
///     .start();
/// ```
pub struct Capture {
    label: String,
    depth: usize,
    keep: Keep,
}

impl Capture {
    /// A capture of everything but [`MACHINERY`], at [`DEFAULT_DEPTH`].
    #[must_use]
    pub fn new(label: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            depth: DEFAULT_DEPTH,
            keep: Arc::new(|target: &str| !MACHINERY.iter().any(|noisy| target.starts_with(noisy))),
        }
    }

    /// How many lines to keep before the oldest is dropped.
    #[must_use]
    pub fn depth(mut self, depth: usize) -> Self {
        self.depth = depth.max(1);
        self
    }

    /// Keep only the targets `keep` accepts, replacing the default filter.
    ///
    /// Narrowing to the crates under test is worth doing when a dump is hard to read: the ring is
    /// the scarce resource, and every line excluded here is one something useful can occupy.
    #[must_use]
    pub fn keeping(mut self, keep: impl Fn(&str) -> bool + Send + Sync + 'static) -> Self {
        self.keep = Arc::new(keep);
        self
    }

    /// Install it on this thread.
    #[must_use = "a recording that is dropped immediately captures nothing"]
    pub fn start(self) -> Recording {
        let empty = Log {
            lines: VecDeque::new(),
            depth: self.depth,
            dropped: 0,
        };
        // nosemgrep: rust-no-direct-std-sync-import
        let log = Arc::new(std::sync::Mutex::new(empty));
        let subscriber = tracing_subscriber::registry().with(EvidenceLayer {
            log: log.clone(),
            keep: self.keep,
        });
        Recording {
            log,
            label: self.label,
            _installed: install(subscriber),
        }
    }
}

/// A dump handle that outlives the [`Recording`] it came from, and can cross a thread boundary.
///
/// The case this exists for: a worker thread records, finishes, and the assertion about what it did
/// is made by the thread that joined it. By then the worker's recording has been dropped without
/// panicking, so it discarded everything -- and the trace that would explain the failure is exactly
/// the one that is gone. An `Evidence` keeps the buffer alive past its recording and lets whoever
/// does the asserting ask for it.
///
/// It can only dump. There is still no way to read the trace back into the program, for the reasons
/// in the module docs.
#[derive(Clone)]
pub struct Evidence {
    // nosemgrep: rust-no-direct-std-sync-import
    log: Arc<std::sync::Mutex<Log>>,
    label: String,
}

impl Evidence {
    /// Print what was captured, to stderr.
    pub fn dump(&self) {
        let Ok(log) = self.log.lock() else {
            eprintln!("==== trace evidence ({}): buffer poisoned ====", self.label);
            return;
        };
        if log.lines.is_empty() {
            let why = if RECORDS {
                "Either the code under test emits no spans or events, or the level filter is above \
                 them, or the targets were excluded -- see MACHINERY. Note that \
                 `release_max_level_debug` compiles `trace!` out of release builds altogether, and \
                 that a recording only sees the thread it was created on."
            } else {
                "This is a model-checker build, where a recording deliberately installs nothing: \
                 loom and shuttle multiplex their tasks onto one OS thread and would corrupt the \
                 thread-local the scoped dispatcher lives in. Use the replayable schedule the \
                 backend printed instead. See this module's docs."
            };
            eprintln!(
                "==== trace evidence ({}): nothing captured ====\n{why}",
                self.label
            );
            return;
        }
        eprintln!("==== trace evidence ({}) ====", self.label);
        if log.dropped > 0 {
            eprintln!("[{} earlier lines dropped by the ring]", log.dropped);
        }
        for line in &log.lines {
            eprintln!("{line}");
        }
        eprintln!("==== end trace evidence ({}) ====", self.label);
    }
}

/// Dump `evidence` if the current thread panics before the returned guard goes out of scope.
///
/// For the shape [`Evidence`] describes: collect the workers' handles, hold one of these across the
/// assertions that judge them, and a failure explains itself without the passing case printing
/// anything.
#[must_use = "the guard must outlive the assertions it is meant to explain"]
pub fn dump_on_panic(evidence: Vec<Evidence>) -> impl Sized {
    struct OnPanic(Vec<Evidence>);
    impl Drop for OnPanic {
        fn drop(&mut self) {
            if std::thread::panicking() {
                for evidence in &self.0 {
                    evidence.dump();
                }
            }
        }
    }
    OnPanic(evidence)
}

impl Recording {
    /// A handle that can dump this recording later, from any thread.
    #[must_use]
    pub fn evidence(&self) -> Evidence {
        Evidence {
            log: self.log.clone(),
            label: self.label.clone(),
        }
    }

    /// Print what has been captured, to stderr.
    ///
    /// Called for you when the thread is panicking. Public so a test that has decided to fail for
    /// its own reasons can ask for the trace before it does.
    pub fn dump(&self) {
        self.evidence().dump();
    }

    /// How many lines are held.
    ///
    /// `#[cfg(test)]`, so it is reachable from this module's own tests and from nowhere else. The
    /// module docs explain why the public surface stops at [`Recording::dump`]; a crate-private
    /// accessor does not reopen that, because no other crate can see it.
    #[cfg(test)]
    fn len(&self) -> usize {
        self.log.lock().map_or(0, |log| log.lines.len())
    }

    /// The captured lines as they would be printed. `#[cfg(test)]` for the same reason as
    /// [`Recording::len`].
    #[cfg(test)]
    fn rendered(&self) -> Vec<String> {
        self.log.lock().map_or_else(
            |_| Vec::new(),
            |log| log.lines.iter().map(ToString::to_string).collect(),
        )
    }
}

impl Drop for Recording {
    fn drop(&mut self) {
        if std::thread::panicking() {
            self.dump();
        }
    }
}

#[cfg(test)]
#[cfg(not(any(feature = "loom", feature = "shuttle")))]
mod tests {
    use super::*;

    #[test]
    fn a_recording_captures_events_on_its_own_thread() {
        let recording = capture("own thread");
        tracing::error!(port = 8080_u64, "a thing happened");
        assert_eq!(recording.len(), 1, "the event was not captured");
    }

    #[test]
    fn a_recording_captures_spans_and_the_events_inside_them() {
        let recording = capture("spans");
        let span = tracing::error_span!("outer", vni = 100_u64);
        let _entered = span.enter();
        tracing::error!("inside");
        assert_eq!(recording.len(), 2, "expected the span and the event");
    }

    /// The ring bounds what is held, so a long-running property cannot accumulate.
    #[test]
    fn the_ring_drops_the_oldest() {
        let recording = Capture::new("bounded").depth(4).start();
        for n in 0..10_u64 {
            tracing::error!(n, "line");
        }
        assert_eq!(recording.len(), 4, "the ring did not bound itself");
    }

    /// A recording is per thread, which is the property the multi-worker harnesses rely on.
    ///
    /// Asserted rather than assumed because getting it backwards would be silent: a harness that
    /// took one recording on the spawning thread would dump an empty buffer for a worker failure
    /// and look like the mechanism was broken.
    #[test]
    fn a_recording_does_not_capture_another_thread() {
        let recording = capture("this thread");
        std::thread::scope(|scope| {
            scope.spawn(|| tracing::error!("from elsewhere"));
        });
        assert_eq!(recording.len(), 0, "a recording reached across a thread");
    }

    /// Typed fields do not go through `Debug`, which is what makes this structured capture.
    ///
    /// The discriminator is the string field: `record_debug` on a `&str` renders it with quotes,
    /// `record_str` does not. A test that only counted lines would pass either way, which is why
    /// this one reads the rendering.
    ///
    /// It is also the evidence for the claim in the module docs that structured capture here does
    /// not need the `valuable` crate, and therefore does not need the `tracing_unstable` rustflag.
    #[test]
    fn a_scalar_field_is_read_as_a_scalar() {
        let recording = capture("typed");
        tracing::error!(port = 8080_u64, name = "eth0", up = true, "hello");
        let rendered = recording.rendered().join("\n");

        assert!(rendered.contains("port=8080"), "u64 field: {rendered}");
        assert!(
            rendered.contains("name=eth0"),
            "a str field went through the `Debug` fallback: {rendered}"
        );
        assert!(rendered.contains("up=true"), "bool field: {rendered}");
        assert!(
            rendered.contains(": hello"),
            "the message was not lifted out of the fields: {rendered}"
        );
    }

    /// Machinery is excluded by default, or the ring fills with it.
    ///
    /// The failure this prevents is not hypothetical: see [`MACHINERY`] for what the first dump
    /// out of the model-checked pipeline harness actually looked like.
    #[test]
    fn machinery_is_not_evidence() {
        let recording = capture("filtered");
        tracing::error!(target: "shuttle::runtime::execution", "scheduling decision");
        tracing::error!(target: "dataplane_nat::masquerade", "allocated");
        assert_eq!(recording.len(), 1, "the machinery target was captured");
    }

    /// A caller can narrow past the default.
    #[test]
    fn a_capture_can_be_narrowed_to_one_crate() {
        let recording = Capture::new("narrow")
            .keeping(|target| target.starts_with("dataplane_nat"))
            .start();
        tracing::error!(target: "dataplane_net::packet", "dropping");
        tracing::error!(target: "dataplane_nat::masquerade", "allocated");
        assert_eq!(recording.len(), 1, "the filter did not narrow");
    }

    /// A repeated line is counted, not repeated, so one chatty stage cannot evict the ring.
    ///
    /// Break test: remove the collapse in `Log::push` and this reports 4 rather than 1, which is
    /// exactly the behaviour that made the first real dump unreadable.
    #[test]
    fn a_run_of_identical_lines_collapses() {
        let recording = Capture::new("repeats").depth(8).start();
        for _ in 0..4 {
            tracing::error!(target: "dataplane_net::buffer", "Dropping TestBuffer");
        }
        assert_eq!(recording.len(), 1, "identical lines were not collapsed");
        assert!(
            recording.rendered().join("\n").contains("(x4)"),
            "the collapsed line does not say how many: {:?}",
            recording.rendered()
        );
    }

    /// Interleaved lines are not collapsed across a different one, because that would reorder the
    /// trace and the order is most of what a trace is for.
    #[test]
    fn only_consecutive_lines_collapse() {
        let recording = Capture::new("interleaved").depth(8).start();
        tracing::error!(target: "dataplane_net::buffer", "a");
        tracing::error!(target: "dataplane_net::buffer", "b");
        tracing::error!(target: "dataplane_net::buffer", "a");
        assert_eq!(recording.len(), 3, "non-consecutive lines were merged");
    }

    /// A field big enough to bury the trace is cut short.
    ///
    /// The value that forced this: `#[instrument]` on `packet_processor::ingress` captures the
    /// whole `Packet`, which renders to several kilobytes per span.
    #[test]
    fn an_enormous_field_is_clipped() {
        let recording = capture("clipped");
        let huge = "x".repeat(8192);
        tracing::error!(target: "dataplane_net::packet", packet = %huge, "in");
        let rendered = recording.rendered().join("\n");
        assert!(
            rendered.len() < 512,
            "an 8 KiB field was kept whole: {} bytes",
            rendered.len()
        );
        assert!(
            rendered.contains("more bytes>"),
            "the clip is not marked, so a reader cannot tell: {rendered}"
        );
    }
}
