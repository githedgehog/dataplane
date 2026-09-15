// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![allow(clippy::disallowed_types)]

use std::collections::VecDeque;
use std::fmt;
use std::fmt::Write as _;
// nosemgrep: rust-no-direct-std-sync-import
use std::sync::Arc;

use tracing::field::{Field, Visit};
use tracing::span::Attributes;
use tracing::subscriber::DefaultGuard;
use tracing::{Event, Id, Level, Metadata, Subscriber};
use tracing_subscriber::layer::{Context, Layer, SubscriberExt};
use tracing_subscriber::registry::LookupSpan;

pub const DEFAULT_DEPTH: usize = 512;

struct Line {
    level: Level,
    target: &'static str,
    kind: Kind,
    scope: String,
    message: String,
    fields: String,
    repeats: usize,
}

impl Line {
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

struct Log {
    lines: VecDeque<Line>,
    depth: usize,
    dropped: usize,
}

impl Log {
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

#[derive(Default)]
struct Fields {
    message: String,
    rest: String,
}

const FIELD_LIMIT: usize = 160;

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

pub const MACHINERY: &[&str] = &["shuttle", "tokio", "runtime", "mio", "hyper"];

type Keep = Arc<dyn Fn(&str) -> bool + Send + Sync>;

concurrency::with_std! {
    const RECORDS: bool = true;

    #[allow(clippy::unnecessary_wraps)]
    fn install<S: Subscriber + Send + Sync + 'static>(subscriber: S) -> Option<DefaultGuard> {
        Some(tracing::subscriber::set_default(subscriber))
    }
}

concurrency::with_loom! {
    const RECORDS: bool = false;

    fn install<S: Subscriber + Send + Sync + 'static>(_subscriber: S) -> Option<DefaultGuard> {
        None
    }
}

concurrency::with_shuttle! {
    const RECORDS: bool = false;

    fn install<S: Subscriber + Send + Sync + 'static>(_subscriber: S) -> Option<DefaultGuard> {
        None
    }
}

struct EvidenceLayer {
    // nosemgrep: rust-no-direct-std-sync-import
    log: Arc<std::sync::Mutex<Log>>,
    keep: Keep,
}

impl EvidenceLayer {
    fn push(&self, line: Line) {
        if let Ok(mut log) = self.log.lock() {
            log.push(line);
        }
    }
}

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

#[must_use = "a recording that is dropped immediately captures nothing"]
pub struct Recording {
    // nosemgrep: rust-no-direct-std-sync-import
    log: Arc<std::sync::Mutex<Log>>,
    label: String,
    _installed: Option<DefaultGuard>,
}

#[must_use = "a recording that is dropped immediately captures nothing"]
pub fn capture(label: impl Into<String>) -> Recording {
    Capture::new(label).start()
}

pub struct Capture {
    label: String,
    depth: usize,
    keep: Keep,
}

impl Capture {
    #[must_use]
    pub fn new(label: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            depth: DEFAULT_DEPTH,
            keep: Arc::new(|target: &str| !MACHINERY.iter().any(|noisy| target.starts_with(noisy))),
        }
    }

    #[must_use]
    pub fn depth(mut self, depth: usize) -> Self {
        self.depth = depth.max(1);
        self
    }

    #[must_use]
    pub fn keeping(mut self, keep: impl Fn(&str) -> bool + Send + Sync + 'static) -> Self {
        self.keep = Arc::new(keep);
        self
    }

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

#[derive(Clone)]
pub struct Evidence {
    // nosemgrep: rust-no-direct-std-sync-import
    log: Arc<std::sync::Mutex<Log>>,
    label: String,
}

impl Evidence {
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
    #[must_use]
    pub fn evidence(&self) -> Evidence {
        Evidence {
            log: self.log.clone(),
            label: self.label.clone(),
        }
    }

    pub fn dump(&self) {
        self.evidence().dump();
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.log.lock().map_or(0, |log| log.lines.len())
    }

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

    #[test]
    fn the_ring_drops_the_oldest() {
        let recording = Capture::new("bounded").depth(4).start();
        for n in 0..10_u64 {
            tracing::error!(n, "line");
        }
        assert_eq!(recording.len(), 4, "the ring did not bound itself");
    }

    #[test]
    fn a_recording_does_not_capture_another_thread() {
        let recording = capture("this thread");
        std::thread::scope(|scope| {
            scope.spawn(|| tracing::error!("from elsewhere"));
        });
        assert_eq!(recording.len(), 0, "a recording reached across a thread");
    }

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

    #[test]
    fn machinery_is_not_evidence() {
        let recording = capture("filtered");
        tracing::error!(target: "shuttle::runtime::execution", "scheduling decision");
        tracing::error!(target: "dataplane_nat::masquerade", "allocated");
        assert_eq!(recording.len(), 1, "the machinery target was captured");
    }

    #[test]
    fn a_capture_can_be_narrowed_to_one_crate() {
        let recording = Capture::new("narrow")
            .keeping(|target| target.starts_with("dataplane_nat"))
            .start();
        tracing::error!(target: "dataplane_net::packet", "dropping");
        tracing::error!(target: "dataplane_nat::masquerade", "allocated");
        assert_eq!(recording.len(), 1, "the filter did not narrow");
    }

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

    #[test]
    fn only_consecutive_lines_collapse() {
        let recording = Capture::new("interleaved").depth(8).start();
        tracing::error!(target: "dataplane_net::buffer", "a");
        tracing::error!(target: "dataplane_net::buffer", "b");
        tracing::error!(target: "dataplane_net::buffer", "a");
        assert_eq!(recording.len(), 3, "non-consecutive lines were merged");
    }

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
