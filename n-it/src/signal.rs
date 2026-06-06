//! Table-driven signal dispatch for the init system.
//!
//! Instead of hand-writing a `tokio::select!` arm for every Unix signal,
//! this module defines a declarative [`SIGNAL_TABLE`] that encodes:
//!
//! - which signals to intercept,
//! - what [`nix::sys::signal::Signal`] to forward to the child process, and
//! - whether receiving the signal constitutes a test failure
//!   ([`SignalPolicy`]).
//!
//! [`SignalSet`] registers handlers for every entry in the table and
//! multiplexes them into a single async [`recv`](SignalSet::recv) stream,
//! reducing the event loop in [`crate::init`] to two `tokio::select!`
//! branches (child exit and signal receipt).
//!
//! # Adding a new forwarded signal
//!
//! Append a [`SignalSpec`] to [`SIGNAL_TABLE`].  Both the handler
//! registration and the dispatch logic are derived from the same table,
//! so there is exactly one place to update.

use nix::sys::signal::Signal;
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::mpsc;

/// Whether receiving a signal should mark the test as failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalPolicy {
    /// Forward to the child process; the test continues normally.
    ///
    /// Used for signals that do not indicate a problem (e.g. `SIGHUP`,
    /// `SIGUSR1`, `SIGWINCH`).
    Benign,

    /// Forward to the child process **and** mark the test as failed.
    ///
    /// Used for signals that indicate an abnormal condition (e.g.
    /// `SIGTERM`, `SIGINT`, `SIGPIPE`).
    Failure,
}

/// A signal the init system should intercept and forward to the test process.
///
/// Each entry pairs a [`tokio::signal::unix::SignalKind`] (used to
/// register the async handler) with a [`nix::sys::signal::Signal`] (used
/// to forward via `kill(2)`), along with the forwarding [`SignalPolicy`]
/// and a human-readable label for log messages.
#[derive(Debug, Clone, Copy)]
pub struct SignalSpec {
    /// The tokio signal kind used to register the async handler.
    pub kind: SignalKind,
    /// The nix signal value forwarded to the child process via `kill(2)`.
    pub signal: Signal,
    /// Whether receipt of this signal marks the test as failed.
    pub policy: SignalPolicy,
    /// Human-readable name for log messages (e.g. `"SIGTERM"`).
    pub label: &'static str,
}

/// The complete signal forwarding table for the init system.
///
/// **Failure signals** are forwarded to the child *and* cause the test to
/// be marked as failed.  **Benign signals** are forwarded without
/// affecting the test outcome.
///
/// `SIGCHLD` is intentionally omitted -- leaked child processes are
/// detected after the main test process exits, during the shutdown
/// sequence.
///
/// # Adding a new signal
///
/// Append a [`SignalSpec`] entry below.  The [`SignalSet`] automatically
/// picks it up; no other code changes are required.
pub const SIGNAL_TABLE: &[SignalSpec] = &[
    // Failure signals
    SignalSpec {
        kind: SignalKind::terminate(),
        signal: Signal::SIGTERM,
        policy: SignalPolicy::Failure,
        label: "SIGTERM",
    },
    SignalSpec {
        kind: SignalKind::interrupt(),
        signal: Signal::SIGINT,
        policy: SignalPolicy::Failure,
        label: "SIGINT",
    },
    SignalSpec {
        kind: SignalKind::alarm(),
        signal: Signal::SIGALRM,
        policy: SignalPolicy::Failure,
        label: "SIGALRM",
    },
    SignalSpec {
        kind: SignalKind::pipe(),
        signal: Signal::SIGPIPE,
        policy: SignalPolicy::Failure,
        label: "SIGPIPE",
    },
    SignalSpec {
        kind: SignalKind::quit(),
        signal: Signal::SIGQUIT,
        policy: SignalPolicy::Failure,
        label: "SIGQUIT",
    },
    // Benign signals
    SignalSpec {
        kind: SignalKind::hangup(),
        signal: Signal::SIGHUP,
        policy: SignalPolicy::Benign,
        label: "SIGHUP",
    },
    SignalSpec {
        kind: SignalKind::user_defined1(),
        signal: Signal::SIGUSR1,
        policy: SignalPolicy::Benign,
        label: "SIGUSR1",
    },
    SignalSpec {
        kind: SignalKind::user_defined2(),
        signal: Signal::SIGUSR2,
        policy: SignalPolicy::Benign,
        label: "SIGUSR2",
    },
    SignalSpec {
        kind: SignalKind::window_change(),
        signal: Signal::SIGWINCH,
        policy: SignalPolicy::Benign,
        label: "SIGWINCH",
    },
];

/// A multiplexed receiver for all signals in a [`SignalSpec`] table.
///
/// Each registered signal gets a dedicated [`tokio::spawn`] task that
/// loops on [`tokio::signal::unix::Signal::recv`] and forwards the
/// corresponding [`SignalSpec`] through an unbounded MPSC channel.
/// The orchestrator calls [`recv`](Self::recv) to await the next signal
/// from *any* handler.
///
/// # Examples
///
/// ```ignore
/// let mut signals = SignalSet::register(SIGNAL_TABLE);
/// loop {
///     tokio::select! {
///         result = child.wait() => { /* handle exit */ break; }
///         spec = signals.recv() => {
///             forward_signal(pid, spec.signal);
///             if spec.policy == SignalPolicy::Failure { success = false; }
///         }
///     }
/// }
/// ```
pub struct SignalSet {
    rx: mpsc::UnboundedReceiver<SignalSpec>,
}

impl SignalSet {
    /// Registers async signal handlers for every entry in `table` and
    /// returns a [`SignalSet`] that multiplexes them.
    ///
    /// Each handler is a [`tokio::spawn`] task that loops on
    /// `Signal::recv()` and sends the spec through an internal channel.
    /// This must be called from within a tokio runtime context (i.e.
    /// inside [`tokio::runtime::Runtime::block_on`]).
    ///
    /// Calls [`fatal!`] if any signal handler fails to register, since
    /// an init system that cannot intercept signals is in an
    /// unrecoverable state.
    pub fn register(table: &'static [SignalSpec]) -> Self {
        let (tx, rx) = mpsc::unbounded_channel();

        for spec in table {
            let tx = tx.clone();
            let spec = *spec;
            let label = spec.label;
            let mut handler = signal(spec.kind)
                .unwrap_or_else(|e| fatal!("failed to register {label} handler: {e}"));

            tokio::spawn(async move {
                loop {
                    handler.recv().await;
                    // If the receiver has been dropped the orchestrator is
                    // shutting down -- stop forwarding.
                    if tx.send(spec).is_err() {
                        break;
                    }
                }
            });
        }

        // Drop the original sender so the channel closes when all tasks
        // complete (rather than being held open by this copy).
        drop(tx);

        Self { rx }
    }

    /// Waits for the next signal from any registered handler.
    ///
    /// Returns the [`SignalSpec`] describing which signal was received.
    /// Calls [`fatal!`] if the internal channel closes unexpectedly
    /// (all handler tasks exited, which should not happen during normal
    /// operation).
    pub async fn recv(&mut self) -> SignalSpec {
        self.rx
            .recv()
            .await
            .unwrap_or_else(|| fatal!("signal dispatch channel closed unexpectedly"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn signal_table_is_non_empty() {
        assert!(
            !SIGNAL_TABLE.is_empty(),
            "SIGNAL_TABLE should contain at least one entry",
        );
    }

    #[test]
    fn signal_table_has_no_duplicate_nix_signals() {
        let mut seen = HashSet::new();
        for spec in SIGNAL_TABLE {
            assert!(
                seen.insert(spec.signal),
                "duplicate nix::Signal in SIGNAL_TABLE: {:?} (label {:?})",
                spec.signal,
                spec.label,
            );
        }
    }

    #[test]
    fn signal_table_has_no_duplicate_labels() {
        let mut seen = HashSet::new();
        for spec in SIGNAL_TABLE {
            assert!(
                seen.insert(spec.label),
                "duplicate label in SIGNAL_TABLE: {:?}",
                spec.label,
            );
        }
    }

    #[test]
    fn signal_table_labels_are_non_empty() {
        for spec in SIGNAL_TABLE {
            assert!(
                !spec.label.is_empty(),
                "signal table entry for {:?} has an empty label",
                spec.signal,
            );
        }
    }

    #[test]
    fn signal_table_labels_match_signal_names() {
        // nix::Signal's Debug output is the signal name (e.g. "SIGTERM").
        // We verify that each label matches its signal's name so they
        // don't drift out of sync.
        for spec in SIGNAL_TABLE {
            let signal_name = format!("{:?}", spec.signal);
            assert_eq!(
                spec.label, signal_name,
                "label {:?} does not match signal name {:?}",
                spec.label, signal_name,
            );
        }
    }

    #[test]
    fn signal_table_contains_sigterm_as_failure() {
        let sigterm = SIGNAL_TABLE
            .iter()
            .find(|s| s.signal == Signal::SIGTERM)
            .expect("SIGNAL_TABLE should contain SIGTERM");
        assert_eq!(
            sigterm.policy,
            SignalPolicy::Failure,
            "SIGTERM should be a failure signal",
        );
    }

    #[test]
    fn signal_table_contains_sigint_as_failure() {
        let sigint = SIGNAL_TABLE
            .iter()
            .find(|s| s.signal == Signal::SIGINT)
            .expect("SIGNAL_TABLE should contain SIGINT");
        assert_eq!(
            sigint.policy,
            SignalPolicy::Failure,
            "SIGINT should be a failure signal",
        );
    }

    #[test]
    fn signal_table_has_at_least_one_benign_signal() {
        let benign_count = SIGNAL_TABLE
            .iter()
            .filter(|s| s.policy == SignalPolicy::Benign)
            .count();
        assert!(
            benign_count > 0,
            "SIGNAL_TABLE should contain at least one benign signal",
        );
    }

    #[test]
    fn signal_table_has_at_least_one_failure_signal() {
        let failure_count = SIGNAL_TABLE
            .iter()
            .filter(|s| s.policy == SignalPolicy::Failure)
            .count();
        assert!(
            failure_count > 0,
            "SIGNAL_TABLE should contain at least one failure signal",
        );
    }

    /// SIGCHLD is intentionally excluded from the table -- child reaping
    /// is handled after the main test process exits, not via the signal
    /// dispatch loop.  This test ensures it is never accidentally added.
    #[test]
    fn signal_table_does_not_contain_sigchld() {
        let has_sigchld = SIGNAL_TABLE.iter().any(|s| s.signal == Signal::SIGCHLD);
        assert!(
            !has_sigchld,
            "SIGNAL_TABLE should not contain SIGCHLD; \
             child reaping is handled separately during shutdown",
        );
    }
}
