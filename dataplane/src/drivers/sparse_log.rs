// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Logging what can happen once per packet without logging once per packet.
//!
//! A frame that does not parse, or a pipeline bug that leaves packets without an output interface,
//! can happen to every packet at line rate, and a line logged for each would bury everything else
//! and cost more than forwarding. The counters say how often; the log only needs to say that it
//! happens, and what it looks like. [`log_sparsely!`] logs the first occurrence at a call site,
//! then at most one per [`EVERY`] on each thread, with the number it left out since the last one
//! as the `suppressed` field.

use std::cell::Cell;
use std::thread::LocalKey;
use std::time::{Duration, Instant};

/// The shortest interval between two lines from one call site on one thread.
pub(crate) const EVERY: Duration = Duration::from_secs(10);

/// One call site's record on one thread: when it last logged, and how many it has not since.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Sparse {
    last: Option<Instant>,
    suppressed: u64,
}

impl Sparse {
    /// It happened again, at `now`. Returns how many went unlogged since the last line if this one
    /// is to be logged, or `None` if not.
    pub(crate) fn hit(&mut self, now: Instant) -> Option<u64> {
        match self.last {
            Some(last) if now.saturating_duration_since(last) < EVERY => {
                self.suppressed = self.suppressed.saturating_add(1);
                None
            }
            _ => {
                self.last = Some(now);
                Some(std::mem::take(&mut self.suppressed))
            }
        }
    }
}

/// [`Sparse::hit`] on a thread-local record, now.
pub(crate) fn hit(site: &'static LocalKey<Cell<Sparse>>) -> Option<u64> {
    site.with(|cell| {
        let mut sparse = cell.get();
        let log = sparse.hit(clock::now());
        cell.set(sparse);
        log
    })
}

/// Log with `tracing`'s `$level!` macro, sparsely: the first time this call site is reached on a
/// thread, then at most once per [`EVERY`](crate::drivers::sparse_log::EVERY), adding the
/// number of occurrences left out as the `suppressed` field.
///
/// ```ignore
/// log_sparsely!(warn!(worker = id, "dropping a packet with no output interface"));
/// ```
macro_rules! log_sparsely {
    ($level:ident!($($arg:tt)*)) => {{
        ::std::thread_local! {
            static SITE: ::std::cell::Cell<$crate::drivers::sparse_log::Sparse> =
                ::std::cell::Cell::new($crate::drivers::sparse_log::Sparse::default());
        }
        if let Some(suppressed) = $crate::drivers::sparse_log::hit(&SITE) {
            $level!(suppressed, $($arg)*);
        }
    }};
}
pub(crate) use log_sparsely;

#[cfg(test)]
mod tests {
    use super::*;
    use tracing::trace;

    /// The first is logged, then one per interval, each with how many were left out before it.
    #[test]
    fn logs_the_first_then_one_per_interval() {
        let start = Instant::now();
        let at = |secs: u64| start + Duration::from_secs(secs);
        let mut sparse = Sparse::default();
        assert_eq!(sparse.hit(at(0)), Some(0));
        assert_eq!(sparse.hit(at(1)), None);
        assert_eq!(sparse.hit(at(9)), None);
        assert_eq!(sparse.hit(at(10)), Some(2));
        assert_eq!(sparse.hit(at(11)), None);
        // A long quiet spell: the next is logged at once.
        assert_eq!(sparse.hit(at(1000)), Some(1));
        assert_eq!(sparse.hit(at(1000)), None);
    }

    /// Each call site keeps its own record: one that logs does not silence another.
    #[test]
    fn call_sites_are_apart() {
        thread_local!(static A: Cell<Sparse> = Cell::new(Sparse::default()));
        thread_local!(static B: Cell<Sparse> = Cell::new(Sparse::default()));
        let mut logged = [0; 2];
        for _ in 0..3 {
            logged[0] += usize::from(hit(&A).is_some());
            logged[1] += usize::from(hit(&B).is_some());
            // And the macro, which declares a site of its own wherever it is used.
            log_sparsely!(trace!(site = "loop", "logged once"));
        }
        assert_eq!(logged, [1, 1]);
    }
}
