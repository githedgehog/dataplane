// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Timestamps that agree with the clock the code under test is reading.
//!
//! `tracing_subscriber`'s default timer is `SystemTime`, which is the wall clock and is deliberately
//! not routed -- [`clock::system_now`] explains why the system clock cannot be paused. That is the
//! right stamp in production and the wrong one under a driven clock: a line emitted at virtual
//! `T+1h` carries the real time, so correlating a log against an expiry is guesswork exactly when
//! the log is the only thing left to read.
//!
//! So under a routed clock the stamp becomes an offset on *that* clock. It cannot be a wall time --
//! [`clock::now`] is monotonic and has no epoch -- but "how far into the test is this line" is the
//! more useful question in a test log anyway, and it is the only stamp that agrees with what the
//! code under test believes.

use clock::Duration;
use std::fmt;
use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::fmt::time::{FormatTime, SystemTime};

/// The workspace's log timestamp.
///
/// Wall time in production, and an offset on the driven clock under test. Chosen at compile time by
/// [`clock::is_routed`], so production pays nothing for the branch.
#[derive(Debug, Clone, Copy, Default)]
pub struct Stamp;

impl FormatTime for Stamp {
    fn format_time(&self, writer: &mut Writer<'_>) -> fmt::Result {
        if !clock::is_routed() {
            return SystemTime.format_time(writer);
        }
        match clock::elapsed_since_first_reading() {
            Some((behind, elapsed)) => write!(
                writer,
                "T{}{}",
                if behind { '-' } else { '+' },
                Rendered(elapsed)
            ),
            // The thread cannot see the clock a test is driving, so there is no offset to report and
            // a wall reading here would be from a different timeline. Say which, rather than print
            // a number that means something else -- a line stamped this way is itself the finding.
            None => writer.write_str("T+?off-clock"),
        }
    }
}

/// Seconds and microseconds, so that a line's offset reads at a glance.
struct Rendered(Duration);

impl fmt::Display for Rendered {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{:06}s", self.0.as_secs(), self.0.subsec_micros())
    }
}

#[cfg(test)]
mod tests {
    use super::{Rendered, Stamp};
    use clock::Duration;
    use clock::virtual_time::{Paused, advance};
    use std::thread;
    use tracing_subscriber::fmt::format::Writer;
    use tracing_subscriber::fmt::time::FormatTime;

    /// What one log line's timestamp would say.
    fn render() -> String {
        let mut out = String::new();
        Stamp
            .format_time(&mut Writer::new(&mut out))
            .expect("the stamp did not format");
        out
    }

    /// A line emitted an hour into a test is stamped an hour in, not with the wall clock.
    ///
    /// This is the whole point: the default `SystemTime` timer would put the real time on both of
    /// these, which is what made correlating a log against an expiry guesswork.
    #[test]
    fn a_line_is_stamped_on_the_clock_the_code_is_reading() {
        let clock = Paused::new();
        clock.block_on(async {
            // The first reading is the origin, so it has to be taken before the advance.
            let first = render();
            advance(Duration::from_hours(1)).await;
            let later = render();
            assert!(
                first.starts_with("T+0."),
                "the first line was stamped {first}"
            );
            assert!(
                later.starts_with("T+3600."),
                "an hour passed and the stamp said {later}"
            );
        });
    }

    /// A thread that cannot see the driven clock is stamped as such, not with a wall reading.
    ///
    /// Rendering wall time here would put two timelines in one log with nothing to tell them apart.
    /// It also must not panic: `clock::now()` would, and replacing a diagnostic with a panic in the
    /// middle of formatting it is a worse outcome than the line it was trying to print.
    #[test]
    fn a_line_from_off_the_clock_says_so() {
        let clock = Paused::new();
        clock.block_on(async { advance(Duration::from_hours(1)).await });
        let stamped = thread::spawn(render)
            .join()
            .expect("formatting a stamp panicked");
        assert_eq!(stamped, "T+?off-clock");
    }

    /// An hour reads as an hour, which is the point of the whole exercise.
    #[test]
    fn an_offset_reads_at_a_glance() {
        assert_eq!(
            Rendered(Duration::from_hours(1)).to_string(),
            "3600.000000s"
        );
        assert_eq!(
            Rendered(Duration::from_micros(1)).to_string(),
            "0.000001s",
            "sub-millisecond detail is what separates two lines in the same burst"
        );
    }
}
