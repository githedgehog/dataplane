// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use clock::Duration;
use std::fmt;
use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::fmt::time::{FormatTime, SystemTime};

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
            None => writer.write_str("T+?off-clock"),
        }
    }
}

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

    fn render() -> String {
        let mut out = String::new();
        Stamp
            .format_time(&mut Writer::new(&mut out))
            .expect("the stamp did not format");
        out
    }

    #[test]
    fn a_line_is_stamped_on_the_clock_the_code_is_reading() {
        let clock = Paused::new();
        clock.block_on(async {
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

    #[test]
    fn a_line_from_off_the_clock_says_so() {
        let clock = Paused::new();
        clock.block_on(async { advance(Duration::from_hours(1)).await });
        let stamped = thread::spawn(render)
            .join()
            .expect("formatting a stamp panicked");
        assert_eq!(stamped, "T+?off-clock");
    }

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
