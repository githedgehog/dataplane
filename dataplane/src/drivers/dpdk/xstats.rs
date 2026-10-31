// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Which of a port's extended statistics to publish.
//!
//! The basic counters (`port_rx_missed` and the rest) say a port dropped; the PMD's extended
//! statistics say where -- `rx_discards_phy` (the NIC's buffer, before any queue) apart from
//! `rx_out_of_buffer` (a queue with no descriptor), CRC and symbol errors on the wire, pause frames.
//! Their names differ by PMD and some PMDs keep hundreds, most of them per queue or per priority, so
//! the driver publishes those whose names say they count a drop, an error or a pause, across the
//! port rather than per queue, up to [`MAX_PER_PORT`].

use dpdk::dev::XstatName;

/// The most extended statistics published per port, to bound what one PMD can add to a scrape.
pub(crate) const MAX_PER_PORT: usize = 64;

/// What a name has to contain to be published.
const WANTED: [&str; 12] = [
    "discard",
    "drop",
    "err",
    "miss",
    "out_of_buffer",
    "nombuf",
    "no_mbuf",
    "crc",
    "symbol",
    "pause",
    "timeout",
    "undersize",
];

/// Whether a statistic is kept per queue: one of the name's `_`-separated words is `q` and digits,
/// as in `rx_q0_errors`, or names a queue as in `rx_queue_3_drops`.
fn per_queue(name: &str) -> bool {
    let words: Vec<&str> = name.split('_').collect();
    words.iter().enumerate().any(|(i, word)| {
        let numbered = |w: &str| !w.is_empty() && w.bytes().all(|b| b.is_ascii_digit());
        word.strip_prefix('q').is_some_and(numbered)
            || (*word == "queue" && words.get(i + 1).is_some_and(|next| numbered(next)))
    })
}

/// The statistics of `names` worth publishing, in the PMD's order.
pub(crate) fn wanted(names: Vec<XstatName>) -> Vec<XstatName> {
    names
        .into_iter()
        .filter(|x| {
            let name = x.name.to_ascii_lowercase();
            WANTED.iter().any(|w| name.contains(w)) && !per_queue(&name)
        })
        .take(MAX_PER_PORT)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(names: &[&str]) -> Vec<XstatName> {
        names
            .iter()
            .enumerate()
            .map(|(id, name)| XstatName {
                id: id as u64,
                name: (*name).to_string(),
            })
            .collect()
    }

    /// Drops, errors and pauses across the port are kept, with their ids; plain traffic counts and
    /// per-queue statistics are not.
    #[test]
    fn keeps_port_wide_drops_and_errors() {
        let kept = wanted(names(&[
            "rx_good_packets",
            "rx_discards_phy",
            "rx_q0_errors",
            "rx_queue_3_drops",
            "rx_out_of_buffer",
            "tx_bytes_phy",
            "rx_crc_errors_phy",
            "rx_pause_ctrl_phy",
            "rx_prio3_buf_discard",
        ]));
        let kept: Vec<(u64, &str)> = kept.iter().map(|x| (x.id, x.name.as_str())).collect();
        assert_eq!(
            kept,
            [
                (1, "rx_discards_phy"),
                (4, "rx_out_of_buffer"),
                (6, "rx_crc_errors_phy"),
                (7, "rx_pause_ctrl_phy"),
                (8, "rx_prio3_buf_discard"),
            ]
        );
    }

    #[test]
    fn bounded_per_port() {
        let many: Vec<String> = (0..MAX_PER_PORT + 10)
            .map(|i| format!("err_{i}x"))
            .collect();
        let many: Vec<&str> = many.iter().map(String::as_str).collect();
        assert_eq!(wanted(names(&many)).len(), MAX_PER_PORT);
    }
}
