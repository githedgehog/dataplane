// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Backends: what a plan costs on one, and whether it fits (`PLANNER.md`: the cost model
//! belongs to the backend; the planner has no thresholds of its own).

use crate::plan::{Plan, Then};
use std::collections::HashMap;

/// What a plan takes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cost {
    /// Levels traversed on the worst path.
    pub worst_path: usize,
    /// Entries over all levels.
    pub entries: usize,
    /// The largest level's entries.
    pub largest_level: usize,
    /// Class registers written, and the bits each needs (its largest value's).
    pub registers: Vec<u32>,
}

impl Cost {
    /// Measure `plan`. `None` if it loops.
    #[must_use]
    pub fn of<A: Clone>(plan: &Plan<A>) -> Option<Cost> {
        let mut bits: HashMap<u8, u32> = HashMap::new();
        for level in &plan.levels {
            for step in level.entries.steps().chain(std::iter::once(&level.miss)) {
                for &(reg, value) in &step.writes {
                    let b = bits.entry(reg).or_default();
                    *b = (*b).max(value.checked_ilog2().map_or(1, |l| l + 1));
                }
            }
        }
        let mut registers: Vec<(u8, u32)> = bits.into_iter().collect();
        registers.sort_unstable();
        Some(Cost {
            worst_path: plan.worst_path()?,
            entries: plan.entries(),
            largest_level: plan
                .levels
                .iter()
                .map(|l| l.entries.len())
                .max()
                .unwrap_or(0),
            registers: registers.into_iter().map(|(_, b)| b).collect(),
        })
    }
}

/// Why a backend can't run a plan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Unfit {
    /// The plan loops.
    Loops,
    /// More levels per packet than the budget.
    Path {
        /// The plan's worst path.
        have: usize,
        /// The budget.
        budget: usize,
    },
    /// A level larger than a table holds.
    Level {
        /// The largest level.
        have: usize,
        /// What a table holds.
        cap: usize,
    },
    /// More class bits than the registers available.
    Registers {
        /// Bits the plan needs.
        have: u32,
        /// Bits available.
        cap: u32,
    },
}

/// A place a plan may run.
pub trait Backend {
    /// What `plan` costs here, or why it can't run here.
    ///
    /// # Errors
    ///
    /// Why the plan doesn't fit.
    fn assess<A: Clone>(&self, plan: &Plan<A>) -> Result<Cost, Unfit>;

    /// This backend, with `levels` of every packet's budget already spent (by a guard in
    /// front of the plans it will assess).
    #[must_use]
    fn reserving(&self, levels: usize) -> Self
    where
        Self: Sized;
}

/// mlx5 steering, as calibrated on the CX-8 (`spike-rfc`): about 0.75G table lookups per second
/// per port, a ceiling of about 120 Mpps of 64 B frames, and up to 8M rules per table. Every
/// level is an exact table (a group with one template); a miss costs what a hit does.
#[derive(Clone, Debug)]
pub struct Mlx5 {
    /// Levels a packet may traverse at the design point's packet rate.
    pub tables_per_packet: usize,
    /// Rules per table.
    pub entries_per_table: usize,
    /// Bits of metadata registers the plan may use for class ids (TAG registers, less what the
    /// bank bit, trap point and VNI need).
    pub register_bits: u32,
}

impl Mlx5 {
    /// Lookups per second per port (CX-8, spike-rfc).
    pub const LOOKUPS_PER_SECOND: f64 = 0.75e9;
    /// The port's packet-rate ceiling, in packets per second.
    pub const CEILING: f64 = 120e6;

    /// The budget at a design point of `pps` packets per second (capped at the port ceiling).
    #[must_use]
    pub fn at(pps: f64) -> Mlx5 {
        let rate = pps.clamp(1.0, Self::CEILING);
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)] // small and positive
        let tables = (Self::LOOKUPS_PER_SECOND / rate).floor() as usize;
        Mlx5 {
            tables_per_packet: tables.max(1),
            entries_per_table: 8 << 20,
            // Eight 32-bit TAG registers, two kept for the bank bit, trap point and VNI.
            register_bits: 6 * 32,
        }
    }
}

impl Backend for Mlx5 {
    fn reserving(&self, levels: usize) -> Self {
        Mlx5 {
            tables_per_packet: self.tables_per_packet.saturating_sub(levels),
            ..self.clone()
        }
    }

    fn assess<A: Clone>(&self, plan: &Plan<A>) -> Result<Cost, Unfit> {
        let cost = Cost::of(plan).ok_or(Unfit::Loops)?;
        if cost.worst_path > self.tables_per_packet {
            return Err(Unfit::Path {
                have: cost.worst_path,
                budget: self.tables_per_packet,
            });
        }
        if cost.largest_level > self.entries_per_table {
            return Err(Unfit::Level {
                have: cost.largest_level,
                cap: self.entries_per_table,
            });
        }
        // Each register's class ids, rounded up to whole bytes: a backend packs them.
        let bits: u32 = cost.registers.iter().map(|b| b.div_ceil(8) * 8).sum();
        if bits > self.register_bits {
            return Err(Unfit::Registers {
                have: bits,
                cap: self.register_bits,
            });
        }
        Ok(cost)
    }
}

/// Software: any plan that terminates runs; its cost is what it is.
#[derive(Clone, Copy, Debug, Default)]
pub struct Software;

impl Backend for Software {
    fn reserving(&self, _: usize) -> Self {
        Software
    }

    fn assess<A: Clone>(&self, plan: &Plan<A>) -> Result<Cost, Unfit> {
        Cost::of(plan).ok_or(Unfit::Loops)
    }
}

/// Whether `plan` ends every path with an action (no dangling goto). For tests.
#[must_use]
pub fn closed<A>(plan: &Plan<A>) -> bool {
    let ok = |t: &Then<A>| match t {
        Then::Goto(id) => *id < plan.levels.len(),
        Then::Done(_) => true,
    };
    ok(&plan.entry.then)
        && plan.levels.iter().all(|l| {
            l.entries
                .steps()
                .chain(std::iter::once(&l.miss))
                .all(|s| ok(&s.then))
        })
}
