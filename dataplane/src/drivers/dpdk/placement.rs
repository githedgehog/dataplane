// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Which CPUs the DPDK driver's threads run on.
//!
//! For now the only placement is the control worker's: it busy-polls, alone, on the last CPU the
//! process may use, and the data workers keep to the others. Everything else still floats over the
//! process's mask; topology-aware placement of the data workers is to come.

use nix::sched::{CpuSet, sched_getaffinity, sched_setaffinity};
use nix::unistd::Pid;
use tracing::{info, warn};

/// Where the control worker and the data workers run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Placement {
    /// The control worker's CPU.
    pub(crate) control: Option<usize>,
    /// The data workers' CPUs, if they are kept off the control worker's.
    pub(crate) data: Option<Vec<usize>>,
}

impl Placement {
    /// Placement over the `allowed` CPUs, in ascending order: the control worker on the last, the
    /// data workers on the others. With a single CPU there are no others, so the data workers are
    /// left where they are, sharing it.
    pub(crate) fn over(allowed: &[usize]) -> Placement {
        match allowed.split_last() {
            None => Placement {
                control: None,
                data: None,
            },
            Some((&control, [])) => Placement {
                control: Some(control),
                data: None,
            },
            Some((&control, rest)) => Placement {
                control: Some(control),
                data: Some(rest.to_vec()),
            },
        }
    }

    /// Placement over the CPUs the calling thread may use, which for the datapath thread is the
    /// process's mask. No placement if the mask cannot be read.
    pub(crate) fn of_this_process() -> Placement {
        match allowed() {
            Ok(allowed) => {
                let placement = Placement::over(&allowed);
                info!(
                    "the control worker will run on CPU {:?}, the data workers on {:?}",
                    placement.control, placement.data
                );
                placement
            }
            Err(e) => {
                warn!("could not read the CPUs this process may use ({e}); not pinning any worker");
                Placement::over(&[])
            }
        }
    }
}

/// The CPUs the calling thread may run on, in ascending order.
fn allowed() -> nix::Result<Vec<usize>> {
    let set = sched_getaffinity(Pid::from_raw(0))?;
    Ok((0..CpuSet::count())
        .filter(|&cpu| set.is_set(cpu).unwrap_or(false))
        .collect())
}

/// Keep the calling thread to `cpus`, logging (as `what`) if it cannot be.
pub(crate) fn pin(what: &str, cpus: &[usize]) {
    let mut set = CpuSet::new();
    for &cpu in cpus {
        if let Err(e) = set.set(cpu) {
            warn!("{what} cannot be pinned to CPU {cpu}: {e}");
            return;
        }
    }
    // Pid 0 is the calling thread, not the process.
    if let Err(e) = sched_setaffinity(Pid::from_raw(0), &set) {
        warn!(
            "{what} could not be pinned to CPUs {cpus:?}: {e}; it floats over the process's CPUs"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::Placement;

    #[test]
    fn the_control_worker_has_the_last_cpu_to_itself() {
        bolero::check!().with_type::<Vec<u8>>().for_each(|cpus| {
            let mut allowed: Vec<usize> = cpus.iter().map(|&c| usize::from(c)).collect();
            allowed.sort_unstable();
            allowed.dedup();
            let placement = Placement::over(&allowed);
            assert_eq!(placement.control, allowed.last().copied());
            match &placement.data {
                // Only a single CPU leaves the data workers where they are.
                None => assert!(allowed.len() <= 1),
                Some(data) => {
                    let control = placement.control.unwrap();
                    assert!(!data.contains(&control));
                    let mut all = data.clone();
                    all.push(control);
                    assert_eq!(all, allowed);
                }
            }
        });
    }
}
