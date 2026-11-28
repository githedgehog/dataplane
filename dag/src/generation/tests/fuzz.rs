// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! The protocol as random sequences of operations, on one thread, against a reference model.
//!
//! Each operation is the publisher's (begin, flip, retire), or one worker's: packets arrive
//! (stamped by the selector, or not), it reads the live generations, it runs a burst, it idles, it
//! joins or leaves. A burst may have operations of the publisher and arrivals between its read and
//! its poll: the window in which a worker holds generations the publisher has moved on from.
//!
//! The model is a few counters: the newest generation, whether a previous one is live, whether
//! hardware stamps the newest, and the generation each worker observed. Checked after every
//! operation:
//! - begin and flip answer exactly as the model says, and retire whenever it must refuse;
//! - every read returns the model's live generations;
//! - the selector stamps what the model says, and only what every worker has observed (I3);
//! - a retire never leaves a worker holding a packet stamped with the retired generation;
//! - every packet runs under the generation its stamp names, and none is stale (I1, FIFO);
//! - at the end, once the workers drain and idle, the pending generation flips and retires, and
//!   every snapshot is released exactly once.
//!
//! Runs under the random driver with the test suite, and under libfuzzer with
//! `just fuzz 'generation::tests::fuzz::operations_keep_the_protocol' 60s -p dataplane-dag`.

use super::*;
use bolero::TypeGenerator;
use concurrency::sync::Mutex;

/// Workers at once, at most; operations name a worker modulo those present.
const WORKERS: usize = 3;
/// Descriptors per RX ring: the NIC drops what does not fit.
const RING: usize = 12;
/// Operations per run, at most.
const OPS: usize = 48;

#[derive(Clone, Copy, Debug, TypeGenerator)]
enum Publish {
    Begin,
    Flip,
    Retire,
}

/// What can happen between a worker's read and its poll.
#[derive(Clone, Copy, Debug, TypeGenerator)]
enum Between {
    Publish(Publish),
    /// As [`Op::Arrive`].
    Arrive {
        worker: u8,
        count: u8,
        unstamped: bool,
    },
}

#[derive(Clone, Debug, TypeGenerator)]
enum Op {
    Publish(Publish),
    /// `count % 4` packets arrive at `worker`'s ring: stamped by the selector now, or unstamped.
    Arrive {
        worker: u8,
        count: u8,
        unstamped: bool,
    },
    /// The worker reads the live generations, and does nothing with them.
    Read {
        worker: u8,
    },
    /// The worker reads, `between` happens, then it polls up to `max % 6 + 1` packets and runs
    /// them under what it read; or idles on an empty poll.
    Burst {
        worker: u8,
        max: u8,
        between: Vec<Between>,
    },
    /// The worker reads, and idles if its ring is empty.
    Idle {
        worker: u8,
    },
    Join,
    Leave {
        worker: u8,
    },
}

/// The bank of `generation`: the first is in A, and they alternate.
fn bank(generation: u64) -> Bank {
    if generation % 2 == 1 {
        Bank::A
    } else {
        Bank::B
    }
}

/// The model, and the parts of the system under test that are not a worker's reader.
struct Model<'g> {
    generations: &'g Generations<Tag>,
    log: Arc<Mutex<Vec<ThreadId>>>,
    rings: Vec<VecDeque<Packet<TestBuffer>>>,
    /// Per worker: the newest generation it has observed.
    observed: Vec<u64>,
    newest: u64,
    previous: bool,
    flipped: bool,
    /// Tables made: the first, and one per begin, refused or not.
    made: usize,
}

impl Model<'_> {
    fn publish(&mut self, step: Publish) {
        match step {
            Publish::Begin => {
                self.made += 1;
                let got = self.generations.begin(Tag::new(self.newest + 1, &self.log));
                if self.previous {
                    assert_eq!(got, Err(Wait::TwoLive));
                } else {
                    self.newest += 1;
                    assert_eq!(got, Ok(self.newest));
                    self.previous = true;
                    self.flipped = false;
                }
            }
            Publish::Flip => {
                let got = self.generations.flip();
                if self.flipped {
                    assert_eq!(got, Err(Wait::NothingPending));
                } else if self.observed.iter().any(|&o| o < self.newest) {
                    assert_eq!(got, Err(Wait::NotObserved));
                } else {
                    assert_eq!(got, Ok(()));
                    self.flipped = true;
                }
            }
            Publish::Retire => {
                let got = self.generations.retire();
                if !self.previous {
                    assert_eq!(got, Err(Wait::NothingPending));
                } else if !self.flipped {
                    assert_eq!(got, Err(Wait::NotFlipped));
                } else if got.is_ok() {
                    // Whether every worker acknowledged is the rule under test. What must hold
                    // when it retires is that no ring still holds the retired generation's packets.
                    let retired = Stamp::new(bank(self.newest - 1), self.newest - 1);
                    for (w, ring) in self.rings.iter().enumerate() {
                        assert!(
                            ring.iter().all(|p| p.meta().stamp() != Some(retired)),
                            "retired {} with its packets still in worker {w}'s ring",
                            self.newest - 1
                        );
                    }
                    self.previous = false;
                } else {
                    assert_eq!(got, Err(Wait::NotAcknowledged));
                }
            }
        }
        assert_eq!(self.generations.newest(), self.newest);
        assert_eq!(self.generations.draining(), self.previous);
    }

    /// As [`Op::Arrive`]; `worker` is taken modulo the workers present.
    fn arrive(&mut self, worker: u8, count: u8, unstamped: bool) {
        if self.rings.is_empty() {
            return;
        }
        let stamping = if self.flipped {
            self.newest
        } else {
            self.newest - 1
        };
        let stamp = self.generations.selector().stamp();
        assert_eq!(stamp, Stamp::new(bank(stamping), stamping));
        assert!(
            self.observed.iter().all(|&o| o >= stamping),
            "I3: stamping {stamping} before every worker can read it"
        );
        let workers = self.rings.len();
        let ring = &mut self.rings[usize::from(worker) % workers];
        for _ in 0..usize::from(count % 4).min(RING - ring.len()) {
            ring.push_back(packet((!unstamped).then_some(stamp)));
        }
    }

    /// Check what `worker` read against the model, and record that it observed the newest.
    fn read(&mut self, worker: usize, live: &Live<Tag>) {
        assert_eq!(live.tables().newest().generation(), self.newest);
        if self.flipped && self.previous {
            // Flipped, not retired: a worker keeps the previous generation until its queue is
            // drained of it, then lets it go. Either is right; what letting go too early would
            // cost (a stale packet) is checked where packets run.
        } else {
            assert_eq!(live.tables().previous().is_some(), self.previous);
        }
        self.observed[worker] = self.newest;
    }
}

/// A run: the workers' readers, and the rest.
struct Run<'g> {
    readers: Vec<Reader<'g, Tag>>,
    model: Model<'g>,
}

impl<'g> Run<'g> {
    fn new(generations: &'g Generations<Tag>, log: Arc<Mutex<Vec<ThreadId>>>) -> Self {
        Run {
            readers: Vec::new(),
            model: Model {
                generations,
                log,
                rings: Vec::new(),
                observed: Vec::new(),
                newest: 1,
                made: 1,
                previous: false,
                flipped: true,
            },
        }
    }

    /// The worker `worker` names, if any is present.
    fn worker(&self, worker: u8) -> Option<usize> {
        (!self.readers.is_empty()).then(|| usize::from(worker) % self.readers.len())
    }

    fn read(&mut self, worker: usize) {
        let live = self.readers[worker].live();
        self.model.read(worker, live);
    }

    /// As [`Op::Burst`].
    fn burst(&mut self, worker: usize, max: u8, between: &[Between]) {
        let model = &mut self.model;
        let reader = &mut self.readers[worker];
        let live = reader.live();
        model.read(worker, live);
        for step in between {
            match *step {
                Between::Publish(step) => model.publish(step),
                Between::Arrive {
                    worker,
                    count,
                    unstamped,
                } => model.arrive(worker, count, unstamped),
            }
        }
        let ring = &mut model.rings[worker];
        let n = (usize::from(max % 6) + 1).min(ring.len());
        let mut burst: Vec<_> = ring.drain(..n).collect();
        if burst.is_empty() {
            reader.idle();
        } else {
            let seen = run_checked(&mut burst, live.tables());
            assert_eq!(seen.stale, 0, "a FIFO worker saw a stale packet");
            reader.settle(seen);
        }
        // A worker may take a newer publication as soon as a burst's evidence allows.
        model.observed[worker] = model.observed[worker].max(reader.observed());
    }

    fn apply(&mut self, op: &Op) {
        match *op {
            Op::Publish(step) => self.model.publish(step),
            Op::Arrive {
                worker,
                count,
                unstamped,
            } => self.model.arrive(worker, count, unstamped),
            Op::Join => {
                if self.readers.len() < WORKERS {
                    self.readers.push(self.model.generations.reader());
                    self.model.rings.push(VecDeque::new());
                    self.model.observed.push(self.model.newest);
                }
            }
            Op::Read { worker } => {
                if let Some(w) = self.worker(worker) {
                    self.read(w);
                }
            }
            Op::Burst {
                worker,
                max,
                ref between,
            } => {
                if let Some(w) = self.worker(worker) {
                    self.burst(w, max, between);
                }
            }
            Op::Idle { worker } => {
                if let Some(w) = self.worker(worker) {
                    self.read(w);
                    if self.model.rings[w].is_empty() {
                        self.readers[w].idle();
                        self.model.observed[w] =
                            self.model.observed[w].max(self.readers[w].observed());
                    }
                }
            }
            Op::Leave { worker } => {
                if let Some(w) = self.worker(worker) {
                    self.readers.swap_remove(w);
                    self.model.rings.swap_remove(w);
                    self.model.observed.swap_remove(w);
                }
            }
        }
    }

    /// The workers drain their rings and idle: nothing may then hold up the pending generation.
    fn quiesce(&mut self) {
        for w in 0..self.readers.len() {
            while !self.model.rings[w].is_empty() {
                self.burst(w, u8::MAX, &[]);
            }
        }
        if self.model.previous {
            for w in 0..self.readers.len() {
                self.read(w);
            }
            self.model.publish(Publish::Flip);
            assert!(self.model.flipped, "every worker observed, but no flip");
            for w in 0..self.readers.len() {
                self.burst(w, 0, &[]);
            }
            self.model.publish(Publish::Retire);
            assert!(
                !self.model.previous,
                "every worker drained and idled, but no retire"
            );
        }
    }
}

/// Run `ops` from a fresh publisher, then quiesce, and check every snapshot is released once.
fn run_ops(ops: &[Op]) {
    let log = drops();
    let created = {
        let generations = Generations::new(Tag::new(1, &log));
        let mut run = Run::new(&generations, Arc::clone(&log));
        for op in ops.iter().take(OPS) {
            run.apply(op);
        }
        run.quiesce();
        run.model.made
    };
    assert_eq!(
        log.lock().len(),
        created,
        "every snapshot is released, once"
    );
}

#[test]
fn operations_keep_the_protocol() {
    bolero::check!()
        .with_type::<Vec<Op>>()
        .for_each(|ops| run_ops(ops));
}

/// One fixed run through two flips, with publisher steps between bursts' reads and polls.
#[test]
fn a_short_run_keeps_the_protocol() {
    let arrive = |worker, count, unstamped| Op::Arrive {
        worker,
        count,
        unstamped,
    };
    let came = |worker, count, unstamped| Between::Arrive {
        worker,
        count,
        unstamped,
    };
    let burst = |worker, between: Vec<Between>| Op::Burst {
        worker,
        max: 1,
        between,
    };
    let flip = Between::Publish(Publish::Flip);
    let retire = Between::Publish(Publish::Retire);
    let mut ops = vec![Op::Join, Op::Join];
    for _ in 0..2 {
        ops.extend([
            arrive(0, 2, false),
            arrive(1, 1, true),
            Op::Publish(Publish::Begin),
            Op::Read { worker: 0 },
            burst(1, vec![flip, came(1, 1, false)]),
            burst(0, vec![came(0, 1, false), retire]),
            burst(0, vec![retire]),
            burst(1, vec![retire]),
            burst(0, vec![retire]),
            Op::Idle { worker: 1 },
            burst(1, vec![retire]),
        ]);
    }
    run_ops(&ops);
}
