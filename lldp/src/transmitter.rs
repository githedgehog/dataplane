// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! The per-port transmit state machine of IEEE 802.1AB-2016 §9.2.8 and §9.2.9.
//!
//! ```text
//!             link up, something to advertise
//!   Silent ─────────────────────────────────▶ Fast ──── txFastInit sent ───▶ Steady
//!     ▲                                         │                              │
//!     └──── link down; nothing to advertise; ───┴──────────────────────────────┘
//!           a new chassis or port ID (after a shutdown frame and reinitDelay)
//! ```
//!
//! Each state is a type, and a step consumes the port in one state and returns it in the next.
//! Only the advertising states hold an [`Advertisement`], so sending without one does not compile.
//!
//! Two deliberate departures from the standard:
//! * Fast start is triggered by the link coming up, not by `newNeighbor` from the receive machine,
//!   which this dataplane does not have yet. A neighbour learns about us within a second either way.
//! * A dataplane that stops while a link is up sends a shutdown frame, so neighbours forget it at once
//!   instead of when its time to live runs out.

use crate::advert::Advertisement;
use crate::sink::{FrameSink, Refused};
use crate::timing::Timing;
use std::time::{Duration, Instant};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

/// Whether a port can carry frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Link {
    /// The link is down; nothing can be sent.
    Down,
    /// The link is up.
    Up,
}

/// What one port's transmitter reads and writes.
pub struct Inputs<S> {
    /// The port's link state. The port is gone when the sender is dropped.
    pub link: watch::Receiver<Link>,
    /// What to advertise, or `None` for nothing. Dropping the sender stops the transmitter.
    pub advertisement: watch::Receiver<Option<Advertisement>>,
    /// Where frames go.
    pub sink: S,
    /// How often to send.
    pub timing: Timing,
}

/// Advertise on one port until `cancel` fires or the port goes away.
pub async fn transmit<S: FrameSink>(inputs: Inputs<S>, cancel: CancellationToken) {
    let now = clock::now();
    let mut machine = Machine::Silent(Port {
        io: Io {
            credit: Credit::new(inputs.timing.credit_max.get(), now),
            link: inputs.link,
            advertisement: inputs.advertisement,
            sink: inputs.sink,
            timing: inputs.timing,
            cancel,
        },
        state: Silent { resume_at: None },
    });
    loop {
        machine = match machine {
            Machine::Silent(port) => port.step().await,
            Machine::Fast(port) => port.step().await,
            Machine::Steady(port) => port.step().await,
            Machine::Done => return,
        };
    }
}

enum Machine<S> {
    Silent(Port<S, Silent>),
    Fast(Port<S, Fast>),
    Steady(Port<S, Steady>),
    Done,
}

struct Port<S, State> {
    io: Io<S>,
    state: State,
}

/// Not advertising: the link is down, there is nothing to advertise, or a shutdown is settling.
struct Silent {
    /// After a shutdown frame, the end of `reinitDelay`.
    resume_at: Option<Instant>,
}

/// Advertising every `msgFastTx`, `remaining` more times.
struct Fast {
    current: Advertising,
    remaining: u8,
}

/// Advertising every `msgTxInterval`.
struct Steady {
    current: Advertising,
}

/// What both advertising states track.
struct Advertising {
    advertisement: Advertisement,
    /// When the next routine advertisement is due.
    next: Instant,
    /// An advertisement is owed but credit ran out; send it as soon as credit returns.
    owed: bool,
}

struct Io<S> {
    link: watch::Receiver<Link>,
    advertisement: watch::Receiver<Option<Advertisement>>,
    sink: S,
    timing: Timing,
    credit: Credit,
    cancel: CancellationToken,
}

/// `txCredit`: advertisements that may go out back to back, returning at one per second.
struct Credit {
    tokens: u8,
    max: u8,
    /// When the last token came back (or now, while full).
    refilled_at: Instant,
}

impl Credit {
    const REFILL: Duration = Duration::from_secs(1);

    fn new(max: u8, now: Instant) -> Credit {
        Credit {
            tokens: max,
            max,
            refilled_at: now,
        }
    }

    fn refill(&mut self, now: Instant) {
        if self.tokens == self.max {
            self.refilled_at = now;
            return;
        }
        let elapsed = now.saturating_duration_since(self.refilled_at);
        let earned = elapsed.as_secs().min(u64::from(self.max - self.tokens));
        // `earned` is at most `max - tokens`, a `u8`.
        #[allow(clippy::cast_possible_truncation)]
        let earned_u8 = earned as u8;
        self.tokens += earned_u8;
        self.refilled_at += Self::REFILL * u32::from(earned_u8);
        if self.tokens == self.max {
            self.refilled_at = now;
        }
    }

    fn take(&mut self, now: Instant) -> bool {
        self.refill(now);
        if self.tokens == 0 {
            return false;
        }
        self.tokens -= 1;
        true
    }

    /// When the next token comes back.
    fn next_at(&self) -> Instant {
        self.refilled_at + Self::REFILL
    }
}

/// What woke a waiting port.
enum Event {
    Cancelled,
    LinkChanged,
    LinkGone,
    AdvertisementChanged,
    AdvertisementGone,
    Due,
    CreditBack,
}

impl<S: FrameSink> Io<S> {
    async fn next_event(&mut self, due: Option<Instant>, credit_back: Option<Instant>) -> Event {
        tokio::select! {
            biased;
            () = self.cancel.cancelled() => Event::Cancelled,
            changed = self.link.changed() => match changed {
                Ok(()) => Event::LinkChanged,
                Err(_) => Event::LinkGone,
            },
            changed = self.advertisement.changed() => match changed {
                Ok(()) => Event::AdvertisementChanged,
                Err(_) => Event::AdvertisementGone,
            },
            () = sleep_until(due) => Event::Due,
            () = sleep_until(credit_back) => Event::CreditBack,
        }
    }

    fn link(&mut self) -> Link {
        *self.link.borrow_and_update()
    }

    fn advertisement(&mut self) -> Option<Advertisement> {
        self.advertisement.borrow_and_update().clone()
    }

    /// Send `frame`, returning `false` if the port is gone.
    fn send(&mut self, frame: Vec<u8>) -> bool {
        match self.sink.send(frame) {
            Ok(()) => true,
            Err(Refused::Full) => {
                warn!("LLDP frame refused: the port's transmit queue is full");
                true
            }
            Err(Refused::Closed) => false,
        }
    }

    /// Send `advertisement` if credit allows, returning whether it is still owed, or `None` if the port
    /// is gone.
    fn advertise(&mut self, advertisement: &Advertisement) -> Option<bool> {
        if !self.credit.take(clock::now()) {
            return Some(true);
        }
        let ttl = self.timing.ttl();
        self.send(advertisement.frame(ttl)).then_some(false)
    }
}

async fn sleep_until(deadline: Option<Instant>) {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(deadline.into()).await,
        None => std::future::pending().await,
    }
}

impl<S: FrameSink> Port<S, Silent> {
    async fn step(mut self) -> Machine<S> {
        let now = clock::now();
        let settling = self.state.resume_at.filter(|&at| at > now);
        if settling.is_none()
            && self.io.link() == Link::Up
            && let Some(advertisement) = self.io.advertisement()
        {
            return self.start(advertisement);
        }
        match self.io.next_event(settling, None).await {
            Event::Cancelled | Event::LinkGone | Event::AdvertisementGone => Machine::Done,
            Event::LinkChanged | Event::AdvertisementChanged | Event::Due | Event::CreditBack => {
                Machine::Silent(self)
            }
        }
    }

    /// The link is up and there is something to advertise: say so now, then keep saying it fast.
    fn start(mut self, advertisement: Advertisement) -> Machine<S> {
        debug!("LLDP: starting to advertise");
        let Some(owed) = self.io.advertise(&advertisement) else {
            return Machine::Done;
        };
        let current = Advertising {
            next: clock::now() + self.io.timing.fast_tx(),
            advertisement,
            owed,
        };
        let io = self.io;
        // The send just made was the first of `txFastInit`.
        match io
            .timing
            .fast_init
            .get()
            .checked_sub(1)
            .filter(|&remaining| remaining > 0)
        {
            Some(remaining) => Machine::Fast(Port {
                io,
                state: Fast { current, remaining },
            }),
            None => Machine::Steady(Port {
                state: Steady {
                    current: Advertising {
                        next: clock::now() + io.timing.tx_interval(),
                        ..current
                    },
                },
                io,
            }),
        }
    }
}

/// What an advertising state does next, before it decides which state that leaves it in.
enum Next {
    /// Keep advertising; `true` if a routine advertisement was just sent.
    Continue {
        sent_routine: bool,
    },
    /// Stop advertising, and stay quiet until `resume_at` (if any).
    Silence {
        resume_at: Option<Instant>,
    },
    Done,
}

impl<S: FrameSink> Io<S> {
    /// One step of advertising `current`, routinely every `interval`.
    async fn advertising_step(&mut self, current: &mut Advertising, interval: Duration) -> Next {
        let credit_back = current.owed.then(|| self.credit.next_at());
        match self.next_event(Some(current.next), credit_back).await {
            Event::Cancelled | Event::AdvertisementGone => {
                self.send(current.advertisement.shutdown_frame());
                Next::Done
            }
            Event::LinkGone => Next::Done,
            Event::LinkChanged => match self.link() {
                Link::Up => Next::Continue {
                    sent_routine: false,
                },
                // A downed link can carry nothing, not even a shutdown frame.
                Link::Down => Next::Silence { resume_at: None },
            },
            Event::AdvertisementChanged => match self.advertisement() {
                Some(new) if new.same_identity(&current.advertisement) => {
                    // News about us: tell the neighbour now rather than at the next interval.
                    current.advertisement = new;
                    self.owe(current)
                }
                // Nothing to advertise any more, or a different identity: retract the old one first.
                _ => {
                    if !self.send(current.advertisement.shutdown_frame()) {
                        return Next::Done;
                    }
                    Next::Silence {
                        resume_at: Some(clock::now() + self.timing.reinit_delay()),
                    }
                }
            },
            Event::CreditBack => self.owe(current),
            Event::Due => {
                current.next = clock::now() + interval;
                match self.owe(current) {
                    Next::Continue { .. } => Next::Continue { sent_routine: true },
                    other => other,
                }
            }
        }
    }

    /// Send `current` now if credit allows, else remember that it is owed.
    fn owe(&mut self, current: &mut Advertising) -> Next {
        match self.advertise(&current.advertisement) {
            Some(owed) => {
                current.owed = owed;
                Next::Continue {
                    sent_routine: false,
                }
            }
            None => Next::Done,
        }
    }
}

impl<S: FrameSink> Port<S, Fast> {
    async fn step(mut self) -> Machine<S> {
        let interval = self.io.timing.fast_tx();
        match self
            .io
            .advertising_step(&mut self.state.current, interval)
            .await
        {
            Next::Done => Machine::Done,
            Next::Silence { resume_at } => silence(self.io, resume_at),
            Next::Continue { sent_routine } => {
                if sent_routine {
                    self.state.remaining -= 1;
                }
                if self.state.remaining > 0 {
                    return Machine::Fast(self);
                }
                let mut current = self.state.current;
                current.next = clock::now() + self.io.timing.tx_interval();
                Machine::Steady(Port {
                    io: self.io,
                    state: Steady { current },
                })
            }
        }
    }
}

impl<S: FrameSink> Port<S, Steady> {
    async fn step(mut self) -> Machine<S> {
        let interval = self.io.timing.tx_interval();
        match self
            .io
            .advertising_step(&mut self.state.current, interval)
            .await
        {
            Next::Done => Machine::Done,
            Next::Silence { resume_at } => silence(self.io, resume_at),
            Next::Continue { .. } => Machine::Steady(self),
        }
    }
}

fn silence<S>(io: Io<S>, resume_at: Option<Instant>) -> Machine<S> {
    debug!("LLDP: stopping advertising");
    Machine::Silent(Port {
        io,
        state: Silent { resume_at },
    })
}
