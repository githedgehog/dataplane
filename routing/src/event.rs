// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Generic thread-local event logs. See the tests for sample usage

#![allow(unused)]

use chrono::DateTime;
use chrono::Local;
use std::cell::RefCell;
use std::fmt::Display;

/// An `Event` is a wrapper over a generic type T that represents something that happened.
/// The only requirement for T is to implement `Display`. This implementation uses generics
/// so that the same code can be used by distinct subsystems, each defining its own event types.
pub(crate) struct Event<T>
where
    T: Display,
{
    code: T,
    ord: usize,
    time: DateTime<Local>,
}
impl<T: Display> Event<T> {
    pub(crate) fn new(code: T, ord: usize) -> Self {
        Self {
            code,
            ord,
            time: Local::now(),
        }
    }
}

/// A structure to orderly store `Events`.
/// An `EventLog` has a maximum capacity (it's a circular buffer) and automatically
/// timestamps `Events`, preserving the order in which they were added. The current
/// implementation is meant to use thread-local `EventLog`. Shared or thread-safe
/// `EventLog`s may be created if needed later.
pub(crate) struct EventLog<T: Display> {
    name: String,
    items: Vec<Event<T>>,
    count: usize,
    next: usize,
    max: usize,
    ord: usize,
}
impl<T: Display> EventLog<T> {
    pub fn new(name: &str, max: usize) -> Self {
        Self {
            name: name.to_owned(),
            items: Vec::with_capacity(max),
            max,
            count: 0,
            next: 0,
            ord: 0,
        }
    }
    pub fn add(&mut self, code: T) {
        let event = Event::new(code, self.ord);
        if self.count < self.max {
            self.count += 1;
            self.items.push(event);
        } else {
            self.items[self.next] = event;
            self.next = (self.next + 1) % self.max;
        }
        self.ord += 1;
    }
}
impl<T: Display> Display for Event<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let fmt_simple = "%Y-%m-%dT %H:%M:%S";
        let mut time = self.time.format(fmt_simple).to_string();
        write!(f, " {:<4} {}: {}", self.ord, time, self.code.to_string())
    }
}

impl<T: Display> Display for EventLog<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, " {}", self.name)?;
        writeln!(
            f,
            " generated: {} stored: {} capacity: {}",
            self.ord, self.count, self.max
        )?;
        writeln!(f, " ━━━━━━━━━━━━━")?;

        for num in 0..self.count {
            let index = (self.next + num) % self.max;
            let event = &self.items[index];
            writeln!(f, "{event}")?;
        }
        Ok(())
    }
}

/// macro to create an  `EventLog` as thread-local, for a certain type
/// and a maximum occupancy
macro_rules! make_event_log {
    ($name:ident, $type:ty, $max:expr) => {
        thread_local! {
            pub static $name: RefCell<EventLog<$type>> = RefCell::new(EventLog::new(stringify!($name), $max));
        }
    }
}

/// macro to produce and store an `Event` on the given thread-local `EventLog`
macro_rules! event {
    ($name:ident, $item:expr) => {
        $name.with(|evlog| evlog.borrow_mut().add($item))
    };
}

#[cfg(test)]
mod test {
    use crate::event::EventLog;
    use std::cell::RefCell;

    #[test]
    fn test_event_log_string() {
        // create a thread-local event log called TEST, with capacity 100, for String events
        make_event_log!(TEST, String, 100);

        // Add some events
        event!(TEST, "The system booted".to_string());
        event!(TEST, "I had breakfast".to_string());
        event!(TEST, "The mouse ate the cat".to_string());
        event!(TEST, "The dog ate the mouse".to_string());
        event!(TEST, "Something good happened".to_string());
        event!(TEST, "Oh! Catastrophic event!".to_string());
        event!(TEST, "A cable was unplugged".to_string());
        event!(TEST, "That thing got configured successfully".to_string());
        event!(TEST, "Unfortunately a bug happened".to_string());
        event!(TEST, "The system is going down now...".to_string());

        // Display. N.B. the TEST EventLog is thread-local, so accessing the
        // eventlog from other threads shall not be possible
        TEST.with(|el| {
            let el = el.borrow();
            println!("{el}");
        })
    }

    #[test]
    fn test_event_log_string_with_loss() {
        // Identical to the above, but when events surpass capacity

        make_event_log!(TEST, String, 5);

        event!(TEST, "The system booted".to_string());
        event!(TEST, "I had breakfast".to_string());
        event!(TEST, "The mouse ate the cat".to_string());
        event!(TEST, "The dog ate the mouse".to_string());
        event!(TEST, "Something good happened".to_string());
        event!(TEST, "Oh! Catastrophic event!".to_string());
        event!(TEST, "A cable was unplugged".to_string());
        event!(TEST, "That thing got configured successfully".to_string());
        event!(TEST, "Unfortunately a bug happened".to_string());
        event!(TEST, "The system is going down now...".to_string());

        TEST.with(|el| {
            let el = el.borrow();
            println!("{el}");
        })
    }
}
