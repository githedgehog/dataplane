// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use concurrency::slot::Slot;
use concurrency::sync::Arc;

use lookup::Lookup;

use crate::generation::Generation;
use crate::head::MutableHead;
use crate::merge::MergeInto;
pub struct FrozenEntry<F> {
    pub generation: Generation,
    pub layer: Arc<F>,
}

impl<F> Clone for FrozenEntry<F> {
    fn clone(&self) -> Self {
        Self {
            generation: self.generation,
            layer: Arc::clone(&self.layer),
        }
    }
}

impl<F: core::fmt::Debug> core::fmt::Debug for FrozenEntry<F> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FrozenEntry")
            .field("generation", &self.generation)
            .field("layer", &self.layer)
            .finish()
    }
}
pub struct DrainEvent<F> {
    pub generation: Generation,
    pub layer: Arc<F>,
}

impl<F> Clone for DrainEvent<F> {
    fn clone(&self) -> Self {
        Self {
            generation: self.generation,
            layer: Arc::clone(&self.layer),
        }
    }
}

impl<F: core::fmt::Debug> core::fmt::Debug for DrainEvent<F> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DrainEvent")
            .field("generation", &self.generation)
            .field("layer", &self.layer)
            .finish()
    }
}
pub struct Snapshot<H, F, T>
where
    H: MutableHead<Frozen = F>,
    F: Lookup<H::Key, H::Action>,
    T: Lookup<H::Key, H::Action>,
{
    head: Arc<H>,
    frozen: Arc<Vec<FrozenEntry<F>>>,
    tail: Arc<T>,
}
impl<H, F, T> Snapshot<H, F, T>
where
    H: MutableHead<Frozen = F>,
    F: Lookup<H::Key, H::Action>,
    T: Lookup<H::Key, H::Action>,
{
    pub fn lookup(&self, input: &H::Key) -> Option<&H::Action> {
        if let Some(v) = self.head.lookup(input) {
            return Some(v);
        }
        for entry in self.frozen.iter() {
            if let Some(v) = entry.layer.lookup(input) {
                return Some(v);
            }
        }
        self.tail.lookup(input)
    }
    pub fn lookup_at(&self, input: &H::Key, horizon: Generation) -> Option<&H::Action> {
        for entry in self.frozen.iter() {
            if entry.generation > horizon {
                continue;
            }
            if let Some(v) = entry.layer.lookup(input) {
                return Some(v);
            }
        }
        self.tail.lookup(input)
    }

    #[must_use]
    pub fn frozen_depth(&self) -> usize {
        self.frozen.len()
    }
    #[must_use]
    pub fn frozen(&self) -> &[FrozenEntry<F>] {
        &self.frozen
    }
}
#[cfg(feature = "subscribe")]
const DEFAULT_DRAIN_CHANNEL_CAPACITY: usize = 16;
pub struct Cascade<H, F, T>
where
    H: MutableHead<Frozen = F>,
    F: Lookup<H::Key, H::Action>,
    T: Lookup<H::Key, H::Action>,
{
    head: Slot<H>,
    frozen: Slot<Vec<FrozenEntry<F>>>,
    tail: Slot<T>,
    #[cfg(feature = "subscribe")]
    drain_sender: tokio::sync::broadcast::Sender<DrainEvent<F>>,
}

impl<H, F, T> Cascade<H, F, T>
where
    H: MutableHead<Frozen = F>,
    F: Lookup<H::Key, H::Action>,
    T: Lookup<H::Key, H::Action>,
{
    pub fn new(head: H, tail: T) -> Self {
        #[cfg(feature = "subscribe")]
        let (drain_sender, _) = tokio::sync::broadcast::channel(DEFAULT_DRAIN_CHANNEL_CAPACITY);
        Self {
            head: Slot::from_pointee(head),
            frozen: Slot::from_pointee(Vec::new()),
            tail: Slot::from_pointee(tail),
            #[cfg(feature = "subscribe")]
            drain_sender,
        }
    }
    #[cfg(feature = "subscribe")]
    pub fn with_drain_capacity(head: H, tail: T, capacity: usize) -> Self {
        let (drain_sender, _) = tokio::sync::broadcast::channel(capacity);
        Self {
            head: Slot::from_pointee(head),
            frozen: Slot::from_pointee(Vec::new()),
            tail: Slot::from_pointee(tail),
            drain_sender,
        }
    }
    #[cfg(feature = "subscribe")]
    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<DrainEvent<F>> {
        self.drain_sender.subscribe()
    }

    #[cfg(feature = "subscribe")]
    #[must_use]
    pub fn subscriber_count(&self) -> usize {
        self.drain_sender.receiver_count()
    }
    pub fn snapshot(&self) -> Snapshot<H, F, T> {
        Snapshot {
            head: self.head.load_full(),
            frozen: self.frozen.load_full(),
            tail: self.tail.load_full(),
        }
    }
    pub fn write(&self, op: H::Op) {
        self.head.load_full().write(op);
    }
    #[must_use]
    pub fn head_for_writing(&self) -> Arc<H> {
        self.head.load_full()
    }
    pub fn rotate<MkH: FnOnce() -> H>(&self, generation: Generation, fresh_head: MkH) {
        let old_head = self.head.load_full();
        let new_layer: Arc<F> = Arc::new(old_head.freeze());

        #[cfg(feature = "subscribe")]
        let layer_for_emit = Arc::clone(&new_layer);

        let current = self.frozen.load_full();
        let mut next: Vec<FrozenEntry<F>> = Vec::with_capacity(current.len() + 1);
        next.push(FrozenEntry {
            generation,
            layer: new_layer,
        });
        next.extend(current.iter().cloned());

        self.frozen.store(Arc::new(next));
        self.head.store(Arc::new(fresh_head()));
        #[cfg(feature = "subscribe")]
        {
            let _ = self.drain_sender.send(DrainEvent {
                generation,
                layer: layer_for_emit,
            });
        }

        drop(old_head);
    }
    pub fn compact(&self, keep: usize)
    where
        F: MergeInto<T>,
    {
        let current = self.frozen.load_full();
        if current.len() <= keep {
            return;
        }
        let to_keep: Vec<FrozenEntry<F>> = current[..keep].to_vec();
        let to_merge: &[FrozenEntry<F>] = &current[keep..];
        self.fold_and_publish(&to_keep, to_merge);
    }
    pub fn compact_through(&self, watermark: Generation)
    where
        F: MergeInto<T>,
    {
        let current = self.frozen.load_full();
        let mut to_keep: Vec<FrozenEntry<F>> = Vec::new();
        let mut to_merge: Vec<FrozenEntry<F>> = Vec::new();
        for entry in current.iter() {
            if entry.generation > watermark {
                to_keep.push(entry.clone());
            } else {
                to_merge.push(entry.clone());
            }
        }
        if to_merge.is_empty() {
            return;
        }
        self.fold_and_publish(&to_keep, &to_merge);
    }
    fn fold_and_publish(&self, to_keep: &[FrozenEntry<F>], to_merge: &[FrozenEntry<F>])
    where
        F: MergeInto<T>,
    {
        let old_tail = self.tail.load_full();
        let mut iter = to_merge.iter().rev();
        let Some(oldest) = iter.next() else {
            return;
        };
        let mut accumulator: T = oldest.layer.merge_into(old_tail.as_ref());
        for entry in iter {
            accumulator = entry.layer.merge_into(&accumulator);
        }

        self.tail.store(Arc::new(accumulator));
        self.frozen.store(Arc::new(to_keep.to_vec()));

        drop(old_tail);
    }

    #[must_use]
    pub fn frozen_depth(&self) -> usize {
        self.frozen.load_full().len()
    }
}
