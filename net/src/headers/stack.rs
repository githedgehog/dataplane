// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Bounded header stacks with lazy allocation.

use arrayvec::ArrayVec;

/// At most `N` values, allocated on first insertion.
///
/// Boxing keeps empty header stacks small at the cost of an allocation for packets
/// with VLAN tags or IPv6 extension headers.
#[derive(Debug, Clone)]
pub struct Stack<T, const N: usize>(Option<Box<ArrayVec<T, N>>>);

// Compare contents so a cleared stack equals a never-allocated stack.
impl<T: PartialEq, const N: usize> PartialEq for Stack<T, N> {
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl<T: Eq, const N: usize> Eq for Stack<T, N> {}

impl<T: core::hash::Hash, const N: usize> core::hash::Hash for Stack<T, N> {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.as_slice().hash(state);
    }
}

impl<T, const N: usize> Default for Stack<T, N> {
    fn default() -> Self {
        Stack(None)
    }
}

impl<T, const N: usize> Stack<T, N> {
    /// The most values this stack can hold.
    pub const CAPACITY: usize = N;

    /// Number of values currently held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.as_ref().map_or(0, |v| v.len())
    }

    /// Whether the stack is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The values, in order.
    #[must_use]
    pub fn as_slice(&self) -> &[T] {
        self.0.as_ref().map_or(&[], |v| v.as_slice())
    }

    /// The values, in order, mutably.
    pub fn as_mut_slice(&mut self) -> &mut [T] {
        self.0.as_mut().map_or(&mut [], |v| v.as_mut_slice())
    }

    /// Iterate the values in order.
    pub fn iter(&self) -> core::slice::Iter<'_, T> {
        self.as_slice().iter()
    }

    /// Iterate the values in order, mutably.
    pub fn iter_mut(&mut self) -> core::slice::IterMut<'_, T> {
        self.as_mut_slice().iter_mut()
    }

    /// The value at `index`, if there is one.
    #[must_use]
    pub fn get(&self, index: usize) -> Option<&T> {
        self.as_slice().get(index)
    }

    /// The first value, if any.
    #[must_use]
    pub fn first(&self) -> Option<&T> {
        self.as_slice().first()
    }

    /// The last value, if any.
    #[must_use]
    pub fn last(&self) -> Option<&T> {
        self.as_slice().last()
    }

    /// Remove all values, retaining the allocation.
    pub fn clear(&mut self) {
        if let Some(v) = self.0.as_mut() {
            v.clear();
        }
    }

    /// Append `value`.
    ///
    /// # Panics
    ///
    /// Panics if the stack already holds `N` values.
    pub(super) fn push(&mut self, value: T) {
        self.0.get_or_insert_with(Box::default).push(value);
    }

    /// Append `value`.
    ///
    /// # Errors
    ///
    /// Returns the value in a [`arrayvec::CapacityError`] if the stack is full.
    pub fn try_push(&mut self, value: T) -> Result<(), arrayvec::CapacityError<T>> {
        self.0.get_or_insert_with(Box::default).try_push(value)
    }

    /// Insert `value` at `index`, shifting later values right.
    ///
    /// # Panics
    ///
    /// Panics if the stack is full or `index` is past the end.
    pub fn insert(&mut self, index: usize, value: T) {
        self.0.get_or_insert_with(Box::default).insert(index, value);
    }

    /// Remove and return the value at `index`, shifting later values left.
    ///
    /// # Panics
    ///
    /// Panics if `index` is out of bounds.
    pub fn remove(&mut self, index: usize) -> T {
        #[allow(clippy::expect_used)] // out-of-bounds is a caller bug, as it is for ArrayVec
        self.0
            .as_mut()
            .expect("remove from an empty header stack")
            .remove(index)
    }
}

impl<T, const N: usize> core::ops::Index<usize> for Stack<T, N> {
    type Output = T;
    fn index(&self, index: usize) -> &T {
        &self.as_slice()[index]
    }
}

impl<'a, T, const N: usize> IntoIterator for &'a mut Stack<T, N> {
    type Item = &'a mut T;
    type IntoIter = core::slice::IterMut<'a, T>;
    fn into_iter(self) -> Self::IntoIter {
        self.iter_mut()
    }
}

impl<'a, T, const N: usize> IntoIterator for &'a Stack<T, N> {
    type Item = &'a T;
    type IntoIter = core::slice::Iter<'a, T>;
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<T, const N: usize> FromIterator<T> for Stack<T, N> {
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        let inner: ArrayVec<T, N> = iter.into_iter().collect();
        if inner.is_empty() {
            Stack(None)
        } else {
            Stack(Some(Box::new(inner)))
        }
    }
}

#[cfg(test)]
mod test {
    use super::Stack;

    #[test]
    fn empty_holds_no_allocation() {
        let s: Stack<u32, 4> = Stack::default();
        assert!(s.0.is_none(), "an untouched stack must not allocate");
        assert!(s.is_empty());
        assert_eq!(s.len(), 0);
        assert_eq!(s.as_slice(), &[] as &[u32]);
        assert_eq!(s.get(0), None);
        assert_eq!(s.last(), None);
        assert_eq!(s.iter().count(), 0);
    }

    #[test]
    fn push_insert_remove_behave_like_a_vec() {
        let mut s: Stack<u32, 4> = Stack::default();
        s.push(2);
        s.push(3);
        s.insert(0, 1);
        assert_eq!(s.as_slice(), &[1, 2, 3]);
        assert_eq!(s.len(), 3);
        assert_eq!(s.last(), Some(&3));
        assert_eq!(s.remove(1), 2);
        assert_eq!(s.as_slice(), &[1, 3]);
        for v in &mut s {
            *v *= 10;
        }
        assert_eq!(s.as_slice(), &[10, 30]);
        s.clear();
        assert!(s.is_empty());
    }

    #[test]
    fn cleared_equals_fresh() {
        let mut used: Stack<u32, 4> = Stack::default();
        used.push(7);
        used.clear();
        assert_eq!(used, Stack::default(), "cleared must equal never-used");
    }

    #[test]
    fn collects_from_an_iterator() {
        let s: Stack<u32, 4> = [1, 2, 3].into_iter().collect();
        assert_eq!(s.as_slice(), &[1, 2, 3]);
        let empty: Stack<u32, 4> = core::iter::empty().collect();
        assert!(empty.0.is_none(), "collecting nothing must not allocate");
    }
}
