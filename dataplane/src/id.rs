use core::marker::PhantomData;
use std::fmt::Debug;
use std::hash::Hash;

#[repr(transparent)]
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct TypedId<T: Copy + Clone + Debug + Eq + PartialEq + Hash> {
    inner: u64,
    _marker: PhantomData<*const T>,
}
pub type Id<T> = TypedId<PhantomData<*const T>>;

impl<T> Id<T> {
    pub fn new(inner: u64) -> Self {
        Self {
            inner,
            _marker: PhantomData,
        }
    }

    pub fn get(&self) -> u64 {
        self.inner
    }
}
