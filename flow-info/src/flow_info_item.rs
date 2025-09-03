// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use downcast_rs::{DowncastSync, impl_downcast};
use std::fmt::Debug;

pub trait FlowInfoItem: DowncastSync + Debug {}
impl_downcast!(sync FlowInfoItem);

impl<T> FlowInfoItem for T where T: Debug + Send + Sync + 'static {}

pub trait ExtractRef {
    fn extract_ref<T>(&self) -> Option<&T>
    where
        T: Debug + Send + Sync + 'static;
}

pub trait ExtractMut {
    fn extract_mut<T>(&mut self) -> Option<&mut T>
    where
        T: Debug + Send + Sync + 'static;
}

impl ExtractRef for Option<Box<dyn FlowInfoItem>> {
    fn extract_ref<T>(&self) -> Option<&T>
    where
        T: Debug + Send + Sync + 'static,
    {
        match self.as_ref() {
            Some(v) => v.extract_ref::<T>(),
            None => None,
        }
    }
}

impl ExtractMut for Option<Box<dyn FlowInfoItem>> {
    fn extract_mut<T>(&mut self) -> Option<&mut T>
    where
        T: Debug + Send + Sync + 'static,
    {
        match self.as_mut() {
            Some(v) => v.extract_mut::<T>(),
            None => None,
        }
    }
}

impl ExtractRef for Option<&Box<dyn FlowInfoItem>> {
    fn extract_ref<T>(&self) -> Option<&T>
    where
        T: Debug + Send + Sync + 'static,
    {
        match self {
            Some(v) => v.extract_ref::<T>(),
            None => None,
        }
    }
}

impl ExtractMut for Option<&mut Box<dyn FlowInfoItem>> {
    fn extract_mut<T>(&mut self) -> Option<&mut T>
    where
        T: Debug + Send + Sync + 'static,
    {
        match self {
            Some(v) => v.extract_mut::<T>(),
            None => None,
        }
    }
}

impl ExtractRef for Box<dyn FlowInfoItem> {
    fn extract_ref<T>(&self) -> Option<&T>
    where
        T: Debug + Send + Sync + 'static,
    {
        self.downcast_ref::<T>()
    }
}

impl ExtractMut for Box<dyn FlowInfoItem> {
    fn extract_mut<T>(&mut self) -> Option<&mut T>
    where
        T: Debug + Send + Sync + 'static,
    {
        self.downcast_mut::<T>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_option_box_extract_ref() {
        let mut option: Option<Box<dyn FlowInfoItem>> = Some(Box::new(100));
        assert_eq!(option.extract_ref::<i32>().unwrap(), &100);
        assert_eq!(option.extract_mut::<i32>().unwrap(), &100);
        *option.extract_mut::<i32>().unwrap() = 200;
        assert_eq!(option.extract_ref::<i32>().unwrap(), &200);

        assert_eq!(option.as_ref().extract_ref::<i32>().unwrap(), &200);
        assert_eq!(option.as_mut().extract_mut::<i32>().unwrap(), &200);
        *option.as_mut().unwrap().extract_mut::<i32>().unwrap() = 300;
        assert_eq!(option.extract_ref::<i32>().unwrap(), &300);
    }

    #[test]
    fn test_box_extract_ref() {
        let mut boxv: Box<dyn FlowInfoItem> = Box::new(100);
        assert_eq!(boxv.extract_ref::<i32>().unwrap(), &100);
        *boxv.extract_mut::<i32>().unwrap() = 200;
        assert_eq!(boxv.extract_ref::<i32>().unwrap(), &200);
    }
}
