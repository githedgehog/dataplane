use thiserror::Error;

#[allow(dead_code)]
#[derive(Error, Debug, PartialEq)]
pub enum RouterError {
    #[error("No such interface (ifindex {0})")]
    NoSuchInterface(u32),

    #[error("The interface is already attached to a distinct VRF")]
    AlreadyAttached,
}
