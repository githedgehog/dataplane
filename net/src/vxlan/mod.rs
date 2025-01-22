//! VXLAN validation and manipulation tools.

mod header;
mod vni;

pub use header::{Vxlan, VxlanError};
pub use vni::{InvalidVni, Vni};
