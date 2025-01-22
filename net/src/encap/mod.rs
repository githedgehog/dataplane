use crate::vxlan::Vxlan;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Encap {
    Vxlan(Vxlan)
}