// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Compile ACL rules into `rte_flow` components.
//!
//! Translates [`AclRule`] match fields and action sequences into
//! the `(FlowAttr, Vec<FlowMatch>, Vec<FlowAction>)` triple that
//! `rte_flow_create` expects.

use std::net::{Ipv4Addr, Ipv6Addr};

use acl::{AclRule, ActionSequence, Fate, FieldMatch, Metadata, Step};
use dpdk::flow::{
    FlowAction, FlowAttr, FlowMatch, FlowSpec, RawEthHeader, RawIpv4Header, RawIpv6Header,
    RawTcpHeader, RawUdpHeader,
};
use net::eth::ethtype::EthType;
use net::eth::mac::Mac;

/// Error during `rte_flow` rule compilation.
#[derive(Debug, thiserror::Error)]
pub enum CompileError {
    /// A match field uses a range or prefix that can't be expressed
    /// as an exact spec+mask in `rte_flow` (v1 limitation).
    #[error("non-exact match not yet supported for rte_flow: {field}")]
    NonExactMatch {
        /// Which field had the unsupported match type.
        field: &'static str,
    },
    /// An action step isn't supported by the `rte_flow` backend.
    #[error("unsupported action step for rte_flow")]
    UnsupportedStep,
    /// A fate isn't supported by the `rte_flow` backend.
    #[error("unsupported fate for rte_flow: {fate:?}")]
    UnsupportedFate {
        /// The unsupported fate.
        fate: Fate,
    },
}

/// Configuration for the `rte_flow` lowering pass.
#[derive(Debug, Clone)]
pub struct FlowLoweringConfig {
    /// `rte_flow` group (0 = root).
    pub group: u32,
    /// Apply as ingress rule.
    pub ingress: bool,
    /// Apply as egress rule.
    pub egress: bool,
    /// Apply as transfer rule (eswitch offload).
    pub transfer: bool,
}

impl Default for FlowLoweringConfig {
    fn default() -> Self {
        Self {
            group: 0,
            ingress: true,
            egress: false,
            transfer: false,
        }
    }
}

/// A compiled `rte_flow` rule — ready to pass to `rte_flow_create`.
/// A compiled `rte_flow` rule — ready to pass to `rte_flow_create`.
pub struct CompiledFlowRule {
    /// Flow attributes (group, priority, direction).
    pub attr: FlowAttr,
    /// Match pattern items.
    pub pattern: Vec<FlowMatch>,
    /// Action sequence.
    pub actions: Vec<FlowAction>,
}

/// Compile a single [`AclRule`] into an `rte_flow` rule.
///
/// # Errors
///
/// Returns [`CompileError`] if the rule contains match fields or
/// actions that can't be expressed in `rte_flow` (e.g., port ranges).
pub fn compile_rule<M: Metadata>(
    rule: &AclRule<M>,
    config: &FlowLoweringConfig,
) -> Result<CompiledFlowRule, CompileError> {
    let attr = compile_attr(rule, config);
    let pattern = compile_pattern(rule)?;
    let actions = compile_actions(rule.actions())?;

    Ok(CompiledFlowRule {
        attr,
        pattern,
        actions,
    })
}

/// Build the flow attributes from rule priority and config.
fn compile_attr<M: Metadata>(rule: &AclRule<M>, config: &FlowLoweringConfig) -> FlowAttr {
    FlowAttr {
        group: config.group,
        // rte_flow: lower priority value = higher precedence (same as ours)
        priority: rule.priority().get(),
        ingress: config.ingress,
        egress: config.egress,
        transfer: config.transfer,
    }
}

/// Translate match fields into `rte_flow` pattern items.
fn compile_pattern<M: Metadata>(rule: &AclRule<M>) -> Result<Vec<FlowMatch>, CompileError> {
    let pm = rule.packet_match();
    let mut pattern = Vec::new();

    // Ethernet
    if let Some(eth) = pm.eth() {
        let has_any_field =
            eth.src_mac.is_select() || eth.dst_mac.is_select() || eth.ether_type.is_select();

        if has_any_field {
            let spec = RawEthHeader::new(
                select_or_zero_mac(&eth.src_mac),
                select_or_zero_mac(&eth.dst_mac),
                select_or_zero_ethtype(&eth.ether_type),
            );
            let mask = RawEthHeader::new(
                mask_mac(&eth.src_mac),
                mask_mac(&eth.dst_mac),
                mask_ethtype(&eth.ether_type),
            );
            pattern.push(FlowMatch::Eth(FlowSpec::new_with_mask(spec, mask)));
        }
    }

    // IPv4
    if let Some(ipv4) = pm.ipv4() {
        let src = exact_ipv4(&ipv4.src, "ipv4_src")?;
        let dst = exact_ipv4(&ipv4.dst, "ipv4_dst")?;

        let spec = RawIpv4Header {
            src: src.unwrap_or(Ipv4Addr::UNSPECIFIED),
            dst: dst.unwrap_or(Ipv4Addr::UNSPECIFIED),
        };
        let mask = RawIpv4Header {
            src: if src.is_some() {
                Ipv4Addr::new(255, 255, 255, 255)
            } else {
                Ipv4Addr::UNSPECIFIED
            },
            dst: if dst.is_some() {
                Ipv4Addr::new(255, 255, 255, 255)
            } else {
                Ipv4Addr::UNSPECIFIED
            },
        };
        pattern.push(FlowMatch::Ipv4(FlowSpec::new_with_mask(spec, mask)));
    }

    // IPv6
    if let Some(ipv6) = pm.ipv6() {
        let src = exact_ipv6(&ipv6.src, "ipv6_src")?;
        let dst = exact_ipv6(&ipv6.dst, "ipv6_dst")?;

        let spec = RawIpv6Header {
            src: src.unwrap_or(Ipv6Addr::UNSPECIFIED),
            dst: dst.unwrap_or(Ipv6Addr::UNSPECIFIED),
        };
        let mask = RawIpv6Header {
            src: if src.is_some() {
                Ipv6Addr::new(0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff)
            } else {
                Ipv6Addr::UNSPECIFIED
            },
            dst: if dst.is_some() {
                Ipv6Addr::new(0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff)
            } else {
                Ipv6Addr::UNSPECIFIED
            },
        };
        pattern.push(FlowMatch::Ipv6(FlowSpec::new_with_mask(spec, mask)));
    }

    // TCP
    if let Some(tcp) = pm.tcp() {
        let src = exact_port(&tcp.src, "tcp_src")?;
        let dst = exact_port(&tcp.dst, "tcp_dst")?;

        let spec = RawTcpHeader {
            src_port: src.unwrap_or(0),
            dst_port: dst.unwrap_or(0),
        };
        let mask = RawTcpHeader {
            src_port: if src.is_some() { 0xFFFF } else { 0 },
            dst_port: if dst.is_some() { 0xFFFF } else { 0 },
        };
        pattern.push(FlowMatch::Tcp(FlowSpec::new_with_mask(spec, mask)));
    }

    // UDP
    if let Some(udp) = pm.udp() {
        let src = exact_port(&udp.src, "udp_src")?;
        let dst = exact_port(&udp.dst, "udp_dst")?;

        let spec = RawUdpHeader {
            src_port: src.unwrap_or(0),
            dst_port: dst.unwrap_or(0),
        };
        let mask = RawUdpHeader {
            src_port: if src.is_some() { 0xFFFF } else { 0 },
            dst_port: if dst.is_some() { 0xFFFF } else { 0 },
        };
        pattern.push(FlowMatch::Udp(FlowSpec::new_with_mask(spec, mask)));
    }

    // End marker
    pattern.push(FlowMatch::End);

    Ok(pattern)
}

/// Translate an action sequence into `rte_flow` actions.
fn compile_actions(actions: &ActionSequence) -> Result<Vec<FlowAction>, CompileError> {
    let mut flow_actions = Vec::new();

    // Steps
    for step in actions.steps() {
        match step {
            Step::Mark(v) => {
                flow_actions.push(FlowAction::Mark(dpdk::flow::FlowMark(*v)));
            }
            Step::Count(id) => {
                flow_actions.push(FlowAction::Count(dpdk::flow::CounterId(*id)));
            }
            _ => return Err(CompileError::UnsupportedStep),
        }
    }

    // Fate
    match actions.fate() {
        Fate::Drop => flow_actions.push(FlowAction::Drop),
        Fate::Forward => flow_actions.push(FlowAction::PassThrough),
        Fate::Trap => {
            // Trap = punt to software. In rte_flow this is typically
            // a Mark + Queue(software_rx_queue), but without knowing
            // the software queue we use PassThrough as a placeholder.
            flow_actions.push(FlowAction::PassThrough);
        }
        fate @ Fate::Jump(_) => {
            return Err(CompileError::UnsupportedFate { fate });
        }
    }

    // End marker
    flow_actions.push(FlowAction::End);

    Ok(flow_actions)
}

// ---- Match field helpers ----

/// Extract an exact IPv4 address from a prefix match.
/// Returns `Ok(None)` for Ignore, `Ok(Some(addr))` for /32,
/// `Err` for non-/32 prefixes.
fn exact_ipv4(
    field: &FieldMatch<acl::Ipv4Prefix>,
    name: &'static str,
) -> Result<Option<Ipv4Addr>, CompileError> {
    match field.as_select() {
        None => Ok(None),
        Some(pfx) if pfx.prefix_len() == 32 => Ok(Some(pfx.addr())),
        Some(_) => Err(CompileError::NonExactMatch { field: name }),
    }
}

/// Extract an exact IPv6 address from a prefix match.
fn exact_ipv6(
    field: &FieldMatch<acl::Ipv6Prefix>,
    name: &'static str,
) -> Result<Option<Ipv6Addr>, CompileError> {
    match field.as_select() {
        None => Ok(None),
        Some(pfx) if pfx.prefix_len() == 128 => Ok(Some(pfx.addr())),
        Some(_) => Err(CompileError::NonExactMatch { field: name }),
    }
}

/// Extract an exact port from a port range match.
/// Returns `Ok(None)` for Ignore, `Ok(Some(port))` for exact (min==max),
/// `Err` for actual ranges.
fn exact_port(
    field: &FieldMatch<acl::PortRange<u16>>,
    name: &'static str,
) -> Result<Option<u16>, CompileError> {
    match field.as_select() {
        None => Ok(None),
        Some(range) if range.min == range.max => Ok(Some(range.min)),
        Some(_) => Err(CompileError::NonExactMatch { field: name }),
    }
}

/// Get MAC value or all-zeros for Ignore.
fn select_or_zero_mac(field: &FieldMatch<Mac>) -> Mac {
    field
        .as_select()
        .copied()
        .unwrap_or(Mac([0; 6]))
}

/// Get mask for MAC: all-FF if Select, all-zero if Ignore.
fn mask_mac(field: &FieldMatch<Mac>) -> Mac {
    if field.is_select() {
        Mac([0xFF; 6])
    } else {
        Mac([0; 6])
    }
}

/// Get `EthType` value or zero for Ignore.
fn select_or_zero_ethtype(field: &FieldMatch<EthType>) -> EthType {
    field
        .as_select()
        .copied()
        .unwrap_or(EthType::from(0u16))
}

/// Get mask for `EthType`: all-FF if Select, zero if Ignore.
fn mask_ethtype(field: &FieldMatch<EthType>) -> EthType {
    if field.is_select() {
        EthType::from(0xFFFFu16)
    } else {
        EthType::from(0u16)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use acl::{AclRuleBuilder, Fate, FieldMatch, Ipv4Prefix, PortRange, Priority};
    use std::net::Ipv4Addr;

    fn pri(n: u32) -> Priority {
        Priority::new(n).unwrap()
    }

    #[test]
    fn compile_simple_drop_rule() {
        let rule = AclRuleBuilder::new()
            .eth(|_| {})
            .ipv4(|ip| {
                ip.src = FieldMatch::Select(Ipv4Prefix::host(Ipv4Addr::new(10, 0, 0, 1)));
            })
            .deny(pri(100));

        let config = FlowLoweringConfig::default();
        let compiled = compile_rule(&rule, &config).unwrap();

        // Attr
        assert_eq!(compiled.attr.priority, 100);
        assert!(compiled.attr.ingress);

        // Pattern should have Eth + Ipv4 + End
        assert!(compiled.pattern.iter().any(|m| matches!(m, FlowMatch::Eth(_))));
        assert!(compiled.pattern.iter().any(|m| matches!(m, FlowMatch::Ipv4(_))));
        assert!(compiled.pattern.iter().any(|m| matches!(m, FlowMatch::End)));

        // Actions should have Drop + End
        assert!(compiled.actions.iter().any(|a| matches!(a, FlowAction::Drop)));
        assert!(compiled.actions.iter().any(|a| matches!(a, FlowAction::End)));
    }

    #[test]
    fn compile_forward_rule() {
        let rule = AclRuleBuilder::new()
            .eth(|_| {})
            .ipv4(|ip| {
                ip.dst = FieldMatch::Select(Ipv4Prefix::host(Ipv4Addr::new(192, 168, 1, 1)));
            })
            .tcp(|tcp| {
                tcp.dst = FieldMatch::Select(PortRange::exact(80));
            })
            .permit(pri(50));

        let config = FlowLoweringConfig::default();
        let compiled = compile_rule(&rule, &config).unwrap();

        assert!(compiled.pattern.iter().any(|m| matches!(m, FlowMatch::Tcp(_))));
        assert!(compiled
            .actions
            .iter()
            .any(|a| matches!(a, FlowAction::PassThrough)));
    }

    #[test]
    fn reject_prefix_match() {
        let rule = AclRuleBuilder::new()
            .eth(|_| {})
            .ipv4(|ip| {
                // /8 prefix — not exact, should fail
                ip.src =
                    FieldMatch::Select(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap());
            })
            .deny(pri(100));

        let config = FlowLoweringConfig::default();
        let result = compile_rule(&rule, &config);
        assert!(result.is_err());
    }

    #[test]
    fn reject_port_range() {
        let rule = AclRuleBuilder::new()
            .eth(|_| {})
            .ipv4(|_| {})
            .tcp(|tcp| {
                // Range 80-443 — not exact, should fail
                tcp.dst = FieldMatch::Select(PortRange::new(80, 443).unwrap());
            })
            .deny(pri(100));

        let config = FlowLoweringConfig::default();
        let result = compile_rule(&rule, &config);
        assert!(result.is_err());
    }

    #[test]
    fn compile_with_mark_step() {
        let rule = AclRuleBuilder::new()
            .eth(|_| {})
            .ipv4(|ip| {
                ip.src = FieldMatch::Select(Ipv4Prefix::host(Ipv4Addr::new(10, 0, 0, 1)));
            })
            .action(
                acl::ActionSequence::new(vec![Step::Mark(42)], Fate::Forward),
                pri(100),
            );

        let config = FlowLoweringConfig::default();
        let compiled = compile_rule(&rule, &config).unwrap();

        assert!(compiled
            .actions
            .iter()
            .any(|a| matches!(a, FlowAction::Mark(_))));
    }
}
