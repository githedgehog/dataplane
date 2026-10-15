// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! The control-plane classes as `rte_flow` rules steering to a port's control queue.

use std::collections::BTreeSet;

use dpdk::dev::{Dev, Started};
use dpdk::flow::{
    EthMatch, Flow, FlowBuilder, FlowError, FlowRule, Ingress, Ipv4Match, Ipv4Prefix, Ipv6Match,
    Ipv6Prefix, Priority, TcpMatch, UdpMatch,
};
use dpdk::queue::rx::RxQueueIndex;
use lpm::prefix::IpPrefix;
use net::headers::Within;
use net::tcp::Tcp;
use net::udp::Udp;
use tracing::{debug, warn};
use traffic_control::{ClassTable, L4Pattern, Pattern, Rule, Tier};

/// The IP protocol numbers the TCP and UDP patterns imply.
const TCP: u8 = 6;
const UDP: u8 = 17;

/// The class rules installed on one port.
pub(crate) struct Installed<'d> {
    /// Each rule the NIC took, with the handle that removes it.
    rules: Vec<(Rule, FlowRule<'d>)>,
}

impl<'d> Installed<'d> {
    /// No rules.
    pub(crate) fn none() -> Installed<'d> {
        Installed { rules: Vec::new() }
    }

    /// Make the rules on `dev` those of `table`, steering to `queue`.
    ///
    /// Rules already installed stay; only those `table` adds are created and those it drops
    /// destroyed, so a config change does not leave a window in which control traffic takes the
    /// data path. A rule the NIC refuses is logged, and tried again on the next change; meanwhile
    /// what it would match stays on the data path, which punts it as before.
    pub(crate) fn update(
        self,
        dev: &'d Dev<'_, Started>,
        port: &str,
        table: &ClassTable,
        queue: RxQueueIndex,
    ) -> Installed<'d> {
        let mut old = self.rules;
        let mut rules = Vec::with_capacity(table.rules().len());
        let mut refused = BTreeSet::new();
        for rule in table.rules() {
            if let Some(at) = old.iter().position(|(installed, _)| installed == rule) {
                rules.push(old.swap_remove(at));
                continue;
            }
            match install(dev, rule, queue) {
                Ok(handle) => rules.push((rule.clone(), handle)),
                Err(e) => {
                    warn!(
                        "port {port} refused the {} rule {:?}: {e}; that traffic stays on the data \
                         path",
                        rule.class, rule.pattern
                    );
                    refused.insert(rule.class);
                }
            }
        }
        let removed = old.len();
        // Dropping the handles destroys the rules the table no longer has.
        drop(old);
        debug!(
            "port {port} has {} control-plane rule(s) ({removed} removed), {} refused class(es)",
            rules.len(),
            refused.len()
        );
        Installed { rules }
    }
}

/// The `rte_flow` priority of a tier: lower is matched first.
fn priority(tier: Tier) -> Priority {
    match tier {
        Tier::Protocol => Priority(0),
        Tier::Local => Priority(1),
    }
}

/// Install `rule` on `dev`, steering what it matches to `queue`.
fn install<'d>(
    dev: &'d Dev<'_, Started>,
    rule: &Rule,
    queue: RxQueueIndex,
) -> Result<FlowRule<'d>, FlowError> {
    let flow = Flow::ingress(dev).priority(priority(rule.tier));
    match &rule.pattern {
        Pattern::Eth { dst, ether_type } => {
            let eth = EthMatch::default().ether_type(*ether_type);
            let eth = match dst {
                Some(dst) => eth.dst(*dst),
                None => eth,
            };
            flow.match_eth(eth).queue(queue).create()
        }
        Pattern::Ipv4(ip) => {
            let mut criteria =
                Ipv4Match::default().dst(Ipv4Prefix::prefix(ip.dst.network(), ip.dst.len()));
            if let Some(src) = ip.src {
                criteria = criteria.src(Ipv4Prefix::host(src));
            }
            if let Some(proto) = proto(ip.l4) {
                criteria = criteria.proto(proto);
            }
            transport(
                flow.match_eth(EthMatch::default()).match_ipv4(criteria),
                ip.l4,
                queue,
            )
        }
        Pattern::Ipv6(ip) => {
            let mut criteria =
                Ipv6Match::default().dst(Ipv6Prefix::prefix(ip.dst.network(), ip.dst.len()));
            if let Some(src) = ip.src {
                criteria = criteria.src(Ipv6Prefix::host(src));
            }
            if let Some(proto) = proto(ip.l4) {
                criteria = criteria.proto(proto);
            }
            transport(
                flow.match_eth(EthMatch::default()).match_ipv6(criteria),
                ip.l4,
                queue,
            )
        }
    }
}

/// The protocol number the IP header must carry for `l4`.
///
/// Explicit even for TCP and UDP, whose items imply it, so that the NIC, like
/// [`ClassTable::classify`], looks at the IP header's own protocol field and not past extension
/// headers.
fn proto(l4: L4Pattern) -> Option<u8> {
    match l4 {
        L4Pattern::Any => None,
        L4Pattern::Proto(proto) => Some(proto),
        L4Pattern::Tcp { .. } => Some(TCP),
        L4Pattern::Udp { .. } => Some(UDP),
    }
}

/// Create `flow`, matching the TCP or UDP ports of `l4` after its IP header, steering to `queue`.
fn transport<Pos>(
    flow: FlowBuilder<'_, Ingress, Pos>,
    l4: L4Pattern,
    queue: RxQueueIndex,
) -> Result<FlowRule<'_>, FlowError>
where
    Tcp: Within<Pos>,
    Udp: Within<Pos>,
{
    match l4 {
        L4Pattern::Any | L4Pattern::Proto(_) => flow.queue(queue).create(),
        L4Pattern::Tcp { src, dst } => {
            let mut tcp = TcpMatch::default();
            if let Some(src) = src {
                tcp = tcp.src(src);
            }
            if let Some(dst) = dst {
                tcp = tcp.dst(dst);
            }
            flow.match_tcp(tcp).queue(queue).create()
        }
        L4Pattern::Udp { src, dst } => {
            let mut udp = UdpMatch::default();
            if let Some(src) = src {
                udp = udp.src(src);
            }
            if let Some(dst) = dst {
                udp = udp.dst(dst);
            }
            flow.match_udp(udp).queue(queue).create()
        }
    }
}
