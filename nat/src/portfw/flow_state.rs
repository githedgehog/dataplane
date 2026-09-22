// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Port forwarding flow state

#![allow(clippy::single_match_else)]

use net::buffer::PacketBufferMut;
use net::flow_key::FlowKeyError;
use net::flows::{ExtractMut, ExtractRef, FlowStatus};
use net::ip::UnicastIpAddr;
use net::packet::{Packet, VpcDiscriminant};
use net::{FlowKey, IpProtoKey};

use std::fmt::Display;
use std::num::NonZero;

use concurrency::sync::{Arc, Weak};

use flow_entry::flow_table::FlowInfo;

use crate::common::{AtomicNatFlowStatus, NatAction, NatFlowStatus};
use crate::portfw::PortFwEntry;
use crate::portfw::protocol::next_flow_status;

#[allow(unused)]
use tracing::{debug, error, warn};

#[derive(Debug, Clone)]
pub struct PortFwState {
    pub(crate) action: NatAction,
    pub(crate) status: AtomicNatFlowStatus,
    use_ip: UnicastIpAddr,
    use_port: NonZero<u16>,
    pub(crate) rule: Weak<PortFwEntry>,
}
impl PortFwState {
    #[must_use]
    pub fn new_snat(
        use_ip: UnicastIpAddr,
        use_port: NonZero<u16>,
        rule: Weak<PortFwEntry>,
        status: AtomicNatFlowStatus,
    ) -> Self {
        Self {
            action: NatAction::SrcNat,
            status,
            use_ip,
            use_port,
            rule,
        }
    }
    #[must_use]
    pub fn new_dnat(
        use_ip: UnicastIpAddr,
        use_port: NonZero<u16>,
        rule: Weak<PortFwEntry>,
        status: AtomicNatFlowStatus,
    ) -> Self {
        Self {
            action: NatAction::DstNat,
            status,
            use_ip,
            use_port,
            rule,
        }
    }
    #[must_use]
    pub fn action(&self) -> NatAction {
        self.action
    }
    #[must_use]
    pub fn use_ip(&self) -> UnicastIpAddr {
        self.use_ip
    }
    #[must_use]
    pub fn use_port(&self) -> NonZero<u16> {
        self.use_port
    }
    #[must_use]
    pub fn rule(&self) -> &Weak<PortFwEntry> {
        &self.rule
    }
}

impl Display for PortFwState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let dir = match self.action {
            NatAction::DstNat => "to",
            NatAction::SrcNat => "from",
        };
        write!(f, "\n        {}", self.action)?;
        writeln!(f, " {dir} ip:{} port:{}", self.use_ip, self.use_port)?;
        writeln!(f, "        status: {}", self.status.load())?;
        match self.rule.upgrade() {
            Some(entry) => write!(f, "        rule: {entry}"),
            None => write!(f, "        rule: removed"),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum PortFwKeyError {
    #[error("packet has no flow key: {0}")]
    NoFlowKey(FlowKeyError),
    #[error("packet has no source port to forward")]
    NoSourcePort,
    #[error("forward target {0} is not of the flow's address family")]
    TargetFamilyMismatch(UnicastIpAddr),
}

pub(crate) fn build_portfw_flow_keys<Buf: PacketBufferMut>(
    packet: &mut Packet<Buf>, // packet to be port-forwarded (in the forward path)
    new_dst_ip: UnicastIpAddr, // destination ip to forward to
    new_dst_port: NonZero<u16>, // destination port to forward to
    dst_vpcd: VpcDiscriminant, // destination VPC to forward to
) -> Result<(FlowKey, FlowKey), PortFwKeyError> {
    // Extract flow key for the current packet
    let current_flow_key = FlowKey::try_from(&*packet).map_err(PortFwKeyError::NoFlowKey)?;

    // Retrieve initial flow key for the current packet (before any other NAT translation); if
    // we don't have the information, we didn't populate it because we don't need it and fall
    // back to the current key
    let initial_flow_key = packet
        .meta()
        .flow_key
        .as_deref()
        .copied()
        .unwrap_or(current_flow_key);

    // Build the key for the reverse path
    let proto = current_flow_key.proto();
    let src_port = current_flow_key
        .src_port()
        .ok_or(PortFwKeyError::NoSourcePort)?;

    let mut key_forward_dnated = current_flow_key
        .with_dst_ip(new_dst_ip)
        .ok_or(PortFwKeyError::TargetFamilyMismatch(new_dst_ip))?;
    key_forward_dnated.set_ip_proto_key(IpProtoKey::from((proto, src_port, new_dst_port)));
    let key_reverse = key_forward_dnated.reverse(Some(dst_vpcd));

    Ok((initial_flow_key, key_reverse))
}

pub(crate) fn setup_forward_flow(
    flow_key: &FlowKey,
    forward_flow: &Arc<FlowInfo>,
    entry: &Arc<PortFwEntry>,
    new_dst_ip: UnicastIpAddr,
    new_dst_port: NonZero<u16>,
) -> AtomicNatFlowStatus {
    // build port forwarding state for the forward flow
    let status = AtomicNatFlowStatus::new();
    let port_fw_state = PortFwState::new_dnat(
        new_dst_ip,
        new_dst_port,
        Arc::downgrade(entry),
        status.clone(),
    );

    // set the port forwarding state in the flow
    {
        let mut write_guard = forward_flow.locked.write();
        write_guard.port_fw_state = Some(Box::new(port_fw_state));
        write_guard.dst_vpcd = Some(entry.dst_vpcd);
    }
    debug!("Set up FORWARD flow for port-forwarding;\nkey={flow_key}\ninfo={forward_flow}");
    status
}

pub(crate) fn setup_reverse_flow(
    reverse_key: &FlowKey,
    reverse_flow: &Arc<FlowInfo>,
    entry: &Arc<PortFwEntry>,
    dst_ip: UnicastIpAddr,
    dst_port: NonZero<u16>,
    status: AtomicNatFlowStatus,
) {
    // build port forwarding state for the REVERSE flow
    let port_fw_state = PortFwState::new_snat(dst_ip, dst_port, Arc::downgrade(entry), status);

    // set the port forwarding state in the flow
    {
        let mut write_guard = reverse_flow.locked.write();
        write_guard.port_fw_state = Some(Box::new(port_fw_state));
        write_guard.dst_vpcd = Some(entry.key.src_vpcd());
    }
    debug!("Set up REVERSE flow for port-forwarding;\nkey={reverse_key}\ninfo={reverse_flow}");
}

/// Update a flow's port-forwarding rule for subsequent packets.
///
/// Used by configuration migration and by packets that trigger stale-rule revalidation.
pub(crate) fn reassign_port_fw_rule(flow_info: &FlowInfo, entry: &Arc<PortFwEntry>) {
    let mut flow_info_locked = flow_info.locked.write();
    if let Some(state) = flow_info_locked.port_fw_state.extract_mut::<PortFwState>() {
        state.rule = Arc::downgrade(entry);
    }
}

/// Check if the flow entry that a packet was annotated with contains any _VALID_
/// port-forwarding state. If so, provide a clone of it.
pub(crate) fn get_packet_port_fw_state<Buf: PacketBufferMut>(
    packet: &Packet<Buf>,
) -> Option<PortFwState> {
    let Some(flow) = packet.meta().flow_info.as_ref() else {
        debug!("Packet has no flow-info associated");
        return None;
    };
    let status = flow.status();
    if status != FlowStatus::Active {
        debug!("Packet flow-info is not active (status:{status})");
        return None;
    }
    let guard = flow.locked.read();
    let Some(state) = guard
        .port_fw_state
        .as_ref()
        .and_then(|s| s.extract_ref::<PortFwState>())
    else {
        debug!("Packet flow-info does not contain port-forwarding state");
        return None;
    };
    debug!("Packet hit entry with port-forwarding state: {flow}");
    Some(state.clone())
}

/// Update the port-forwarding state of a flow entry after processing a packet.
/// This updates the flow status shared by flow entries' port-forwarding state.
/// We use the status of the flow to determine the extent to which the lifetime
/// of a flow entry will be extended. Entries in status established get
/// extended by a large period. In other states, the entries are kept alive with
/// the initial timeout just to give enough time to transition to the next status.
///
/// Note: currently, in the case of TCP, we don't penalize entries for which packets
/// are unexpectedly received. This will be done later when introducing a more
/// elaborate TCP state machine with ack & seqn numbers.
pub(crate) fn refresh_port_fw_entry<Buf: PacketBufferMut>(
    packet: &mut Packet<Buf>,
    entry: &PortFwEntry,
    state: &PortFwState, // (*)
    genid: i64,
) {
    //(*) Note: atm, this is a clone of the state found by the packet
    // That's fine for updating the status since it's an arc'ed atomic

    // update the flow status (for port forwarding) depending on the packet and the current status
    let new_status = next_flow_status(packet, state);
    let current_status = state.status.load();
    if new_status != current_status {
        debug!("Flow state transitions from {current_status} -> {new_status}");
        state.status.store(new_status);
    }

    // compute new timeout for the flow. In case of TCP, if the connection was reset or closed,
    // invalidate the flows in both directions. In either case, the packet is let through.
    let extend_by = match new_status {
        NatFlowStatus::Established => entry.estab_timeout(),
        NatFlowStatus::Closed | NatFlowStatus::Reset => return packet.invalidate_flows(),
        _ => entry.init_timeout(),
    };

    let seconds = extend_by.as_secs();

    if let Some(flow) = packet.meta_mut().flow_info.as_ref() {
        if flow.reset_expiry_unchecked(extend_by).is_ok() {
            debug!("Extended flow lifetime by {seconds}s");
        }

        flow.related
            .as_ref()
            .and_then(Weak::upgrade)
            .inspect(|reverse| {
                if reverse.reset_expiry_unchecked(extend_by).is_ok() {
                    debug!("Extended reverse-flow lifetime by {seconds}s");
                }
            });

        // update flow info generation
        flow.set_genid(genid);
    }
}

#[cfg(test)]
mod test {
    use super::build_portfw_flow_keys;
    use crate::static_nat::probe::build;
    use net::FlowKey;
    use net::buffer::TestBuffer;
    use net::ip::UnicastIpAddr;
    use net::packet::{Packet, VpcDiscriminant};
    use net::vxlan::Vni;
    use std::net::IpAddr;
    use std::num::NonZero;

    fn vni(raw: u32) -> Vni {
        Vni::new_checked(raw).unwrap_or_else(|_| unreachable!())
    }

    fn addr(raw: &str) -> IpAddr {
        raw.parse().unwrap_or_else(|_| unreachable!())
    }

    fn hash_of(key: &FlowKey) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        key.hash(&mut hasher);
        hasher.finish()
    }

    /// Two tenant VPCs reaching one shared backend, each through its own published tuple.
    ///
    /// Overlapping private address space is what a VPC is for, so both clients can hold the same
    /// address. Neither `validate_ruleset` nor `VpcManifest::validate` rejects this: the former
    /// groups rules by `PortFwKey`, which carries the source VPC, so two tenants' rules are never
    /// compared, and it checks published ranges rather than backends; the latter runs per
    /// manifest, and Tenant1<->Service and Tenant2<->Service are two peerings.
    fn two_tenants_one_backend() -> ((FlowKey, FlowKey), (FlowKey, FlowKey)) {
        let backend_vpcd = VpcDiscriminant::from_vni(vni(3000));
        let backend_ip = UnicastIpAddr::try_from(addr("192.168.1.1"))
            .unwrap_or_else(|_| unreachable!("the backend address is unicast"));
        let backend_port = NonZero::new(80).unwrap_or_else(|| unreachable!());

        let client = addr("10.0.0.5");
        let client_port = 1234;

        let mut first: Packet<TestBuffer> =
            build(client, addr("172.16.0.1"), true, client_port, 8001);
        first.meta_mut().src_vpcd = Some(VpcDiscriminant::from_vni(vni(1000)));

        let mut second: Packet<TestBuffer> =
            build(client, addr("172.16.1.1"), true, client_port, 9001);
        second.meta_mut().src_vpcd = Some(VpcDiscriminant::from_vni(vni(2000)));

        let keys = |packet: &mut Packet<TestBuffer>| {
            build_portfw_flow_keys(packet, backend_ip, backend_port, backend_vpcd)
                .unwrap_or_else(|e| unreachable!("{e}"))
        };
        (keys(&mut first), keys(&mut second))
    }

    /// The property port forwarding would need in order to drop its reverse-key arbitration.
    ///
    /// **This test fails.** It is the statement of a known defect, kept as an instrument rather
    /// than deleted, because the alternative is that nothing in the tree records the problem.
    ///
    /// `FlowTable::insert_pair_if_absent` claims both halves of a flow pair under the table's
    /// write lock so that no competing creator can observe a half-installed pair. That write lock
    /// serializes every flow creation in the dataplane, and `lookup` -- which runs per packet --
    /// takes the read side of the same lock, so under `parking_lot`'s task-fair policy a waiting
    /// pair insert also stalls every worker's next lookup. Replacing it with cheaper single-key
    /// admission requires knowing that a forward key determines the reverse key it will be paired
    /// with, so that the two claims cannot disagree.
    ///
    /// For masquerade that holds: its reverse key is built from an allocated public tuple, and one
    /// allocator cannot issue the same tuple twice. (Across an allocator *swap* it can -- see
    /// `masquerade::nf::race::a_reissued_public_tuple_does_not_take_over_the_replies_of_the_flow_holding_it`
    /// -- but that is fixable by carrying reservations across the swap.)
    ///
    /// For port forwarding it does not hold, and cannot be made to hold by construction. Both
    /// halves of the reverse key are given rather than allocated: the backend comes from the
    /// rule's deterministic mapping, the client tuple from the client. `build_portfw_flow_keys`
    /// stamps the reverse key with the *destination* VPC, so the source VPC -- the only thing
    /// distinguishing the two conversations in [`two_tenants_one_backend`] -- is erased.
    ///
    /// The collision is genuinely ambiguous rather than merely inconvenient: a reply from the
    /// backend to the shared client tuple carries nothing that says which tenant opened the
    /// conversation. Today `PairInsertion::ReverseOccupied` refuses the second flow and drops the
    /// packet with `NatNotPortForwarded`, which is a defensible answer, but it is an unannounced
    /// one -- the configuration is accepted and the second tenant intermittently cannot reach the
    /// service, depending on the first tenant's ephemeral port.
    ///
    /// Deciding what *should* happen is a design question, not a bug fix, and the three candidate
    /// answers differ in what they cost:
    ///
    /// 1. Treat it as unsupported and reject it during configuration validation, with a
    ///    cross-peering check on port-forwarding backends. Nothing performs such a check today.
    /// 2. Treat it as supported and source-NAT the port-forwarded path, allocating a unique source
    ///    tuple in the backend's VPC. The reverse key becomes unique by construction, by the same
    ///    argument masquerade already relies on, at the cost of the backend no longer seeing the
    ///    client's address.
    /// 3. Treat it as supported and accept that the ambiguity is irreducible, in which case
    ///    two-key arbitration is permanent and only its *cost* can be reduced -- by claiming the
    ///    reverse key with a pending marker, so both claims are ordinary single-key operations and
    ///    the global write lock goes away.
    #[test]
    #[ignore = "instrument: port forwarding's forward key does not determine its reverse key"]
    fn a_forward_key_determines_its_reverse_key() {
        let ((first_forward, first_reverse), (second_forward, second_reverse)) =
            two_tenants_one_backend();

        assert_ne!(
            first_forward, second_forward,
            "the two tenants share a forward key, so this models nothing"
        );
        assert_ne!(
            first_reverse, second_reverse,
            "two conversations that are told apart on the way out are merged on the way back"
        );
    }

    /// Pin the collision [`a_forward_key_determines_its_reverse_key`] describes.
    ///
    /// This one passes, and is deliberately not ignored: an ignored test reports as a pass, so the
    /// instrument above records the problem for a reader but would not notice it being solved.
    /// This will fail the day the reverse key gains something that separates the two tenants,
    /// which is the point at which the arbitration could be revisited.
    #[test]
    fn distinct_forward_keys_derive_one_reverse_key() {
        let ((first_forward, first_reverse), (second_forward, second_reverse)) =
            two_tenants_one_backend();

        assert_ne!(
            first_forward, second_forward,
            "the two tenants share a forward key, so this models nothing"
        );
        assert_eq!(
            first_reverse, second_reverse,
            "the reverse keys differ, so a forward key does determine its partner after all"
        );

        // `FlowKey`'s `PartialEq` is symmetric in the ports while its `Hash` is directional, so
        // equality alone would not prove that the two keys land on one another in the flow table.
        assert_eq!(
            hash_of(&first_reverse),
            hash_of(&second_reverse),
            "the reverse keys compare equal but hash apart, so they would not collide in the table"
        );
    }
}
