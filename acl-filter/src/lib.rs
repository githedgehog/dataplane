// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use concurrency::sync::Arc;
use config::external::overlay::acl::{AclAction, AclScope};
use net::buffer::PacketBufferMut;
use net::flows::FlowInfo;
use net::flows::FlowStatus;
use net::headers::{Headers, Net, NetExt, Transport, TryHeaders, TryIp, UpperLayerProto};
use net::ip::NextHeader;
use net::packet::{DoneReason, Packet, PacketMeta, VpcDiscriminant};
use net::tcp::TcpFlags;
use net::vxlan::Vni;
use pipeline::{NetworkFunction, PipelineData};
use std::num::NonZero;
use tracing::{debug, info};

use tracectl::trace_target;
trace_target!("acl-filter", LevelFilter::INFO, &["pipeline"]);

mod access;
mod context;
mod display;
#[cfg(test)]
mod tests;

pub use access::{
    AclFilterContext, AclFilterContextReader, AclFilterContextReaderFactory, AclFilterContextWriter,
};
use acl::dpdk::lookup::MAX_BATCH;
pub use acl::table::RuleRow;
use context::AclTables;
pub use context::{AclKey, AclKeyRule, LookupResult};

pub struct AclFilter {
    name: String,
    tablesr: AclFilterContextReader,
    pipeline_data: Arc<PipelineData>,
}

impl AclFilter {
    #[must_use]
    pub fn new(name: &str, tablesr: AclFilterContextReader) -> Self {
        Self {
            name: name.to_string(),
            tablesr,
            pipeline_data: Arc::new(PipelineData::default()),
        }
    }

    /// Filter up to [`MAX_BATCH`] packets, looking up those that need it in one classify per IP
    /// version: `rte_acl` takes its vector paths for a batch, but its scalar one for a single key.
    fn process_chunk<Buf: PacketBufferMut>(&self, chunk: &mut [Packet<Buf>], tables: &AclTables) {
        debug_assert!(chunk.len() <= MAX_BATCH);
        let genid = self.pipeline_data.genid();

        // 1. Summarize the packets this stage handles; drop those it cannot summarize. Only the
        //    packets of a VPC pair with an ACL (one with a default action) need a lookup.
        let mut summaries: [Option<PacketSummary>; MAX_BATCH] = [const { None }; MAX_BATCH];
        let mut defaults: [Option<AclAction>; MAX_BATCH] = [None; MAX_BATCH];
        // A burst rarely spans more than a VPC pair or two: reuse the last pair's lookup.
        let mut last: Option<((Vni, Vni), Option<AclAction>)> = None;
        for (i, packet) in chunk.iter_mut().enumerate() {
            if packet.is_done() || !packet.meta().is_overlay() {
                continue;
            }
            match PacketSummary::try_from(&*packet) {
                Ok(summary) => {
                    let pair = (summary.src_vni, summary.dst_vni);
                    defaults[i] = match last {
                        Some((seen, default)) if seen == pair => default,
                        _ => {
                            let default = tables.find_default_action(pair.0, pair.1);
                            last = Some((pair, default));
                            default
                        }
                    };
                    summaries[i] = Some(summary);
                }
                Err(reason) => packet.done(reason),
            }
        }

        // 2. Look up the packets with an ACL, all at once.
        let mut wanted: [Option<&PacketSummary>; MAX_BATCH] = [None; MAX_BATCH];
        for (want, (summary, default)) in wanted.iter_mut().zip(summaries.iter().zip(&defaults)) {
            *want = summary.as_ref().filter(|_| default.is_some());
        }
        let mut direct = [None; MAX_BATCH];
        tables.lookup_batch(&wanted[..chunk.len()], &mut direct[..chunk.len()]);

        // 3. Apply each packet's verdict.
        for (i, packet) in chunk.iter_mut().enumerate() {
            if let Some(summary) = &summaries[i] {
                self.apply_verdict(packet, summary, defaults[i], direct[i], tables, genid);
            }
        }
    }

    fn apply_verdict<Buf: PacketBufferMut>(
        &self,
        packet: &mut Packet<Buf>,
        summary: &PacketSummary,
        default_action: Option<AclAction>,
        direct: Option<&LookupResult>,
        tables: &AclTables,
        genid: i64,
    ) {
        let nfi = &self.name;
        let valid_flow = self.packet_has_valid_flow(packet.meta(), genid);
        let has_valid_flow = valid_flow.is_some();

        let (verdict, flow_scoped_allow) =
            Self::verdict(summary, default_action, direct, valid_flow, tables);
        if verdict == AclAction::Deny {
            debug!("{nfi}: Packet rejected by ACLs, dropping packet");
            packet.invalidate_flows();
            packet.done(DoneReason::AclDropped);
            return;
        }

        // If this packet opens a flow, the flow keeps the flags it was classified with, to classify
        // it again for replies, see PacketSummary::reverse_summary()
        packet.meta_mut().tcp_flags = summary.tcp_flags;

        // The flow filter requests flow tracking for all packets of a peering with flow-scoped
        // rules. Only flows opened by such a rule need it: we never use the others to let replies
        // through, so they would only take room in the flow table. Packets on a valid flow keep
        // the request, so that tracking keeps updating the flow.
        if !has_valid_flow && !flow_scoped_allow && packet.meta().has_forced_flow_tracking() {
            debug!("{nfi}: Packet not allowed by a flow-scoped rule, no flow tracking needed");
            packet.meta_mut().set_forced_flow_tracking(false);
        }
    }

    fn packet_has_valid_flow<'a>(
        &self,
        meta: &'a PacketMeta,
        genid: i64,
    ) -> Option<&'a Arc<FlowInfo>> {
        let nfi = &self.name;
        let Some(flow) = &meta.flow_info else {
            debug!("{nfi}: Packet has no flow information");
            return None;
        };

        if flow.status() != FlowStatus::Active {
            debug!("{nfi}: Packet has inactive flow information");
            return None;
        }
        let flow_genid = flow.genid();
        if flow_genid < genid {
            debug!(
                "{nfi}: Packet has outdated flow information from a prior configuration ({flow_genid} < {genid})"
            );
            return None;
        }
        Some(flow)
    }

    // Return the verdict for the packet, and whether it comes from an Allow rule of scope "flow"
    // matching the packet itself. `default_action` is the packet's VPC pair's, and `direct` the
    // result of looking up the packet itself (batched, see `process_chunk`).
    fn verdict(
        summary: &PacketSummary,
        default_action: Option<AclAction>,
        direct: Option<&LookupResult>,
        flow_info: Option<&Arc<FlowInfo>>,
        tables: &AclTables,
    ) -> (AclAction, bool) {
        // Every peering with an ACL has a default action registered for both directions, and only
        // such a peering has rules. Without one, nothing can match either way: allow the packet
        // without the lookups, and without reaching the reverse flow (a cold cache line, and an
        // atomic on it, for every packet of every flow).
        let Some(default_action) = default_action else {
            return (AclAction::Allow, false);
        };

        // An ACL directly matching the packet
        if let Some(result) = direct {
            let verdict = result.action;
            if result.log {
                info!("ACL filtering: {summary} -> {verdict:?}")
            }
            return (
                verdict,
                verdict == AclAction::Allow && result.scope == AclScope::Flow,
            );
        }

        // If we have flow information, we may be dealing with a reply for an authorized flow. But
        // we need to check whether the corresponding ACL rule has a 'flow' or 'packet' scope. To do
        // that, we need to reverse-NAT the packet and do another lookup, to find the rule and its
        // scope, if any.
        if let Some(flow) = flow_info
            && let Some(reverse_summary) = summary.reverse_summary(flow)
        {
            let reverse_lookup_result = tables.lookup(&reverse_summary);
            if let Some(result) = reverse_lookup_result
                && result.action == AclAction::Allow
                && result.scope == AclScope::Flow
            {
                let verdict = result.action;
                if result.log {
                    info!("ACL filtering: {summary} -> {verdict:?} (reply from allowed flow)")
                }
                return (verdict, false);
            }
        }

        // Fall back to the peering's default action
        (default_action, false)
    }
}

impl<Buf: PacketBufferMut> NetworkFunction<Buf> for AclFilter {
    fn process_burst(&mut self, burst: &mut Vec<Packet<Buf>>) {
        // Load the tables once per burst, not once per packet: a load takes a reference to them,
        // an atomic read-modify-write each way.
        let guard = self.tablesr.load();
        for chunk in burst.chunks_mut(MAX_BATCH) {
            self.process_chunk(chunk, &guard.acls);
        }
    }

    fn set_data(&mut self, data: Arc<PipelineData>) {
        self.pipeline_data = data;
    }
}

#[derive(Debug, Clone)]
pub(crate) struct PacketSummary {
    pub(crate) src_vni: Vni,
    pub(crate) dst_vni: Vni,
    pub(crate) src_ip: std::net::IpAddr,
    pub(crate) dst_ip: std::net::IpAddr,
    pub(crate) proto: NextHeader,
    pub(crate) ports: Option<(NonZero<u16>, NonZero<u16>)>,
    /// Only for TCP packets carrying a TCP header, so not for non-first fragments.
    pub(crate) tcp_flags: Option<TcpFlags>,
}

impl<Buf: PacketBufferMut> TryFrom<&Packet<Buf>> for PacketSummary {
    type Error = DoneReason;

    fn try_from(packet: &Packet<Buf>) -> Result<Self, Self::Error> {
        let Some((src_vpcd, dst_vpcd)) = packet.meta().src_vpcd.zip(packet.meta().dst_vpcd) else {
            debug!("Missing source or destination VPC discriminant, dropping packet");
            return Err(DoneReason::Unroutable);
        };
        let VpcDiscriminant::VNI(src_vni) = src_vpcd;
        let VpcDiscriminant::VNI(dst_vni) = dst_vpcd;

        let Some((_eth, net, transport)) = packet
            .headers()
            .pat()
            .opt_eth()
            .net()
            .opt_transport()
            .done()
        else {
            if packet.try_ip().is_none() {
                debug!("No IP headers found, dropping packet");
                return Err(DoneReason::NotIp);
            }
            debug!("Header chain carries a layer this stage cannot account for, dropping packet");
            return Err(DoneReason::Unhandled);
        };

        let src_ip = net.src_addr();
        let dst_ip = net.dst_addr();
        let upper = packet.upper_layer_proto();
        let proto = match upper {
            UpperLayerProto::Carried(proto) => proto,
            UpperLayerProto::NonFirstFragment
                if is_tcp_fragment_at_offset_one(net, packet.headers()) =>
            {
                debug!("TCP fragment at offset 1, dropping packet");
                return Err(DoneReason::Malformed);
            }
            // Match wildcard and protocol-44 rules, without inferring a transport.
            UpperLayerProto::NonFirstFragment => NextHeader::FRAGMENT,
            UpperLayerProto::Indeterminate => {
                debug!("Could not determine the upper-layer protocol, dropping packet");
                return Err(DoneReason::Malformed);
            }
        };
        // The parser may have read ports and flags from fragment payload.
        let transport = transport.filter(|_| !matches!(upper, UpperLayerProto::NonFirstFragment));
        let ports = transport.and_then(|t| t.src_port().zip(t.dst_port()));
        let tcp_flags = match transport {
            Some(Transport::Tcp(tcp)) => Some(tcp.flags()),
            _ => None,
        };

        Ok(Self {
            src_vni,
            dst_vni,
            src_ip,
            dst_ip,
            proto,
            ports,
            tcp_flags,
        })
    }
}

/// Tell if a packet is a TCP fragment at offset 1 (in 8-byte units), see RFC 3128.
///
/// Such a fragment starts at byte 8 of the TCP header, so it can overwrite the TCP flags of the
/// first fragment when the receiver reassembles the packet. We would classify the first fragment
/// with flags other than the ones the receiver sees. A legitimate fragment never starts there: the
/// first fragment would hold only 8 bytes of TCP header, and we drop it as malformed.
///
/// With extension headers in the fragmentable part, such as an IPv4 authentication header, the TCP
/// header starts further and other offsets could reach the flags. We cannot tell without the first
/// fragment, and do not look for them.
fn is_tcp_fragment_at_offset_one(net: &Net, headers: &Headers) -> bool {
    match net {
        Net::Ipv4(ip) => {
            NextHeader::from(ip.protocol()) == NextHeader::TCP && ip.fragment_offset().value() == 1
        }
        Net::Ipv6(_) => headers.net_ext().iter().any(|ext| {
            matches!(ext, NetExt::Fragment(frag)
                if frag.next_header() == NextHeader::TCP && frag.fragment_offset().value() == 1)
        }),
    }
}

impl PacketSummary {
    fn reverse_summary(&self, flow_info: &Arc<FlowInfo>) -> Option<PacketSummary> {
        let related = flow_info.related.as_ref()?.upgrade()?;
        let flow_key = related.flowkey();
        Some(PacketSummary {
            src_vni: self.dst_vni,
            dst_vni: self.src_vni,
            src_ip: flow_key.src_ip(),
            dst_ip: flow_key.dst_ip(),
            proto: flow_key.proto(),
            ports: flow_key.ports(),
            // The flow key has no TCP flags, but rules may match on them: use the flags of the
            // packet that opened the flow, so that this lookup selects the same rule as that packet
            // did. Without them, as for flows opened by packets that did not go through this stage,
            // earlier rules matching empty flags could shadow the flow-scoped rule.
            tcp_flags: related.opening_tcp_flags(),
        })
    }
}
