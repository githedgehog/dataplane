// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Defines the cli protocol for the dataplane

use crate::iocache::IoCache;
use rkyv::util::AlignedVec;
use std::os::unix::net::SocketAddr;

/// The [`AlignedVec`] flavour returned by [`rkyv::to_bytes`] (i.e. with its
/// default alignment).  Deserialization buffers must use the same alignment
/// because the serializer inserts padding that assumes the buffer's base
/// address satisfies this alignment; a misaligned base shifts every interior
/// field, causing `bytecheck` validation to reject the archive.
///
/// Using a type alias rather than a bare constant keeps us in lockstep with
/// rkyv: if the crate ever changes its default `AlignedVec` alignment, this
/// alias picks it up automatically.
type SerializerVec = AlignedVec;

// `rkyv::from_bytes` only validates archived data when rkyv's `bytecheck`
// feature is active.  If it were ever disabled, deserialization of IPC
// messages would silently skip validation -- a safety hole.
// This import fails at compile time if the feature is missing.
const _: () = {
    #[allow(unused_imports)]
    use rkyv::bytecheck::CheckBytes as _;
};

use std::{net::IpAddr, os::unix::net::UnixDatagram};
use strum::{AsRefStr, EnumIter, EnumString};
use thiserror::Error;

// Size of a chunk. Messages may be split into chunks of this size if they exceed it
const CLI_MSG_CHUNK_SIZE: usize = 2048;

// Socket snd/rx size. This is a recommendation as it can't be enforced 100%
pub const CLI_RX_BUFF_SIZE: usize = CLI_MSG_CHUNK_SIZE * 8192;

#[derive(
    AsRefStr,
    EnumString,
    Debug,
    Clone,
    EnumIter,
    PartialEq,
    Eq,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
#[strum(ascii_case_insensitive)]
pub enum RouteProtocol {
    Local,
    Connected,
    Static,
    Ospf,
    Isis,
    Bgp,
}

/// Arguments to a cli request
#[derive(
    Debug, Default, Clone, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize,
)]
#[allow(unused)]
pub struct RequestArgs {
    pub address: Option<IpAddr>,         /* an IP address */
    pub prefix: Option<(IpAddr, u8)>,    /* an IP prefix */
    pub vrfid: Option<u32>,              /* Id of a VRF */
    pub vni: Option<u32>,                /* Vxlan vni */
    pub ifname: Option<String>,          /* name of interface */
    pub protocol: Option<RouteProtocol>, /* a type of route or routing protocol */
}

/// A Cli request
#[derive(Debug, Clone, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
#[allow(unused)]
pub struct CliRequest {
    pub action: CliAction,
    pub args: RequestArgs,
}

#[derive(Error, Debug)]
pub enum CliSerdeError {
    #[error("Serialize error: {0}")]
    Serialize(String),
    #[error("Deserialize error: {0}")]
    Deserialize(String),
}

/// Convenience trait for serializing / deserializing CLI protocol messages
/// using [`rkyv`].
pub trait CliSerialize: Sized {
    /// Serialize `self` into a byte vector.
    fn serialize(&self) -> Result<Vec<u8>, CliSerdeError>;

    /// Deserialize an instance from a byte slice.
    fn deserialize(buf: &[u8]) -> Result<Self, CliSerdeError>;
}

impl CliSerialize for CliRequest {
    fn serialize(&self) -> Result<Vec<u8>, CliSerdeError> {
        rkyv::to_bytes::<rkyv::rancor::Error>(self)
            .map(|aligned| aligned.to_vec())
            .map_err(|e| CliSerdeError::Serialize(e.to_string()))
    }

    fn deserialize(buf: &[u8]) -> Result<Self, CliSerdeError> {
        let mut aligned = SerializerVec::with_capacity(buf.len());
        aligned.extend_from_slice(buf);
        rkyv::from_bytes::<Self, rkyv::rancor::Error>(&aligned)
            .map_err(|e| CliSerdeError::Deserialize(e.to_string()))
    }
}

impl CliSerialize for CliResponse {
    fn serialize(&self) -> Result<Vec<u8>, CliSerdeError> {
        rkyv::to_bytes::<rkyv::rancor::Error>(self)
            .map(|aligned| aligned.to_vec())
            .map_err(|e| CliSerdeError::Serialize(e.to_string()))
    }

    fn deserialize(buf: &[u8]) -> Result<Self, CliSerdeError> {
        let mut aligned = SerializerVec::with_capacity(buf.len());
        aligned.extend_from_slice(buf);
        rkyv::from_bytes::<Self, rkyv::rancor::Error>(&aligned)
            .map_err(|e| CliSerdeError::Deserialize(e.to_string()))
    }
}

#[derive(Error, Debug, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub enum CliError {
    #[error("Internal error")]
    InternalError,
    #[error("Could not find: {0}")]
    NotFound(String),
    #[error("Not supported: {0}")]
    NotSupported(String),
}

#[derive(Error, Debug)]
pub enum CliLocalError {
    #[error("Serialization error: {0}")]
    Serialization(#[from] CliSerdeError),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

/// A Cli response
#[derive(Debug, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub struct CliResponse {
    pub request: CliRequest,
    // TODO: replace this String with a proper enum of response types
    // once all CLI-visible objects derive the rkyv traits.
    pub result: Result<String, CliError>,
}

#[allow(unused)]
impl CliRequest {
    #[must_use]
    pub fn new(action: CliAction, args: RequestArgs) -> Self {
        Self { action, args }
    }
    pub fn send(&self, sock: &UnixDatagram) -> Result<usize, CliLocalError> {
        let serialized = self.serialize()?;
        sock.send(&serialized).map_err(std::convert::Into::into)
    }
    pub fn recv(sock: &UnixDatagram) -> Result<((SocketAddr, Self)), CliLocalError> {
        let mut rx_buf = vec![0u8; CLI_MSG_CHUNK_SIZE];
        let (len, peer) = sock.recv_from(rx_buf.as_mut())?;
        let request = CliRequest::deserialize(&rx_buf[0..len])?;
        Ok((peer, request))
    }
}

#[allow(unused)]
impl CliResponse {
    #[must_use]
    pub fn from_request_ok(request: CliRequest, data: String) -> Self {
        Self {
            request,
            result: Ok(data),
        }
    }

    #[must_use]
    pub fn from_request_fail(request: CliRequest, error: CliError) -> Self {
        Self {
            request,
            result: Err(error),
        }
    }

    pub fn send(
        &self,
        peer: &SocketAddr,
        sock: &UnixDatagram,
        cache: &mut IoCache,
    ) -> Result<(), CliLocalError> {
        let serialized = self.serialize()?;
        let total_len = serialized.len();
        let num_chunks = total_len.div_ceil(CLI_MSG_CHUNK_SIZE);

        // attempt to send any cached data first
        if !cache.is_empty() {
            cache.drain(sock);
        }
        // if we did not clear the cache, cache the messages
        let mut use_cache = !cache.is_empty();

        // Partition the serialized response in chunks and attempt to send them.
        // Each chunk is appended one octet indicating if more chunks follow. If send returns
        // WouldBlock, cache the chunk and all the remaining ones. On any other error,
        // clear the cache for the recipient and return.
        for (num, chunk) in serialized.chunks(CLI_MSG_CHUNK_SIZE).enumerate() {
            let more = num < num_chunks - 1;
            let mut raw = chunk.to_vec();
            raw.push(more.into());

            if use_cache {
                cache.push(peer.clone(), raw.as_slice());
            } else if let Err(e) = sock.send_to_addr(raw.as_slice(), peer) {
                if e.kind() == std::io::ErrorKind::WouldBlock {
                    cache.push(peer.clone(), raw.as_slice());
                    use_cache = true;
                } else {
                    cache.clear_peer(peer);
                    return Err(e.into());
                }
            }
        }
        Ok(())
    }

    pub fn recv_sync(sock: &UnixDatagram) -> Result<Self, CliLocalError> {
        fn recv_chunk(sock: &UnixDatagram) -> Result<(Vec<u8>, bool), std::io::Error> {
            let mut rx_buff = vec![0u8; CLI_MSG_CHUNK_SIZE + 1];
            let rx_len = sock.recv(rx_buff.as_mut())?;
            Ok((rx_buff[..rx_len - 1].to_vec(), rx_buff[rx_len - 1] != 0))
        }

        let mut raw_data = vec![];
        loop {
            let (chunk, more) = recv_chunk(sock)?;
            raw_data.extend(chunk);
            if !more {
                break;
            }
        }
        Ok(CliResponse::deserialize(raw_data.as_slice())?)
    }
}

#[repr(u16)]
#[derive(
    Debug,
    Clone,
    Copy,
    EnumIter,
    PartialEq,
    Eq,
    strum::FromRepr,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
pub enum CliAction {
    Clear = 0,
    Connect,
    Disconnect,
    Help,
    Quit,

    // config
    ShowConfigSummary,

    // config: gateways & communities
    ShowGatewayGroups,
    ShowGatewayCommunities,

    // config: tracing
    ShowTracingTargets,
    ShowTracingTagGroups,

    // config: vpcs & peerings
    ShowVpc,
    ShowVpcPeerings,

    // router: Eventlog
    RouterEventLog,

    // router: cpi
    ShowCpiStats,
    CpiRequestRefresh,

    // router: frrmi
    ShowFrrmiStats,
    ShowFrrmiLastConfig,
    FrrmiApplyLastConfig,

    // router: internal state
    ShowRouterInterfaces,
    ShowRouterInterfaceAddresses,
    ShowRouterVrfs,
    ShowRouterIpv4Routes,
    ShowRouterIpv6Routes,
    ShowRouterIpv4NextHops,
    ShowRouterIpv6NextHops,
    ShowRouterEvpnVrfs,
    ShowRouterEvpnRmacStore,
    ShowRouterEvpnVtep,
    ShowAdjacencies,
    ShowRouterIpv4FibEntries,
    ShowRouterIpv6FibEntries,
    ShowRouterIpv4FibGroups,
    ShowRouterIpv6FibGroups,

    // NF: nat
    ShowPortForwarding,
    ShowStaticNat,
    ShowMasquerading,

    // NF: flow table
    ShowFlowTable,

    // NF: flow filter
    ShowFlowFilter,

    // internal config
    ShowConfigInternal,

    ShowTech,

    /* == Not supported yet == */
    // pipelines
    ShowPipeline,
    ShowPipelineStages,
    ShowPipelineStats,

    // kernel
    ShowKernelInterfaces,

    // DPDK
    ShowDpdkPort,
    ShowDpdkPortStats,
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngExt;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::{thread, time::Duration};

    /// Build a `CliRequest` that exercises every `RequestArgs` field so the
    /// round-trip covers `Option`, `String`, `IpAddr`, `u32`, and enum
    /// variants — the types most likely to contain alignment-sensitive
    /// archived representations.
    fn sample_request() -> CliRequest {
        CliRequest::new(
            CliAction::ShowRouterIpv4Routes,
            RequestArgs {
                address: Some(IpAddr::V6(Ipv6Addr::LOCALHOST)),
                prefix: Some((IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 24)),
                vrfid: Some(42),
                vni: Some(10_100),
                ifname: Some("eth0".into()),
                protocol: Some(RouteProtocol::Bgp),
            },
        )
    }

    /// Build a `CliResponse` that carries both the nested `CliRequest` and a
    /// non-trivial `Ok(String)` result.
    fn sample_response() -> CliResponse {
        CliResponse::from_request_ok(sample_request(), "some result data".into())
    }

    #[test]
    fn request_round_trip() {
        let original = sample_request();
        let bytes = original.serialize().expect("serialize");
        let got = CliRequest::deserialize(&bytes).expect("deserialize");
        assert_eq!(got, original);
    }

    #[test]
    fn response_round_trip() {
        let original = sample_response();
        let bytes = original.serialize().expect("serialize");
        let got = CliResponse::deserialize(&bytes).expect("deserialize");
        assert_eq!(got, original);
    }

    /// Simulate the misalignment that `BytesMut::split_to` caused: prepend
    /// between 1 and `SerializerVec::ALIGNMENT - 1` junk bytes so the rkyv
    /// payload starts at every possible sub-alignment offset.  The
    /// `AlignedVec` copy in `deserialize` must correct each one.
    #[test]
    fn request_deserialize_from_misaligned_buffer() {
        let bytes = sample_request().serialize().expect("serialize");
        for offset in 1..SerializerVec::ALIGNMENT {
            let mut shifted = vec![0xFFu8; offset];
            shifted.extend_from_slice(&bytes);
            let got = CliRequest::deserialize(&shifted[offset..])
                .unwrap_or_else(|_| panic!("deserialize failed at offset {offset}"));
            assert_eq!(got, sample_request());
        }
    }

    /// Same misalignment sweep for `CliResponse`.
    #[test]
    fn response_deserialize_from_misaligned_buffer() {
        let bytes = sample_response().serialize().expect("serialize");
        for offset in 1..SerializerVec::ALIGNMENT {
            let mut shifted = vec![0xFFu8; offset];
            shifted.extend_from_slice(&bytes);
            let got = CliResponse::deserialize(&shifted[offset..])
                .unwrap_or_else(|_| panic!("deserialize failed at offset {offset}"));
            assert_eq!(got, sample_response());
        }
    }

    fn generate_big_response_data(random: usize) -> String {
        let data = "DATA";
        data.repeat(random)
    }

    fn generate_big_response(data: String) -> CliResponse {
        CliResponse::from_request_ok(sample_request(), data)
    }

    /// Open 2 sockets, one for dataplane and one for cli. Spawn a thread representing dataplane.
    /// Send dataplane a request and receive a big response from it.
    #[test]
    fn test_communications() {
        const DP_PATH: &str = "/tmp/dpsock";
        const CLI_PATH: &str = "/tmp/clisock";
        let _ = std::fs::remove_file(DP_PATH);
        let _ = std::fs::remove_file(CLI_PATH);

        let dpsock = UnixDatagram::bind(DP_PATH).unwrap();
        dpsock.set_nonblocking(true).unwrap();

        let clisock = UnixDatagram::bind(CLI_PATH).unwrap();
        clisock.set_nonblocking(false).unwrap();
        clisock.connect(DP_PATH).unwrap();

        // generate reponse data with random length
        let mut rng = rand::rng();
        let random_repeat = rng.random_range(100 * CLI_MSG_CHUNK_SIZE..CLI_MSG_CHUNK_SIZE * 10_000);
        let response_data = generate_big_response_data(random_repeat);
        let response_data_len = response_data.len();

        thread::spawn(move || {
            let mut cache = IoCache::new();
            let mut send_attempted = false;
            let response = generate_big_response(response_data.clone());
            loop {
                if send_attempted {
                    // send from cache if we already called send()
                    cache.drain(&dpsock);
                    thread::sleep(Duration::from_millis(10));
                } else {
                    match CliRequest::recv(&dpsock) {
                        Ok((peer, _request)) => {
                            response.send(&peer, &dpsock, &mut cache).unwrap();
                            send_attempted = true;
                            // from now on, send from cache
                        }
                        Err(_) => thread::sleep(Duration::from_millis(100)),
                    }
                }
                if send_attempted && cache.is_empty() {
                    break;
                }
            }
        });

        // send request
        let request = sample_request();
        request.send(&clisock).unwrap();

        // receive response
        let response = CliResponse::recv_sync(&clisock).unwrap();
        let data = response.result.unwrap();
        assert_eq!(data.len(), response_data_len);
    }
}
