// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use dyn_iter::{DynIter, IntoDynIterator};
use net::buffer::PacketBufferMut;

use crate::packet::Packet;
use crate::pipeline::{DynNetworkFunction, NetworkFunction, nf_dyn};

/// A dynamic pipeline that can be updated at runtime.
///
/// This struct is used to create a dynamic pipeline that can be updated at runtime.
///
/// # See Also
///
/// [`DynNetworkFunction`]
#[derive(Default)]
pub struct DynPipeline<Buf: PacketBufferMut> {
    nfs: Vec<Box<dyn DynNetworkFunction<Buf>>>,
}

impl<Buf: PacketBufferMut + 'static> DynPipeline<Buf> {
    #[allow(unused)]
    pub fn new() -> Self {
        Self { nfs: vec![] }
    }

    /// Add a static network function to the pipeline.
    ///
    /// This method takes a [`NetworkFunction`] and adds it to the pipeline.
    ///
    #[allow(unused)]
    pub fn add_stage<NF: NetworkFunction<Buf> + 'static>(self, nf: NF) -> Self {
        self.add_stage_dyn(nf_dyn(nf))
    }

    /// Add a dynamic network function to the pipeline.
    ///
    /// This method takes a [`DynNetworkFunction`] and adds it to the pipeline.
    ///
    /// # See Also
    ///
    /// [`DynNetworkFunction`]
    /// [`nf_dyn`]
    #[allow(unused)]
    pub fn add_stage_dyn(mut self, nf: Box<dyn DynNetworkFunction<Buf>>) -> Self {
        self.nfs.push(nf);
        self
    }
}

impl<Buf: PacketBufferMut> DynNetworkFunction<Buf> for DynPipeline<Buf> {
    fn process_dyn<'a>(&'a mut self, input: DynIter<'a, Packet<Buf>>) -> DynIter<'a, Packet<Buf>> {
        self.nfs
            .iter_mut()
            .fold(input, move |input, nf| nf.process_dyn(input))
            .into_dyn_iter()
    }
}

impl<Buf: PacketBufferMut> NetworkFunction<Buf> for DynPipeline<Buf> {
    fn process<'a, Input: Iterator<Item = Packet<Buf>> + 'a>(
        &'a mut self,
        input: Input,
    ) -> impl Iterator<Item = Packet<Buf>> {
        self.process_dyn(input.into_dyn_iter())
    }
}

#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[cfg(test)]
mod test {
    use dyn_iter::IntoDynIterator;
    use net::eth::mac::{DestinationMac, Mac};
    use net::headers::{Net, TryEth, TryIp, TryIpv4};

    use crate::pipeline::test_utils::{DynStageGenerator, build_test_ipv4_packet};
    use crate::pipeline::{DynNetworkFunction, DynPipeline, NetworkFunction};

    #[test]
    fn long_dyn_pipeline() {
        const MAX_TTL: u8 = u8::MAX;

        let mut pipeline = DynPipeline::new();
        let mut stages = DynStageGenerator::new();
        let num_stages = 1000;

        for _ in 0..num_stages {
            pipeline = pipeline.add_stage_dyn(stages.next().unwrap());
        }

        let packets = vec![build_test_ipv4_packet(u8::MAX).unwrap()].into_iter();
        let packets_out: Vec<_> = pipeline.process(packets).collect();

        assert_eq!(packets_out.len(), 1);

        let p0_out = &packets_out[0];
        assert_eq!(
            DestinationMac::new(Mac::BROADCAST).unwrap(),
            p0_out.try_eth().unwrap().destination()
        );
        assert_eq!(
            (MAX_TTL as usize) - DynStageGenerator::num_ttl_decs(num_stages),
            p0_out.try_ipv4().unwrap().ttl() as usize
        );
    }

    // Allow clippy::similar_names for packet[12] and packets, cannot allow per line
    // See https://github.com/rust-lang/rust-clippy/issues/9514
    #[allow(clippy::similar_names)]
    #[test]
    fn process_dyn() {
        let mut pipeline = DynPipeline::new();
        let mut stages = DynStageGenerator::new();
        let num_stages = 10;
        let p1_ttl = 10;
        let p2_ttl = 20;

        for _ in 0..num_stages {
            pipeline = pipeline.add_stage_dyn(stages.next().unwrap());
        }

        let packet1 = build_test_ipv4_packet(p1_ttl).unwrap();
        let packet2 = build_test_ipv4_packet(p2_ttl).unwrap();
        let packet_vec = vec![packet1, packet2];
        let num_packets = packet_vec.len();

        let packets = packet_vec.into_iter().into_dyn_iter();
        let packets_out: Vec<_> = pipeline.process_dyn(packets).collect();

        assert_eq!(num_packets, packets_out.len());

        let p1_out = &packets_out[0];
        let p2_out = &packets_out[1];
        assert_eq!(
            DestinationMac::new(Mac::BROADCAST).unwrap(),
            p1_out.try_eth().unwrap().destination()
        );
        assert_eq!(
            (p1_ttl as usize) - DynStageGenerator::num_ttl_decs(num_stages),
            p1_out.try_ipv4().unwrap().ttl() as usize
        );
        assert_eq!(
            DestinationMac::new(Mac::BROADCAST).unwrap(),
            p2_out.try_eth().unwrap().destination()
        );
        assert_eq!(
            (p2_ttl as usize) - DynStageGenerator::num_ttl_decs(num_stages),
            p2_out.try_ipv4().unwrap().ttl() as usize
        );

        // Check try_ip() and try_ipv4() are consistent
        let p1_ipv4 = p1_out.try_ipv4().expect("Expected IPv4 packet");
        let p1_net = p1_out.try_ip();
        if let Some(Net::Ipv4(p1_net_ipv4)) = p1_net {
            assert_eq!(p1_ipv4.ttl(), p1_net_ipv4.ttl());
        } else {
            panic!("Expected IPv4 packet");
        }
    }
}
