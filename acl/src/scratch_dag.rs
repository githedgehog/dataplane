// Typed-coproduct DAG scratch.
//
// Demonstrates the rank-based NF pipeline model where each rank
// boundary is a typed enum (Xform<N>), and NFs compose via:
//
//   NFn::Out<'a>: Into<XformN_plus_1<'a>>
//   Each arm of XformN+1<'a>: Into<NFx::In<'a>>
//
// This file is a manual hand-wiring of the pattern for a toy
// pipeline.  The proc-macro that would derive this from a topology
// spec comes later.
//
// Toy pipeline (3 ranks, no synthetic passthroughs needed):
//
//   rank 0: Classify  (fans out to Tcp / Udp paths)
//   rank 1: TcpStage, UdpStage  (each processes independently)
//   rank 2: Emit  (fan-in from both Tcp and Udp)
//
// ```dot
// digraph toy {
//   Classify -> TcpStage;
//   Classify -> UdpStage;
//   TcpStage -> Emit;
//   UdpStage -> Emit;
// }
// ```

#![allow(dead_code)] // scratch

// ==========================================================================
// Core trait: what an NF is
// ==========================================================================

/// One node in the NF DAG.  Stateful transition function from `In` to `Out`.
pub trait NetworkFunction {
    type In<'a>
    where
        Self: 'a;
    type Out<'a>
    where
        Self: 'a;

    fn process<'a>(&'a mut self, input: Self::In<'a>) -> Self::Out<'a>
    where
        Self: 'a;
}

// ==========================================================================
// Payload types
// ==========================================================================
//
// Stand-ins for Window<'a, Shape> / Phase<'a, P>.  A real pipeline
// would carry typed references into Packet<Buf>; this toy just
// tracks the flow.

#[derive(Debug)]
pub struct RawPacket<'a> {
    pub bytes: &'a [u8],
}

#[derive(Debug)]
pub struct TcpPayload<'a> {
    pub raw: RawPacket<'a>,
    pub sport: u16,
    pub dport: u16,
}

#[derive(Debug)]
pub struct UdpPayload<'a> {
    pub raw: RawPacket<'a>,
    pub sport: u16,
    pub dport: u16,
}

#[derive(Debug)]
pub struct EmittedPacket<'a> {
    pub raw: RawPacket<'a>,
    pub classified_as: &'static str,
}

// ==========================================================================
// Rank-boundary transition enums (Xform<N>)
// ==========================================================================
//
// Xform1 covers edges crossing the rank-0 -> rank-1 boundary.
// Two edges here: Classify -> TcpStage and Classify -> UdpStage.
// Each arm names its destination NF (by convention).
//
// Xform2 covers edges crossing the rank-1 -> rank-2 boundary.
// Two edges here: TcpStage -> Emit and UdpStage -> Emit.  Different
// payload types because they came from different NFs, same
// destination.

#[derive(Debug)]
pub enum Xform1<'a> {
    ToTcpStage(TcpPayload<'a>),
    ToUdpStage(UdpPayload<'a>),
}

#[derive(Debug)]
pub enum Xform2<'a> {
    EmitFromTcp(TcpPayload<'a>),
    EmitFromUdp(UdpPayload<'a>),
}

// ==========================================================================
// NF 1: Classify  (rank 0 -> rank 1)
// ==========================================================================

pub struct Classify;

impl NetworkFunction for Classify {
    type In<'a>
        = RawPacket<'a>
    where
        Self: 'a;
    type Out<'a>
        = Xform1<'a>
    where
        Self: 'a;

    fn process<'a>(&'a mut self, pkt: RawPacket<'a>) -> Xform1<'a>
    where
        Self: 'a,
    {
        // Toy classifier: inspect first byte to decide tcp vs udp.
        // Real impl would parse protocol headers.
        if pkt.bytes.first().copied().unwrap_or(0) & 0x1 == 0 {
            Xform1::ToTcpStage(TcpPayload {
                raw: pkt,
                sport: 12345,
                dport: 80,
            })
        } else {
            Xform1::ToUdpStage(UdpPayload {
                raw: pkt,
                sport: 6881,
                dport: 53,
            })
        }
    }
}

// ==========================================================================
// NF 2: TcpStage  (rank 1 -> rank 2)
// ==========================================================================

pub struct TcpStage;

impl NetworkFunction for TcpStage {
    type In<'a>
        = TcpPayload<'a>
    where
        Self: 'a;
    type Out<'a>
        = Xform2<'a>
    where
        Self: 'a;

    fn process<'a>(&'a mut self, pkt: TcpPayload<'a>) -> Xform2<'a>
    where
        Self: 'a,
    {
        // Toy TCP processing: just pass through, tag via arm.
        Xform2::EmitFromTcp(pkt)
    }
}

// ==========================================================================
// NF 3: UdpStage  (rank 1 -> rank 2)
// ==========================================================================

pub struct UdpStage;

impl NetworkFunction for UdpStage {
    type In<'a>
        = UdpPayload<'a>
    where
        Self: 'a;
    type Out<'a>
        = Xform2<'a>
    where
        Self: 'a;

    fn process<'a>(&'a mut self, pkt: UdpPayload<'a>) -> Xform2<'a>
    where
        Self: 'a,
    {
        Xform2::EmitFromUdp(pkt)
    }
}

// ==========================================================================
// NF 4: Emit  (rank 2 sink, fan-in from TcpStage and UdpStage)
// ==========================================================================
//
// Fan-in is handled by Emit's In type being an enum over the
// upstream sources -- and by having Into impls from each Xform2 arm
// into that enum.

#[derive(Debug)]
pub enum EmitInput<'a> {
    FromTcp(TcpPayload<'a>),
    FromUdp(UdpPayload<'a>),
}

impl<'a> From<TcpPayload<'a>> for EmitInput<'a> {
    fn from(v: TcpPayload<'a>) -> Self {
        EmitInput::FromTcp(v)
    }
}

impl<'a> From<UdpPayload<'a>> for EmitInput<'a> {
    fn from(v: UdpPayload<'a>) -> Self {
        EmitInput::FromUdp(v)
    }
}

pub struct Emit {
    pub emitted: Vec<&'static str>, // trace for testing
}

impl Emit {
    pub fn new() -> Self {
        Self {
            emitted: Vec::new(),
        }
    }
}

impl NetworkFunction for Emit {
    type In<'a>
        = EmitInput<'a>
    where
        Self: 'a;
    // Sink NF: its "Out" is a synthetic terminal (nothing downstream).
    type Out<'a>
        = EmittedPacket<'a>
    where
        Self: 'a;

    fn process<'a>(&'a mut self, input: EmitInput<'a>) -> EmittedPacket<'a>
    where
        Self: 'a,
    {
        match input {
            EmitInput::FromTcp(p) => {
                self.emitted.push("tcp");
                EmittedPacket {
                    raw: p.raw,
                    classified_as: "tcp",
                }
            }
            EmitInput::FromUdp(p) => {
                self.emitted.push("udp");
                EmittedPacket {
                    raw: p.raw,
                    classified_as: "udp",
                }
            }
        }
    }
}

// ==========================================================================
// Xform -> downstream-NF::In dispatch
// ==========================================================================
//
// This is the "each arm of XformN+1<'a>: Into<NFx::In<'a>>" part.
// For the rank-1->2 boundary, the Xform2 arms dispatch to Emit::In
// (which is EmitInput).  Implemented as Into impls.
//
// For fan-out cases like Xform1 where arms go to DIFFERENT
// downstream NFs, we can't use Into<EmitInput> directly -- instead
// the driver matches on Xform1 and calls the appropriate
// downstream NF.  See the Pipeline driver below.

impl<'a> From<Xform2<'a>> for EmitInput<'a> {
    fn from(x: Xform2<'a>) -> Self {
        match x {
            Xform2::EmitFromTcp(p) => EmitInput::FromTcp(p),
            Xform2::EmitFromUdp(p) => EmitInput::FromUdp(p),
        }
    }
}

// ==========================================================================
// Pipeline driver (hand-wired)
// ==========================================================================
//
// A proc-macro would generate this from the topology spec.  Here
// we hand-wire for the toy.
//
// Per-packet flow:
//   1. Classify::process(pkt) -> Xform1
//   2. Match Xform1 to pick which rank-1 NF to invoke
//   3. That NF produces Xform2
//   4. Convert Xform2 into Emit::In via Into
//   5. Emit::process(input) -> EmittedPacket

pub struct Pipeline {
    pub classify: Classify,
    pub tcp_stage: TcpStage,
    pub udp_stage: UdpStage,
    pub emit: Emit,
}

impl Pipeline {
    pub fn new() -> Self {
        Self {
            classify: Classify,
            tcp_stage: TcpStage,
            udp_stage: UdpStage,
            emit: Emit::new(),
        }
    }

    pub fn process<'a>(&'a mut self, pkt: RawPacket<'a>) -> EmittedPacket<'a>
    where
        Self: 'a,
    {
        // Rank 0 -> 1
        let x1: Xform1<'a> = self.classify.process(pkt);

        // Rank 1 -> 2
        let x2: Xform2<'a> = match x1 {
            Xform1::ToTcpStage(p) => self.tcp_stage.process(p),
            Xform1::ToUdpStage(p) => self.udp_stage.process(p),
        };

        // Rank 2 -> 3 (sink)
        self.emit.process(x2.into())
    }
}

// ==========================================================================
// Tests
// ==========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_tcp_path() {
        let mut p = Pipeline::new();
        let bytes = [0u8, 1, 2, 3]; // low bit 0 -> tcp
        let out = p.process(RawPacket { bytes: &bytes });
        assert_eq!(out.classified_as, "tcp");
        assert_eq!(p.emit.emitted, vec!["tcp"]);
    }

    #[test]
    fn classify_udp_path() {
        let mut p = Pipeline::new();
        let bytes = [1u8, 1, 2, 3]; // low bit 1 -> udp
        let out = p.process(RawPacket { bytes: &bytes });
        assert_eq!(out.classified_as, "udp");
        assert_eq!(p.emit.emitted, vec!["udp"]);
    }

    #[test]
    fn mixed_batch_preserves_per_packet_routing() {
        let mut p = Pipeline::new();
        let packets: &[&[u8]] = &[&[0, 1, 2], &[1, 1, 2], &[0, 3, 4], &[1, 0]];
        let mut results = Vec::new();
        for bytes in packets {
            results.push(p.process(RawPacket { bytes }).classified_as);
        }
        assert_eq!(results, vec!["tcp", "udp", "tcp", "udp"]);
        assert_eq!(p.emit.emitted, vec!["tcp", "udp", "tcp", "udp"]);
    }
}
