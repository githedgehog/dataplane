// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Serialize [`CaptureRecord`]s as pcapng.

use crate::names::CaptureNames;
use crate::record::{CaptureRecord, Direction};
use net::interface::InterfaceIndex;
use net::parse::DeParse;
use pcap_file::DataLink;
use pcap_file::pcapng::blocks::enhanced_packet::{EnhancedPacketBlock, EnhancedPacketOption};
use pcap_file::pcapng::blocks::interface_description::{
    InterfaceDescriptionBlock, InterfaceDescriptionOption, InterfaceTsResolution,
};
use pcap_file::pcapng::blocks::interface_statistics::{
    InterfaceStatisticsBlock, InterfaceStatisticsOption,
};
use pcap_file::pcapng::blocks::opt_common::CommonOption;
use pcap_file::pcapng::{PcapNgWriteError, PcapNgWriter};
use std::borrow::Cow;
use std::collections::HashMap;
use std::fmt::Display;
use std::io::Write;
use std::time::Duration;

/// `epb_flags` direction bits ([pcapng §4.3.1]).
///
/// [pcapng §4.3.1]: https://www.ietf.org/archive/id/draft-ietf-opsawg-pcapng-03.html#section-4.3.1
const EPB_FLAGS_INBOUND: u32 = 0b01;
const EPB_FLAGS_OUTBOUND: u32 = 0b10;

/// Errors from [`CaptureWriter`].
#[derive(Debug, thiserror::Error)]
pub enum CaptureWriteError {
    /// The underlying pcapng writer failed (usually an I/O error).
    #[error(transparent)]
    Pcapng(#[from] PcapNgWriteError),
    /// The record's headers could not be rebuilt into bytes.
    #[error("failed to deparse captured headers")]
    Deparse,
}

/// Writes [`CaptureRecord`]s to a pcapng stream.
///
/// Each dataplane interface gets its own pcapng interface, described the first time a record names it.
/// Records with no interface at all (e.g. dropped before routing) share one more.
pub struct CaptureWriter<W: Write> {
    pcapng: PcapNgWriter<W>,
    names: CaptureNames,
    interfaces: HashMap<Option<InterfaceIndex>, u32>,
    frame: Vec<u8>,
    comment: String,
}

impl<W: Write> CaptureWriter<W> {
    /// Start a pcapng stream on `sink`, showing interfaces and VPCs by the given `names`.
    ///
    /// # Errors
    ///
    /// Fails if the section header cannot be written.
    pub fn new(sink: W, names: CaptureNames) -> Result<Self, CaptureWriteError> {
        Ok(CaptureWriter {
            pcapng: PcapNgWriter::new(sink)?,
            names,
            interfaces: HashMap::new(),
            frame: Vec::new(),
            comment: String::new(),
        })
    }

    /// Append one record.
    ///
    /// The frame holds only the rebuilt headers; the original length still counts the payload, so readers
    /// see an ordinary snaplen-truncated packet.
    ///
    /// # Errors
    ///
    /// Fails if the headers cannot be rebuilt or the stream cannot be written.
    pub fn write(&mut self, record: &CaptureRecord) -> Result<(), CaptureWriteError> {
        use std::fmt::Write as _;

        let interface_id = self.interface_id(record.interface())?;

        let headers = record.headers();
        self.frame.clear();
        self.frame.resize(usize::from(headers.size().get()), 0);
        headers
            .deparse(&mut self.frame)
            .map_err(|_| CaptureWriteError::Deparse)?;

        self.comment.clear();
        write!(self.comment, "{}", record.annotation(&self.names))
            .unwrap_or_else(|_| unreachable!("formatting into a String cannot fail"));

        let direction = match record.direction() {
            Direction::Ingress => EPB_FLAGS_INBOUND,
            Direction::Egress => EPB_FLAGS_OUTBOUND,
        };
        self.pcapng.write_pcapng_block(EnhancedPacketBlock {
            interface_id,
            timestamp: record.timestamp(),
            original_len: record.original_len(),
            data: Cow::Borrowed(&self.frame),
            options: vec![
                EnhancedPacketOption::Flags(direction),
                EnhancedPacketOption::Common(CommonOption::Comment(Cow::Borrowed(&self.comment))),
            ],
        })?;
        Ok(())
    }

    /// Close the stream with `summary`, then flush and return the underlying sink.
    ///
    /// pcapng has nowhere to put a whole-capture note once the section header is written, so the summary
    /// goes in an interface statistics block for each interface, stamped with `ended` (time since the
    /// Unix epoch).
    /// A capture which wrote no packets described no interfaces and so carries no summary.
    ///
    /// # Errors
    ///
    /// Fails if the statistics cannot be written or the flush fails.
    pub fn finish(
        mut self,
        summary: &impl Display,
        ended: Duration,
    ) -> Result<W, CaptureWriteError> {
        let summary = summary.to_string();
        let mut ids: Vec<u32> = self.interfaces.values().copied().collect();
        ids.sort_unstable();
        for interface_id in ids {
            self.pcapng.write_pcapng_block(InterfaceStatisticsBlock {
                interface_id,
                timestamp: ended,
                options: vec![
                    InterfaceStatisticsOption::IsbEndTime(ended),
                    InterfaceStatisticsOption::Common(CommonOption::Comment(Cow::Borrowed(
                        &summary,
                    ))),
                ],
            })?;
        }
        let mut sink = self.pcapng.into_inner();
        sink.flush().map_err(PcapNgWriteError::Io)?;
        Ok(sink)
    }

    /// The pcapng interface id for `interface`, describing it first if this is its first record.
    fn interface_id(
        &mut self,
        interface: Option<InterfaceIndex>,
    ) -> Result<u32, CaptureWriteError> {
        if let Some(&id) = self.interfaces.get(&interface) {
            return Ok(id);
        }
        let name = match interface {
            Some(index) => self.names.interface(index).to_string(),
            None => "no interface".to_owned(),
        };
        self.pcapng.write_pcapng_block(InterfaceDescriptionBlock {
            linktype: DataLink::ETHERNET,
            snaplen: 0,
            options: vec![
                InterfaceDescriptionOption::IfName(Cow::Owned(name)),
                InterfaceDescriptionOption::IfTsResol(InterfaceTsResolution::NANO),
            ],
        })?;
        // pcapng numbers interfaces in the order they are described.
        let id = u32::try_from(self.interfaces.len())
            .unwrap_or_else(|_| unreachable!("more than u32::MAX interfaces"));
        self.interfaces.insert(interface, id);
        Ok(id)
    }
}
