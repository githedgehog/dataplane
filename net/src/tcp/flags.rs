// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! TCP control bits.

use std::fmt::{Display, Formatter};

bitflags::bitflags! {
    /// The TCP control bits ("flags"), in their wire layout: the byte at offset 13 of the TCP
    /// header, see [RFC 9293, section 3.1][RFC 9293].
    ///
    /// Every 8-bit pattern is a valid set of flags.
    ///
    /// [RFC 9293]: https://www.rfc-editor.org/rfc/rfc9293#section-3.1
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct TcpFlags: u8 {
        /// No more data from sender
        const FIN = 0x01;
        /// Synchronize sequence numbers
        const SYN = 0x02;
        /// Reset the connection
        const RST = 0x04;
        /// Push function
        const PSH = 0x08;
        /// Acknowledgment field is significant
        const ACK = 0x10;
        /// Urgent pointer field is significant
        const URG = 0x20;
        /// ECN-Echo
        const ECE = 0x40;
        /// Congestion Window Reduced
        const CWR = 0x80;
    }
}

impl Display for TcpFlags {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if self.is_empty() {
            return f.write_str("-");
        }
        for (i, (name, _)) in self.iter_names().enumerate() {
            if i > 0 {
                f.write_str("|")?;
            }
            f.write_str(name)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::TcpFlags;

    #[test]
    fn display_names_set_flags_in_wire_order() {
        assert_eq!(TcpFlags::empty().to_string(), "-");
        assert_eq!(TcpFlags::SYN.to_string(), "SYN");
        assert_eq!((TcpFlags::ACK | TcpFlags::SYN).to_string(), "SYN|ACK");
        assert_eq!(
            TcpFlags::from_bits_retain(u8::MAX).to_string(),
            "FIN|SYN|RST|PSH|ACK|URG|ECE|CWR"
        );
    }

    #[test]
    fn contains_requires_every_flag() {
        let syn_ack = TcpFlags::SYN | TcpFlags::ACK;
        assert!(syn_ack.contains(TcpFlags::SYN));
        assert!(syn_ack.contains(syn_ack));
        assert!(syn_ack.contains(TcpFlags::empty()));
        assert!(!TcpFlags::SYN.contains(syn_ack));
    }
}
