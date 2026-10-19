// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! The questions this crate asks `mstlink`, as command lines.

/// One `mstlink` invocation's worth of questions about a PCI function's port.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Query {
    /// Link state, the firmware's troubleshooting verdict, physical counters and bit error
    /// rates, and the receiver's eye (`-c -e`): a [`crate::PortReport`].
    Port,
    /// The histogram of FEC-corrected symbols per codeword (`--rx_fec_histogram
    /// --show_histogram`): a [`crate::FecHistogram`]. Fails while the link runs without FEC.
    FecHistogram,
    /// The PCIe link to the host (`--port_type PCIE -c`): a [`crate::Pcie`].
    Pcie,
}

impl Query {
    /// The arguments that ask it of the function at `pci_address` (`0000:02:00.0`, say).
    #[must_use]
    pub fn args(self, pci_address: &str) -> Vec<String> {
        let specific: &[&str] = match self {
            Query::Port => &["-c", "-e"],
            Query::FecHistogram => &["--rx_fec_histogram", "--show_histogram"],
            Query::Pcie => &["--port_type", "PCIE", "-c"],
        };
        ["-d", pci_address]
            .iter()
            .chain(specific)
            .chain(&["--json"])
            .map(|arg| (*arg).to_string())
            .collect()
    }
}
