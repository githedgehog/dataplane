// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![doc = include_str!("../README.md")]
#![deny(clippy::pedantic, missing_docs)]

use hardware::nic::{BindToVfioPci, PciNic};

fn main() {
    tracing_subscriber::fmt()
        .with_ansi(false)
        .with_file(true)
        .with_level(true)
        .with_line_number(true)
        .init();
    // TODO: proper argument parsing
    // -- hack add a real command line parser
    let mut args = std::env::args().skip(1);
    // -- end hack
    // TODO: fix unwraps in the next PR.  These can't be properly addressed before the arg parser is done.
    let address = hardware::pci::address::PciAddress::try_from(args.next().unwrap()).unwrap();
    let mut device = PciNic::new(address).unwrap();
    device.bind_to_vfio_pci().unwrap();
}
