// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Exercise PCI selection against an isolated sysfs fixture in a fresh EAL process.

use dataplane_dpdk::{dev::ProbeError, eal};
use hardware::pci::address::PciAddress;
use std::ffi::CStr;
use std::path::PathBuf;
use std::process::Command;

const SELECTED: &str = "0000:00:01.0";
const UNSELECTED: &str = "0000:00:02.0";
const MISSING: &str = "0000:00:03.0";
const CHILD_MODE: &str = "DATAPLANE_PROBE_TEST_MODE";

struct PciFixture(PathBuf);

impl PciFixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!("dataplane-probe-{}", std::process::id()));
        std::fs::create_dir(&root).unwrap();
        let fixture = Self(root);
        let driver = fixture.0.join("fixture-driver");
        std::fs::create_dir(&driver).unwrap();
        for name in [SELECTED, UNSELECTED] {
            let dev = fixture.0.join(name);
            std::fs::create_dir(&dev).unwrap();
            for field in ["vendor", "device", "subsystem_vendor", "subsystem_device"] {
                std::fs::write(dev.join(field), "0xffff\n").unwrap();
            }
            std::fs::write(dev.join("class"), "0x020000\n").unwrap();
            std::fs::write(dev.join("resource"), "0 0 0\n".repeat(6)).unwrap();
            std::os::unix::fs::symlink(&driver, dev.join("driver")).unwrap();
        }
        fixture
    }
}

impl Drop for PciFixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

fn scanned_devices() -> Vec<String> {
    let mut iterator = dpdk_sys::rte_dev_iterator::default();
    // SAFETY: EAL is live, and the iterator and filter stay valid through traversal.
    let ret = unsafe { dpdk_sys::rte_dev_iterator_init(&raw mut iterator, c"bus=pci".as_ptr()) };
    // DPDK can return stale errno on success; verify that it initialized the iterator.
    assert!(
        !iterator.bus.is_null() && !iterator.bus_str.is_null(),
        "iterator init: {ret}"
    );
    let mut names = Vec::new();
    loop {
        let dev = unsafe { dpdk_sys::rte_dev_iterator_next(&raw mut iterator) };
        if dev.is_null() {
            break;
        }
        // SAFETY: the iterator returned a live device with a NUL-terminated name.
        names.push(
            unsafe { CStr::from_ptr(dpdk_sys::rte_dev_name(dev)) }
                .to_str()
                .unwrap()
                .to_owned(),
        );
    }
    names
}

fn exercise(mode: &str) {
    let cpus = eal::main_lcore_arg();
    let mut args = vec![
        "--no-huge",
        "--no-auto-probing",
        "--in-memory",
        "--no-telemetry",
        "--no-shconf",
        "--iova-mode=va",
        "--lcores",
        &cpus,
    ];
    if mode == "disabled" {
        args.push("--no-pci");
    }
    let mut eal = eal::init(args);
    assert!(
        scanned_devices().is_empty(),
        "EAL must leave PCI devices untouched"
    );
    let address = PciAddress::try_from(SELECTED).unwrap();
    if mode == "disabled" {
        assert!(
            matches!(eal.probe_pci(address), Err(ProbeError::PciDisabled {address: got}) if got == address)
        );
        assert!(scanned_devices().is_empty());
        return;
    }

    // No PMD supports the fixture's vendor ID. Reaching ENOTSUP proves it was found.
    let error = eal.probe_pci(address).unwrap_err();
    assert!(
        matches!(error, ProbeError::Driver {address: got, source} if got == address && source == errno::ErrorCode::parse_i32(-95))
    );
    assert_eq!(scanned_devices(), [SELECTED]);

    let address = PciAddress::try_from(MISSING).unwrap();
    assert!(
        matches!(eal.probe_pci(address), Err(ProbeError::Driver {address: got, source}) if got == address && source == errno::ErrorCode::parse_i32(-19))
    );
    assert_eq!(
        scanned_devices(),
        [SELECTED],
        "failure must not broaden selection"
    );

    // Establish that the other fixture is discoverable, but only when explicitly selected.
    let address = PciAddress::try_from(UNSELECTED).unwrap();
    assert!(
        matches!(eal.probe_pci(address), Err(ProbeError::Driver {source, ..}) if source == errno::ErrorCode::parse_i32(-95))
    );
    assert_eq!(scanned_devices(), [SELECTED, UNSELECTED]);
}

#[test]
fn pci_selection_is_explicit() {
    if let Ok(mode) = std::env::var(CHILD_MODE) {
        exercise(&mode);
        return;
    }
    let fixture = PciFixture::new();
    for mode in ["explicit", "disabled"] {
        let output = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "pci_selection_is_explicit", "--nocapture"])
            .env(CHILD_MODE, mode)
            .env("SYSFS_PCI_DEVICES", &fixture.0)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{mode}:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
