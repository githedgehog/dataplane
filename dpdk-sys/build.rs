// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use std::env;

use bindgen::callbacks::ParseCallbacks;
use std::path::{Path, PathBuf};

#[derive(Debug)]
struct Cb;

impl ParseCallbacks for Cb {
    fn process_comment(&self, comment: &str) -> Option<String> {
        match doxygen_rs::generator::rustdoc(comment.into()) {
            Ok(transformed) => Some(transformed),
            Err(_) => Some(comment.into()),
        }
    }
}

fn bind(path: &Path, sysroot: &str) {
    bindgen::Builder::default()
        .header(format!("{sysroot}/include/dpdk_wrapper.h"))
        .anon_fields_prefix("annon")
        .generate_comments(true)
        .generate_inline_functions(false)
        .generate_block(true)
        .array_pointers_in_arguments(false)
        .detect_include_paths(true)
        .prepend_enum_name(false)
        .translate_enum_integer_types(false)
        .generate_cstr(true)
        .derive_copy(true)
        .derive_debug(true)
        .derive_default(true)
        .derive_partialeq(true)
        .parse_callbacks(Box::new(Cb))
        .layout_tests(true)
        .default_enum_style(bindgen::EnumVariation::ModuleConsts)
        .allowlist_item("rte.*")
        .allowlist_item("wrte_.*")
        .allowlist_item("RTE.*")
        .blocklist_item("__*")
        .clang_macro_fallback()
        // Bindgen tests seem to object to the documentation in the following
        // (not the items themselves, just the documentation associated with them)
        // I suspect this is a bug in bindgen, but I'm not sure.
        // I don't have any reason to think we need any of these functions and I'd
        // rather have the doc comments on for the rest of the project
        .blocklist_type("rte_bus_cmp_t")
        .blocklist_type("rte_class_cmp_t")
        .blocklist_function("rte_bus_find")
        .blocklist_function("rte_bus_probe")
        .blocklist_function("rte_class_find")
        .blocklist_function("rte_dev_dma_map")
        .blocklist_function("rte_dev_dma_unmap")
        .blocklist_function("rte_pci_addr_cmp")
        .blocklist_function("rte_pci_addr_parse")
        // rustc doesn't like repr(packed) types which contain other repr(packed) types
        .opaque_type("rte_arp_hdr")
        .opaque_type("rte_arp_ipv4")
        .opaque_type("rte_gtp_psc_generic_hdr")
        .opaque_type("rte_l2tpv2_combined_msg_hdr")
        .clang_arg(format!("-I{sysroot}/include"))
        .clang_arg("-fretain-comments-from-system-headers")
        .clang_arg("-fparse-all-comments")
        .clang_arg("-march=native")
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file(path.join("generated.rs"))
        .expect("Couldn't write bindings!");
}

fn main() {
    let sysroot = dpdk_sysroot_helper::get_sysroot();

    println!("cargo:rustc-link-arg=--sysroot={sysroot}");
    println!("cargo:rustc-link-search=all={sysroot}/lib");

    // NOTE: DPDK absolutely requires whole-archive in the linking command.
    // While I find this very questionable, it is what it is.
    // It is just more work for the LTO later on I suppose ¯\_(ツ)_/¯
    let depends = [
        "dpdk_wrapper",
        "rte_net_mlx5",
        "rte_common_mlx5",
        "rte_ethdev",
        "rte_bus_auxiliary",
        "rte_net",
        "rte_bus_pci",
        "rte_pci",
        "rte_mbuf",
        "rte_mempool_ring",
        "rte_mempool",
        "rte_hash",
        "rte_rcu",
        "rte_ring",
        "rte_eal",
        "rte_kvargs",
        "rte_telemetry",
        "rte_log",
        "ibverbs",
        "mlx5",
        "nl-route-3",
        "nl-3",
        "numa",
    ];

    for dep in &depends {
        println!("cargo:rustc-link-lib=static:+whole-archive,+bundle={dep}");
    }

    let rerun_if_changed = ["build.rs"];

    for file in &rerun_if_changed {
        println!("cargo:rerun-if-changed={file}");
    }

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    // let out_path = PathBuf::from("src");

    bind(&out_path, sysroot.as_str());
}
