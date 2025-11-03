// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

use bindgen::callbacks::ParseCallbacks;
use std::env;
use std::path::{Path, PathBuf};

#[derive(Debug)]
struct Cb;

impl ParseCallbacks for Cb {
    fn process_comment(&self, comment: &str) -> Option<String> {
        match doxygen_bindgen::transform(comment) {
            Ok(yup) => Some(yup),
            Err(nope) => {
                eprintln!("failed to transform doxygen comment: {nope}");
                Some(comment.to_string())
            }
        }
    }
}

fn bind(path: &Path, sysroot: &str) {
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    let static_fn_path = out_path.join("generated.h");
    bindgen::Builder::default()
        .header(format!("{sysroot}/include/dpdk_wrapper.h"))
        .anon_fields_prefix("annon")
        .use_core()
        .generate_comments(true)
        .clang_arg("-Wno-deprecated-declarations")
        // .clang_arg("-Dinline=") // hack to make bindgen spit out wrappers
        .wrap_static_fns(true)
        .wrap_static_fns_suffix("_w")
        .wrap_static_fns_path(static_fn_path)
        .array_pointers_in_arguments(false)
        .detect_include_paths(true)
        .prepend_enum_name(false)
        .translate_enum_integer_types(false)
        .generate_cstr(true)
        .derive_copy(true)
        .derive_debug(true)
        .derive_default(true)
        .derive_partialeq(false)
        .parse_callbacks(Box::new(Cb))
        .layout_tests(true)
        .default_enum_style(bindgen::EnumVariation::ModuleConsts)
        .blocklist_item("rte_atomic.*")
        .allowlist_item("rte.*")
        .allowlist_item("wrte_.*")
        .allowlist_item("RTE.*")
        .blocklist_item("__*")
        .clang_macro_fallback()
        // rustc doesn't like repr(packed) types which contain other repr(packed) types
        .opaque_type("rte_arp_hdr")
        .opaque_type("rte_arp_ipv4")
        .opaque_type("rte_gtp_psc_generic_hdr")
        .opaque_type("rte_l2tpv2_combined_msg_hdr")
        .clang_arg(format!("-I{sysroot}/include"))
        .clang_arg("-fretain-comments-from-system-headers")
        .clang_arg("-fparse-all-comments")
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file(path.join("generated.rs"))
        .expect("Couldn't write bindings!");
}

fn main() {
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    let sysroot = dpdk_sysroot_helper::get_sysroot();

    println!("cargo:rustc-link-arg=--sysroot={sysroot}");
    println!("cargo:rustc-link-search=all={sysroot}/lib");

    // NOTE: DPDK absolutely requires whole-archive in the linking command.
    // While I find this very questionable, it is what it is.
    // It is just more work for the LTO later on I suppose ¯\_(ツ)_/¯
    let depends = [
        "dpdk_wrapper",
        "rte_net_virtio",
        "rte_net_vhost",
        "rte_vhost",
        "rte_net_mlx5",
        "rte_common_mlx5",
        "rte_ethdev",
        "rte_cryptodev",
        "rte_bus_vdev",
        "rte_dmadev",
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
        "mlx4",
        "efa",
        "hns",
        "mana",
        "bnxt_re-rdmav59",
        "cxgb4-rdmav59",
        "erdma-rdmav59",
        "hfi1verbs-rdmav59",
        "ipathverbs-rdmav59",
        "irdma-rdmav59",
        "mthca-rdmav59",
        "ocrdma-rdmav59",
        "qedr-rdmav59",
        "rxe-rdmav59",
        "siw-rdmav59",
        "vmw_pvrdma-rdmav59",
        "nl-route-3",
        "nl-3",
        "numa",
    ];

    for dep in &depends {
        println!("cargo:rustc-link-lib=static:+whole-archive,+bundle={dep}");
    }
    let rerun_if_changed = ["build.rs", "../scripts/dpdk-sys.env"];
    for file in &rerun_if_changed {
        println!("cargo:rerun-if-changed={file}");
    }
    bind(&out_path, sysroot.as_str());
}
