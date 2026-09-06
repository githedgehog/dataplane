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

/// Generate the bindings, returning the path of the C source bindgen wrote for
/// DPDK's `static inline` functions.
fn bind(path: &Path) -> PathBuf {
    let sysroot = dpdk_sysroot_helper::get_sysroot();
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
        .wrap_static_fns_path(&static_fn_path)
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
        // DPDK declares these two with `__attribute__((error))` unless the build
        // enables GFNI, so generating a wrapper produces C that cannot compile.
        // They are unusable from Rust either way.
        .blocklist_function("rte_thash_gfni")
        .blocklist_function("rte_thash_gfni_bulk")
        .allowlist_item("rte.*")
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
        .rust_edition(bindgen::RustEdition::Edition2024)
        .wrap_unsafe_ops(true)
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file(path.join("generated.rs"))
        .expect("Couldn't write bindings!");
    // bindgen writes the wrappers beside the header path it was given, with the
    // extension replaced.
    static_fn_path.with_extension("c")
}

/// Compile the `_w` wrappers bindgen generated for DPDK's `static inline`
/// functions, and link them.
///
/// Every `static inline` in the DPDK headers is unreachable from Rust without a
/// non-inline definition to call. bindgen emits one per function and declares the
/// Rust side with `#[link_name = "<name>_w"]`; this is what turns that C into a
/// library. Without it those bindings are declarations of symbols nobody defines.
///
/// # Optimisation and LTO are deliberately not set here
///
/// These wrappers sit on the datapath, so their optimisation level and their
/// participation in LTO both matter. Neither is chosen here on purpose: `cc`
/// invokes the same wrapped compiler as the rest of the build, and nix appends
/// `NIX_CFLAGS_COMPILE` *after* the command line, so the profile wins. Under
/// `optimize-for.performance` in `nix/profiles.nix` that is `-O3 -flto=thin`,
/// which makes these objects ThinLTO bitcode that rustc's `-Clinker-plugin-lto`
/// can inline through -- the same treatment the hand-written wrapper library
/// used to get, for the same reason.
///
/// So do not add an `opt_level` or an `-flto` here. Setting them would not
/// override the profile, but it would hide which one is in charge, and pinning
/// an optimisation level is how a datapath shim quietly stops being inlined.
fn build_static_fn_wrappers(source: &Path) {
    let sysroot = dpdk_sysroot_helper::get_sysroot();
    let mut build = cc::Build::new();
    build
        .file(source)
        .include(format!("{sysroot}/include"))
        // DPDK marks its experimental API deprecated, and we wrap it anyway.
        .flag("-Wno-deprecated-declarations")
        // Machine-generated: its style is not ours to fix, and the warnings
        // (duplicate `const`, `_FORTIFY_SOURCE` without `-O`) are all its own.
        .warnings(false);
    // DPDK's headers use intrinsics that the baseline target does not enable, so
    // the wrappers need the same flags DPDK itself is built with. These mirror
    // `march.x86_64.NIX_CFLAGS_COMPILE` in `nix/profiles.nix`; keep them in step.
    if env::var("CARGO_CFG_TARGET_ARCH").as_deref() == Ok("x86_64") {
        build.flag("-mrtm").flag("-mcrc32").flag("-mssse3");
    }
    build.compile("dpdk_static_fns");
}

fn main() {
    dpdk_sysroot_helper::use_sysroot();
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    let static_fns = bind(&out_path);
    build_static_fn_wrappers(&static_fns);

    let depends = [
        "dpdk_wrapper",
        "rte_net_virtio",
        "rte_net_vhost",
        "rte_net_i40e",
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
        "rte_acl",
        "rte_eal",
        "rte_argparse",
        "rte_kvargs",
        "rte_telemetry",
        "rte_log",
        "ibverbs",
        "mlx5",
        "mlx4",
        "efa",
        "hns",
        "mana",
        "ionic",
        "bnxt_re-rdmav64",
        "cxgb4-rdmav64",
        "erdma-rdmav64",
        "hfi1verbs-rdmav64",
        "ipathverbs-rdmav64",
        "irdma-rdmav64",
        "mthca-rdmav64",
        "ocrdma-rdmav64",
        "qedr-rdmav64",
        "rxe-rdmav64",
        "siw-rdmav64",
        "vmw_pvrdma-rdmav64",
        "nl-route-3",
        "nl-3",
        "numa",
    ];

    // NOTE: DPDK absolutely requires whole-archive in the linking command.
    // While I find this very questionable, it is what it is.
    // It is just more work for the LTO later on I suppose ¯\_(ツ)_/¯
    for dep in depends {
        println!("cargo:rustc-link-lib=static:+whole-archive,+bundle={dep}");
    }
}
