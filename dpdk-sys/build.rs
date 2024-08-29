extern crate bindgen;

use std::path::{Path, PathBuf};

fn bind(path: &Path) {
    bindgen::Builder::default()
        .header("src/dpdk.h")
        .anon_fields_prefix("annon")
        .generate_comments(true)
        .generate_inline_functions(false)
        .generate_block(true)
        .array_pointers_in_arguments(true)
        .detect_include_paths(true)
        // .enable_function_attribute_detection()
        .prepend_enum_name(false)
        .translate_enum_integer_types(true)
        .generate_cstr(true)
        .derive_copy(true)
        .derive_debug(true)
        .derive_default(true)
        .derive_partialeq(true)
        .default_enum_style(bindgen::EnumVariation::Rust {
            non_exhaustive: false,
        })
        .allowlist_item("rte_.*")
        // .blocklist_item("__.*")
        .opaque_type("rte_arp_hdr")
        .opaque_type("rte_arp_ipv4")
        .opaque_type("rte_gtp_psc_generic_hdr")
        .opaque_type("rte_l2tpv2_combined_msg_hdr")
        .clang_arg("-I/mnt/dpdk-arch-sysroot/usr/include")
        .clang_arg("-fretain-comments-from-system-headers")
        .clang_arg("-fparse-all-comments")
        .clang_arg("-finline-functions")
        .clang_arg("-march=native")
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file(path.join("mod.rs"))
        .expect("Couldn't write bindings!");
}

fn main() {
    println!("cargo:rustc-link-search=native=/mnt/dpdk-arch-sysroot/usr/lib");

    let out_path = PathBuf::from("src/dpdk_sys");

    bind(&out_path);

    // println!("cargo:rustc-link-lib=dylib=

    println!("cargo:rustc-link-lib=dylib=rte_net_mlx5");
    println!("cargo:rustc-link-lib=dylib=rte_common_mlx5");
    println!("cargo:rustc-link-lib=dylib=rte_ethdev");
    println!("cargo:rustc-link-lib=dylib=rte_bus_auxiliary");
    println!("cargo:rustc-link-lib=dylib=rte_net");
    println!("cargo:rustc-link-lib=dylib=rte_bus_pci");
    println!("cargo:rustc-link-lib=dylib=rte_pci");
    println!("cargo:rustc-link-lib=dylib=rte_mbuf");
    println!("cargo:rustc-link-lib=dylib=rte_mempool");
    println!("cargo:rustc-link-lib=dylib=rte_hash");
    println!("cargo:rustc-link-lib=dylib=rte_rcu");
    println!("cargo:rustc-link-lib=dylib=rte_ring");
    println!("cargo:rustc-link-lib=dylib=rte_eal");
    println!("cargo:rustc-link-lib=dylib=rte_kvargs");
    println!("cargo:rustc-link-lib=dylib=rte_telemetry");
    println!("cargo:rustc-link-lib=dylib=rte_log");
    println!("cargo:rustc-link-lib=dylib=ibverbs");
    println!("cargo:rustc-link-lib=dylib=mlx5");
    println!("cargo:rustc-link-lib=dylib=nl-route-3");
    println!("cargo:rustc-link-lib=dylib=nl-3");
    println!("cargo:rustc-link-lib=dylib=archive");
    println!("cargo:rustc-link-lib=dylib=acl");
    println!("cargo:rustc-link-lib=dylib=bz2");
    println!("cargo:rustc-link-lib=dylib=crypto");
    println!("cargo:rustc-link-lib=dylib=lz4");
    println!("cargo:rustc-link-lib=dylib=numa");
    println!("cargo:rustc-link-lib=dylib=xml2");
    println!("cargo:rustc-link-lib=dylib=z");
    println!("cargo:rustc-link-lib=dylib=zstd");
    println!("cargo:rustc-link-lib=dylib=icuuc");
    println!("cargo:rustc-link-lib=dylib=icudata");
    println!("cargo:rustc-link-lib=dylib=lzma");
    println!("cargo:rustc-link-lib=dylib=atomic");

    // println!("cargo:rustc-link-lib=dylib=rte_net_mlx5");
    // println!("cargo:rustc-link-lib=dylib=z");
    // println!("cargo:rustc-link-lib=dylib=icuuc");
    // println!("cargo:rustc-link-lib=dylib=icudata");
    // println!("cargo:rustc-link-lib=dylib=lzma");
    // println!("cargo:rustc-link-lib=dylib=bz2");
    // println!("cargo:rustc-link-lib=dylib=lz4");
    // println!("cargo:rustc-link-lib=dylib=zstd");
    // println!("cargo:rustc-link-lib=dylib=lzma");
    // println!("cargo:rustc-link-lib=dylib=acl");
    // println!("cargo:rustc-link-lib=dylib=crypto");
    // println!("cargo:rustc-link-lib=dylib=archive");
    // println!("cargo:rustc-link-lib=dylib=crypto");
    // println!("cargo:rustc-link-lib=dylib=z");
    // println!("cargo:rustc-link-lib=dylib=bz2");
    // println!("cargo:rustc-link-lib=dylib=lz4");
    // println!("cargo:rustc-link-lib=dylib=zstd");
    // println!("cargo:rustc-link-lib=dylib=lzma");
    // println!("cargo:rustc-link-lib=dylib=acl");
    // println!("cargo:rustc-link-lib=dylib=rte_bus_auxiliary");
    // println!("cargo:rustc-link-lib=dylib=bz2");
    // println!("cargo:rustc-link-lib=dylib=lz4");
    // println!("cargo:rustc-link-lib=dylib=zstd");
    // println!("cargo:rustc-link-lib=dylib=lzma");
    // println!("cargo:rustc-link-lib=dylib=acl");
    // println!("cargo:rustc-link-lib=dylib=crypto");
    // println!("cargo:rustc-link-lib=dylib=archive");
    // println!("cargo:rustc-link-lib=dylib=rte_telemetry");
    // println!("cargo:rustc-link-lib=dylib=rte_log");
    // println!("cargo:rustc-link-lib=dylib=numa");
    // println!("cargo:rustc-link-lib=dylib=atomic");
    // println!("cargo:rustc-link-lib=dylib=numa");
    // println!("cargo:rustc-link-lib=dylib=rte_log");
    // println!("cargo:rustc-link-lib=dylib=numa");
    // println!("cargo:rustc-link-lib=dylib=rte_eal");
    // println!("cargo:rustc-link-lib=dylib=bz2");
    // println!("cargo:rustc-link-lib=dylib=lz4");
    // println!("cargo:rustc-link-lib=dylib=zstd");
    // println!("cargo:rustc-link-lib=dylib=lzma");
    // println!("cargo:rustc-link-lib=dylib=acl");
    // println!("cargo:rustc-link-lib=dylib=crypto");
    // println!("cargo:rustc-link-lib=dylib=archive");
    // println!("cargo:rustc-link-lib=dylib=rte_telemetry");
    // println!("cargo:rustc-link-lib=dylib=rte_log");
    // println!("cargo:rustc-link-lib=dylib=numa");
    // println!("cargo:rustc-link-lib=dylib=rte_common_mlx5");
    // println!("cargo:rustc-link-lib=dylib=bz2");
    // println!("cargo:rustc-link-lib=dylib=lz4");
    // println!("cargo:rustc-link-lib=dylib=zstd");
    // println!("cargo:rustc-link-lib=dylib=lzma");
    // println!("cargo:rustc-link-lib=dylib=acl");
    // println!("cargo:rustc-link-lib=dylib=crypto");
    // println!("cargo:rustc-link-lib=dylib=archive");
    // println!("cargo:rustc-link-lib=dylib=nl-route-3");
    // println!("cargo:rustc-link-lib=dylib=nl-3");
    // println!("cargo:rustc-link-lib=dylib=rte_bus_auxiliary");
    // println!("cargo:rustc-link-lib=dylib=rte_bus_pci");
    // println!("cargo:rustc-link-lib=dylib=bz2");
    // println!("cargo:rustc-link-lib=dylib=lz4");
    // println!("cargo:rustc-link-lib=dylib=zstd");
    // println!("cargo:rustc-link-lib=dylib=lzma");
    // println!("cargo:rustc-link-lib=dylib=acl");
    // println!("cargo:rustc-link-lib=dylib=crypto");
    // println!("cargo:rustc-link-lib=dylib=archive");
    // println!("cargo:rustc-link-lib=dylib=rte_pci");
    // println!("cargo:rustc-link-lib=dylib=bz2");
    // println!("cargo:rustc-link-lib=dylib=lz4");
    // println!("cargo:rustc-link-lib=dylib=zstd");
    // println!("cargo:rustc-link-lib=dylib=lzma");
    // println!("cargo:rustc-link-lib=dylib=acl");
    // println!("cargo:rustc-link-lib=dylib=crypto");
    // println!("cargo:rustc-link-lib=dylib=archive");
    // println!("cargo:rustc-link-lib=dylib=rte_telemetry");
    // println!("cargo:rustc-link-lib=dylib=rte_log");
    // println!("cargo:rustc-link-lib=dylib=rte_eal");
    // println!("cargo:rustc-link-lib=dylib=numa");
    // println!("cargo:rustc-link-lib=dylib=rte_telemetry");
    // println!("cargo:rustc-link-lib=dylib=rte_log");
    // println!("cargo:rustc-link-lib=dylib=rte_eal");
    // println!("cargo:rustc-link-lib=dylib=numa");
    // println!("cargo:rustc-link-lib=dylib=rte_pci");
    // println!("cargo:rustc-link-lib=dylib=rte_rcu");
    // println!("cargo:rustc-link-lib=dylib=bz2");
    // println!("cargo:rustc-link-lib=dylib=lz4");
    // println!("cargo:rustc-link-lib=dylib=zstd");
    // println!("cargo:rustc-link-lib=dylib=lzma");
    // println!("cargo:rustc-link-lib=dylib=acl");
    // println!("cargo:rustc-link-lib=dylib=crypto");
    // println!("cargo:rustc-link-lib=dylib=archive");
    // println!("cargo:rustc-link-lib=dylib=rte_ring");
    // println!("cargo:rustc-link-lib=dylib=bz2");
    // println!("cargo:rustc-link-lib=dylib=lz4");
    // println!("cargo:rustc-link-lib=dylib=zstd");
    // println!("cargo:rustc-link-lib=dylib=lzma");
    // println!("cargo:rustc-link-lib=dylib=acl");
    // println!("cargo:rustc-link-lib=dylib=crypto");
    // println!("cargo:rustc-link-lib=dylib=archive");
    // println!("cargo:rustc-link-lib=dylib=rte_telemetry");
    // println!("cargo:rustc-link-lib=dylib=rte_log");
    // println!("cargo:rustc-link-lib=dylib=rte_eal");
    // println!("cargo:rustc-link-lib=dylib=numa");
    // println!("cargo:rustc-link-lib=dylib=rte_telemetry");
    // println!("cargo:rustc-link-lib=dylib=rte_log");
    // println!("cargo:rustc-link-lib=dylib=rte_eal");
    // println!("cargo:rustc-link-lib=dylib=numa");
    // println!("cargo:rustc-link-lib=dylib=rte_ring");
    // println!("cargo:rustc-link-lib=dylib=rte_mempool");
    // println!("cargo:rustc-link-lib=dylib=bz2");
    // println!("cargo:rustc-link-lib=dylib=lz4");
    // println!("cargo:rustc-link-lib=dylib=zstd");
    // println!("cargo:rustc-link-lib=dylib=lzma");
    // println!("cargo:rustc-link-lib=dylib=acl");
    // println!("cargo:rustc-link-lib=dylib=crypto");
    // println!("cargo:rustc-link-lib=dylib=archive");
    // println!("cargo:rustc-link-lib=dylib=rte_telemetry");
    // println!("cargo:rustc-link-lib=dylib=rte_log");
    // println!("cargo:rustc-link-lib=dylib=rte_eal");
    // println!("cargo:rustc-link-lib=dylib=numa");
    // println!("cargo:rustc-link-lib=dylib=rte_telemetry");
    // println!("cargo:rustc-link-lib=dylib=rte_log");
    // println!("cargo:rustc-link-lib=dylib=rte_eal");
    // println!("cargo:rustc-link-lib=dylib=rte_hash");
    // println!("cargo:rustc-link-lib=dylib=bz2");
    // println!("cargo:rustc-link-lib=dylib=lz4");
    // println!("cargo:rustc-link-lib=dylib=zstd");
    // println!("cargo:rustc-link-lib=dylib=lzma");
    // println!("cargo:rustc-link-lib=dylib=acl");
    // println!("cargo:rustc-link-lib=dylib=crypto");
    // println!("cargo:rustc-link-lib=dylib=archive");
    // println!("cargo:rustc-link-lib=dylib=rte_rcu");
    // println!("cargo:rustc-link-lib=dylib=rte_ring");
    // println!("cargo:rustc-link-lib=dylib=rte_telemetry");
    // println!("cargo:rustc-link-lib=dylib=rte_log");
    // println!("cargo:rustc-link-lib=dylib=rte_eal");
    // println!("cargo:rustc-link-lib=dylib=numa");
    // println!("cargo:rustc-link-lib=dylib=rte_rcu");
    // println!("cargo:rustc-link-lib=dylib=rte_hash");
    // println!("cargo:rustc-link-lib=dylib=rte_pci");
    // println!("cargo:rustc-link-lib=dylib=rte_bus_pci");
    // println!("cargo:rustc-link-lib=dylib=rte_ring");
    // println!("cargo:rustc-link-lib=dylib=rte_mempool");
    // println!("cargo:rustc-link-lib=dylib=rte_mbuf");
    // println!("cargo:rustc-link-lib=dylib=bz2");
    // println!("cargo:rustc-link-lib=dylib=lz4");
    // println!("cargo:rustc-link-lib=dylib=zstd");
    // println!("cargo:rustc-link-lib=dylib=lzma");
    // println!("cargo:rustc-link-lib=dylib=acl");
    // println!("cargo:rustc-link-lib=dylib=crypto");
    // println!("cargo:rustc-link-lib=dylib=archive");
    // println!("cargo:rustc-link-lib=dylib=rte_mempool");
    // println!("cargo:rustc-link-lib=dylib=rte_telemetry");
    // println!("cargo:rustc-link-lib=dylib=rte_log");
    // println!("cargo:rustc-link-lib=dylib=rte_eal");
    // println!("cargo:rustc-link-lib=dylib=numa");
    // println!("cargo:rustc-link-lib=dylib=rte_net");
    // println!("cargo:rustc-link-lib=dylib=bz2");
    // println!("cargo:rustc-link-lib=dylib=lz4");
    // println!("cargo:rustc-link-lib=dylib=zstd");
    // println!("cargo:rustc-link-lib=dylib=lzma");
    // println!("cargo:rustc-link-lib=dylib=acl");
    // println!("cargo:rustc-link-lib=dylib=crypto");
    // println!("cargo:rustc-link-lib=dylib=archive");
    // println!("cargo:rustc-link-lib=dylib=rte_mempool");
    // println!("cargo:rustc-link-lib=dylib=rte_mbuf");
    // println!("cargo:rustc-link-lib=dylib=rte_telemetry");
    // println!("cargo:rustc-link-lib=dylib=rte_log");
    // println!("cargo:rustc-link-lib=dylib=rte_eal");
    // println!("cargo:rustc-link-lib=dylib=numa");
    // println!("cargo:rustc-link-lib=dylib=rte_log");
    // println!("cargo:rustc-link-lib=dylib=rte_eal");
    // println!("cargo:rustc-link-lib=dylib=rte_ethdev");
    // println!("cargo:rustc-link-lib=dylib=rte_mempool");
    // println!("cargo:rustc-link-lib=dylib=rte_mbuf");
    // println!("cargo:rustc-link-lib=dylib=rte_net");
    // println!("cargo:rustc-link-lib=dylib=rte_eal");
    // println!("cargo:rustc-link-lib=dylib=rte_telemetry");
    // println!("cargo:rustc-link-lib=dylib=rte_log");
    // println!("cargo:rustc-link-lib=dylib=rte_kvargs");
    // println!("cargo:rustc-link-lib=dylib=xml2");
    // println!("cargo:rustc-link-lib=dylib=bz2");
    // println!("cargo:rustc-link-lib=dylib=lz4");
    // println!("cargo:rustc-link-lib=dylib=zstd");
    // println!("cargo:rustc-link-lib=dylib=lzma");
    // println!("cargo:rustc-link-lib=dylib=acl");
    // println!("cargo:rustc-link-lib=dylib=crypto");
    // println!("cargo:rustc-link-lib=dylib=archive");
    // println!("cargo:rustc-link-lib=dylib=numa");

    // // TODO: fix linking order
    // /*00*/ println!("cargo:rustc-link-lib=dylib=rte_net_mlx5"); // 0
    // /*01*/ println!("cargo:rustc-link-lib=dylib=rte_common_mlx5");
    // println!("cargo:rustc-link-lib=dylib=rte_net_ring");
    // println!("cargo:rustc-link-lib=dylib=rte_net");
    // println!("cargo:rustc-link-lib=dylib=rte_bus_pci");
    // println!("cargo:rustc-link-lib=dylib=rte_pci");
    // println!("cargo:rustc-link-lib=dylib=rte_bus_auxiliary");
    // println!("cargo:rustc-link-lib=dylib=rte_bus_vdev");
    // println!("cargo:rustc-link-lib=dylib=rte_cmdline");
    // /*02*/ println!("cargo:rustc-link-lib=dylib=rte_eal"); // 1
    // /*01*/ println!("cargo:rustc-link-lib=dylib=rte_ethdev"); // 1
    // println!("cargo:rustc-link-lib=dylib=rte_hash");
    // println!("cargo:rustc-link-lib=dylib=rte_kvargs");
    // println!("cargo:rustc-link-lib=dylib=rte_log");
    // println!("cargo:rustc-link-lib=dylib=rte_mbuf");
    // println!("cargo:rustc-link-lib=dylib=rte_mempool");
    // println!("cargo:rustc-link-lib=dylib=rte_mempool_bucket");
    // println!("cargo:rustc-link-lib=dylib=rte_mempool_ring");
    // println!("cargo:rustc-link-lib=dylib=rte_mempool_stack");
    // println!("cargo:rustc-link-lib=dylib=rte_meter");
    // println!("cargo:rustc-link-lib=dylib=rte_rcu");
    // println!("cargo:rustc-link-lib=dylib=rte_ring");
    // println!("cargo:rustc-link-lib=dylib=rte_stack");
    // println!("cargo:rustc-link-lib=dylib=rte_telemetry");

    // println!("cargo:rustc-link-lib=dylib=m");
    // println!("cargo:rustc-link-lib=dylib=numa");


    // re-run build.rs upon changes
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/dpdk.h");
}

// // Skip the build script on docs.rs
// fn main() {}

