use std::env;

use std::path::{Path, PathBuf};
use bindgen::callbacks::ParseCallbacks;

#[derive(Debug)]
struct Cb;

impl ParseCallbacks for Cb {
    fn process_comment(&self, comment: &str) -> Option<String> {
        match doxygen_rs::generator::rustdoc(comment.into()) {
            Ok(transformed) => Some(transformed),
            Err(_) => {
                // eprintln!("Error transforming comment: {:?}", err);
                Some(comment.into())
            }
        }
    }
}

fn bind(path: &Path) {
    bindgen::Builder::default()
        .header("c/wrapper.h")
        .anon_fields_prefix("annon")
        .generate_comments(true)
        .generate_inline_functions(false)
        .generate_block(true)
        .array_pointers_in_arguments(false)
        .detect_include_paths(true)
        // .enable_function_attribute_detection()
        .prepend_enum_name(false)
        .translate_enum_integer_types(false)
        .generate_cstr(true)
        .derive_copy(true)
        .derive_debug(true)
        .derive_default(true)
        .derive_partialeq(true)
        .parse_callbacks(Box::new(Cb))
        .default_enum_style(bindgen::EnumVariation::ModuleConsts)
        // .bitfield_enum("rte_eth_tx_offload")
        .allowlist_item("rte.*")
        .allowlist_item("wrte_.*")
        .allowlist_item("RTE.*")
        .blocklist_item("__*")
        .opaque_type("rte_arp_hdr")
        .opaque_type("rte_arp_ipv4")
        .opaque_type("rte_gtp_psc_generic_hdr")
        .opaque_type("rte_l2tpv2_combined_msg_hdr")
        .clang_arg("-Isysroot/usr/include")
        .clang_arg("-fretain-comments-from-system-headers")
        .clang_arg("-fparse-all-comments")
        .clang_arg("-march=native")
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file(path.join("generated.rs"))
        .expect("Couldn't write bindings!");
}

fn main() {

    env::set_var("CC", "clang");
    env::set_var("CXX", "clang++");
    env::set_var("AR", "llvm-ar");
    env::set_var("LD", "rust-lld");


    let outputs = cc::Build::new()
        .file("c/wrapper.c")
        .include("c")
        .include("sysroot/usr/include")
        .cargo_output(false)
        .cargo_debug(false)
        .flag("-Wno-deprecated-declarations")
        .flag("-O3")
        .flag("-flto=thin")
        .compile_intermediates();

    std::process::Command::new("llvm-ar")
        .args(["r", "libdpdk_wrapper.a", outputs[0].to_str().unwrap()])
        .output()
        .expect("failed to archive wrapper");

    std::process::Command::new("mv")
        .args(["libdpdk_wrapper.a", "sysroot/usr/lib"])
        .output()
        .expect("failed to move wrapper");

    // std::process::Command::new("mv")
    //     .args(["libdpdk_wrapper.a", "/usr/lib"])
    //     .output()
    //     .expect("failed to move wrapper");

    println!("cargo:rustc-link-search=native=dpdk-sys/sysroot/usr/lib");
    // println!("cargo:rustc-link-search=native=/usr/lib");

    // NOTE: DPDK absolutely requires whole-archive in the linking command.
    // While I find this very questionable, it is what it is.
    // It is just more work for the LTO later on I suppose ¯\_(ツ)_/¯
    println!("cargo:rustc-link-lib=static:+whole-archive=dpdk_wrapper");
    println!("cargo:rustc-link-lib=static:+whole-archive=rte_net_mlx5");
    println!("cargo:rustc-link-lib=static:+whole-archive=rte_common_mlx5");
    println!("cargo:rustc-link-lib=static:+whole-archive=rte_ethdev");
    println!("cargo:rustc-link-lib=static:+whole-archive=rte_bus_auxiliary");
    println!("cargo:rustc-link-lib=static:+whole-archive=rte_net");
    println!("cargo:rustc-link-lib=static:+whole-archive=rte_bus_pci");
    println!("cargo:rustc-link-lib=static:+whole-archive=rte_pci");
    println!("cargo:rustc-link-lib=static:+whole-archive=rte_mbuf");
    println!("cargo:rustc-link-lib=static:+whole-archive=rte_mempool_ring");
    println!("cargo:rustc-link-lib=static:+whole-archive=rte_mempool");
    println!("cargo:rustc-link-lib=static:+whole-archive=rte_hash");
    println!("cargo:rustc-link-lib=static:+whole-archive=rte_rcu");
    println!("cargo:rustc-link-lib=static:+whole-archive=rte_ring");
    println!("cargo:rustc-link-lib=static:+whole-archive=rte_eal");
    println!("cargo:rustc-link-lib=static:+whole-archive=rte_kvargs");
    println!("cargo:rustc-link-lib=static:+whole-archive=rte_telemetry");
    println!("cargo:rustc-link-lib=static:+whole-archive=rte_log");

    // TODO: do we need whole-archive for these?
    println!("cargo:rustc-link-lib=static:+whole-archive=ibverbs");
    println!("cargo:rustc-link-lib=static:+whole-archive=mlx5");

    // TODO: see if we can't get these to be static
    println!("cargo:rustc-link-lib=dylib=nl-route-3");
    println!("cargo:rustc-link-lib=dylib=nl-3");

    // println!("cargo:rustc-link-lib=dylib=archive");
    // println!("cargo:rustc-link-lib=dylib=acl");
    // println!("cargo:rustc-link-lib=dylib=bz2");
    // println!("cargo:rustc-link-lib=dylib=crypto");
    // println!("cargo:rustc-link-lib=dylib=lz4");

    // TODO: Ideally this would be static, but numa fails to link statically
    // due to some linker script issues I have not looked into yet.
    println!("cargo:rustc-link-lib=dylib=numa");

    // println!("cargo:rustc-link-lib=dylib=xml2");
    // println!("cargo:rustc-link-lib=dylib=z");
    // println!("cargo:rustc-link-lib=dylib=zstd");
    // println!("cargo:rustc-link-lib=dylib=icuuc");
    // println!("cargo:rustc-link-lib=dylib=icudata");
    // println!("cargo:rustc-link-lib=dylib=lzma");
    // println!("cargo:rustc-link-lib=dylib=atomic");

    // re-run build.rs upon changes
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=c/wrapper.h");
    println!("cargo:rerun-if-changed=c/wrapper.c");
    println!("cargo:rerun-if-changed=c/dpdk.h");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    // let out_path = PathBuf::from("src");

    bind(&out_path);

}
