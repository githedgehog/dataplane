use dpdk_sysroot_helper;

fn main() {
    let sysroot = dpdk_sysroot_helper::get_sysroot();

    println!("cargo:rustc-link-arg=--sysroot={sysroot}");
    println!("cargo:rustc-link-search=all={sysroot}/lib");
}
