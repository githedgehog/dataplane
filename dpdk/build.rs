fn main() {
    let sysroot = dpdk_sysroot_helper::get_sysroot();
    println!("cargo:rustc-link-search=all={sysroot}/lib");
    println!("cargo:rustc-link-arg=--sysroot={sysroot}");
}
