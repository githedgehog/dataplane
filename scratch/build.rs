fn main() {
    let sysroot = dpdk_sysroot_helper::get_sysroot();
    let project_root = dpdk_sysroot_helper::get_project_root();
    let rerun_if_changed = ["build.rs".to_string(), format!("{project_root}/../sysroot")];
    rerun_if_changed.iter().for_each(|file| {
        println!("cargo:rerun-if-changed={file}");
    });
    println!("cargo:rustc-link-search=all={sysroot}/lib");
    println!("cargo:rustc-link-arg=--sysroot={sysroot}");
}
