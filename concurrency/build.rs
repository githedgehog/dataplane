fn main() {
    println!(r#"cargo::rustc-check-cfg=cfg(concurrency, values("default", "loom", "shuttle"))"#);
    println!(
        r#"cargo::rustc-check-cfg=cfg(dataplane_concurrency_slot, values("default", "fallback"))"#
    );
    cfg_select! {
        all(feature = "shuttle", feature = "loom") => {
            compile_error!(
                "Cannot enable both 'loom' and 'shuttle' features at the same time, disabling both"
            );
        }
        feature = "loom" => {
            println!("cargo::rustc-check-cfg=cfg(loom)");
            println!("cargo::rustc-cfg=loom");
            println!(r#"cargo::rustc-cfg=concurrency="loom""#);
        }
        feature = "shuttle" => {
            println!("cargo::rustc-check-cfg=cfg(shuttle)");
            println!("cargo::rustc-cfg=shuttle");
            println!(r#"cargo::rustc-cfg=concurrency="shuttle""#);
        }
        _ => {
            println!(r#"cargo::rustc-cfg=concurrency="default""#);
        }
    }
    cfg_select! {
        any(feature = "loom", feature = "shuttle") => {
            println!(r#"cargo::rustc-cfg=dataplane_concurrency_slot="fallback""#);
        }
        _ => {
            println!(r#"cargo::rustc-cfg=dataplane_concurrency_slot="default""#);
        }
    }
}
