pub use fake_kani_macro::proof;

pub fn any<T>() -> T {
    unimplemented!("(fake kani) called kani::any() in non-kani context");
}

pub fn assume(_: bool) {
    panic!("(fake kani) called kani::assume() in non-kani context")
}
