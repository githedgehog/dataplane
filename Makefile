export RUSTFLAGS?=-C linker=${HOME}/.rustup/toolchains/nightly-x86_64-unknown-linux-gnu/lib/rustlib/x86_64-unknown-linux-gnu/bin/gcc-ld/ld.lld

install-nix:
	sh <(curl -L https://nixos.org/nix/install) --no-daemon

sysroot:
	echo "Building sysroot..."
	rm sysroot || true
	nix build -f default.nix 'env' --out-link sysroot
	echo "Built sysroot."

update-channel:
	nix-channel --update

update-flake: update-channel
	nix flake update

build: sysroot
	cargo build --target=x86_64-unknown-linux-musl

test: build
	cargo test --target=x86_64-unknown-linux-musl
