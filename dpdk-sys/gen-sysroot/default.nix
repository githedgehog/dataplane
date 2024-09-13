{ pkgsFn ? import <nixpkgs> }:
  let
  	overlays = {
	 disableAppArmor = self: super: { libapparmor = null; };
	 disableSystemd = self: super: { systemd = null; }; # git rekt
	 disableDoxygen = self: super: { doxygen = null; };
	 useLlvm = self: super: { llvmPackages = super.llvmPackages_19; };
  	};
	defaultOverlays = [
	  overlays.disableAppArmor
	  overlays.disableSystemd
	  overlays.disableDoxygen
	  overlays.useLlvm
	];

	# NOTE: this is obviously impure since it use -march=native
	fancyCFLAGS = "-O3 -match=native -mtune=native -flto=thin -Wl,--plugin-opt=O3";
	fancyLDFLAGS = "-fuse-ld=mold -Wl,-z,relro,-z,now -pie -Wl,--as-needed";

	useStdenv = stdenv: package: package.override { stdenv = stdenv; };
	useLto = super: pkg: (pkg.overrideAttrs (orig: {
	  nativeBuildInputs = (orig.nativeBuildInputs or []) ++ [ super.llvmPackages.bintools ];
	  CFLAGS = "${orig.CFLAGS or ""} ${fancyCFLAGS}";
	  CXXFLAGS = "${orig.CXXFLAGS or ""} ${fancyCFLAGS}";
	  LDFLAGS = "${orig.LDFLAGS or ""} ${fancyLDFLAGS}";
	}));
    pkgs = (pkgsFn {
	  overlays = defaultOverlays ++ [
		(self: super: let
		  cc = super.llvmPackages.clangUseLLVM;
		  stdenv = with super; overrideCC llvmPackages.stdenv cc;
		  useCustomStdenv = (pkg: (useStdenv stdenv pkg));
		  optimize = (pkg: (useLto super (useCustomStdenv pkg)));
		  in {
			rdma-core = optimize (super.rdma-core.overrideAttrs (orig: {
			  nativeBuildInputs = with super; [ cmake pkg-config python3 mold ];
			  outputs = pkgs.lib.lists.remove "man" orig.outputs;
			  buildInputs = with super; [ libnl ethtool iproute2 ];
			  CFLAGS = "${orig.CFLAGS or ""} ${fancyCFLAGS} -ffat-lto-objects -funified-lto";
			  LDFLAGS = "${orig.LDFLAGS or ""} ${fancyLDFLAGS}";
			  cmakeFlags = orig.cmakeFlags ++ [
				"-DENABLE_STATIC=1"
				"-DNO_MAN_PAGES=1"
				"-DNO_PY_VERBS=1"
			  ];
			}));

			overlayStdenv = stdenv;
		  }
		)
	  ];
	}).pkgsMusl;
    overrides = (builtins.fromTOML (builtins.readFile ./toolchain.toml));
    libPath = with pkgs; lib.makeLibraryPath [
      # load external libraries that you need in your rust project here
    ];
    llvm = pkgs.llvmPackages;
    rustup = pkgs.rustup.overrideAttrs (orig: { doCheck = false; });
in
  pkgs.mkShell rec {
    buildInputs = [
      llvm.clang
      llvm.bintools
      rustup
      pkgs.rdma-core
    ];

  	CFLAGS = "-O3 -match=native -flto=thin";
  	NIX_CFLAGS = "${CFLAGS}";
  	LDFLAGS = "-fuse-ld=mold";
  	NIX_LDFLAGS = "${LDFLAGS}";
    RUSTC_VERSION = overrides.toolchain.channel;
    # https://github.com/rust-lang/rust-bindgen#environment-variables
    LIBCLANG_PATH = pkgs.lib.makeLibraryPath [ llvm.libclang.lib ];
    shellHook = ''
      export PATH=$PATH:''${CARGO_HOME:-~/.cargo}/bin
      export PATH=$PATH:''${RUSTUP_HOME:-~/.rustup}/toolchains/${RUSTC_VERSION}-x86_64-unknown-linux-gnu/bin/
      '';
    # Add precompiled library to rustc search path
    RUSTFLAGS = (builtins.map (a: ''-L ${a}/lib'') [
      # add libraries here (e.g. pkgs.libvmi)
    ]);
    LD_LIBRARY_PATH = libPath;
    # Add glibc, clang, glib, and other headers to bindgen search path
    BINDGEN_EXTRA_CLANG_ARGS =
    # Includes normal include path
    (builtins.map (a: ''-I"${a}/include"'') [
      # add dev libraries here (e.g. pkgs.libvmi.dev)
      pkgs.glibc.dev
    ])
    # Includes with special directory paths
    ++ [
      ''-I"${pkgs.llvmPackages_latest.libclang.lib}/lib/clang/${llvm.libclang.version}/include"''
      ''-I"${pkgs.glib.dev}/include/glib-2.0"''
      ''-I${pkgs.glib.out}/lib/glib-2.0/include/''
    ];
  }
