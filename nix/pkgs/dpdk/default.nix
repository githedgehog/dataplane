# SPDX-License-Identifier: Apache-2.0
# Copyright Open Network Fabric Authors
{
  src,
  stdenv,
  lib,
  pkg-config,
  meson,
  ninja,
  libbsd,
  numactl,
  rdma-core,
  libnl,
  python3,
  build-params ? {
    lto = "true";
    build-type = "release"; # "debug" | "release"
    platform = "bluefield3";
  },
  writeText,
}:

stdenv.mkDerivation {
  pname = "dpdk";
  version = src.branch;
  # src = src.outPath;
  src = ./src;
  nativeBuildInputs = [
    meson
    ninja
    pkg-config
    python3
    python3.pkgs.pyelftools
  ];

  buildInputs = [
    libbsd
    libnl
    numactl
    rdma-core
  ];

  postPatch = ''
    patchShebangs config/arm buildtools
    # We have no use for RTE_TRACE at all and it makes things more difficult from a security POV so disable it
    sed -i 's/#define RTE_TRACE 1/#undef RTE_TRACE/g' config/rte_config.h
    # We have no use for receive or transmit callbacks at this time so disable them
    sed -i 's/#define RTE_ETHDEV_RXTX_CALLBACKS 1/#undef RTE_ETHDEV_RXTX_CALLBACKS/g' config/rte_config.h
  '';

  mesonFlags =
    let
      disabledLibs = [
        "acl"
        "argparse"
        "bbdev"
        "bitratestats"
        "bpf"
        "cfgfile"
        "compressdev"
        "dispatcher"
        "distributor"
        "efd"
        "fib"
        "gpudev"
        "graph"
        "gro"
        "gso"
        "ip_frag"
        "ipsec"
        "jobstats"
        "latencystats"
        "lpm"
        "member"
        "metrics"
        "mldev"
        "node"
        "pcapng"
        "pdcp"
        "pdump"
        "pipeline"
        "port"
        "power"
        "ptr_compress"
        "rawdev"
        "regexdev"
        "reorder"
        "rib"
        "sched"
        "table"
      ];
      enabledLibs = [
        "cryptodev" # required for vhost
        "dmadev" # required by vhost
        "ethdev"
        "eventdev"
        "pci"
        "security"
        "timer"
        "vhost"
      ];
      disabledDrivers = [
        "baseband/*"
        "bus/ifpga"
        "bus/vdev"
        "bus/vmbus"
        "common/cnxk"
        "common/cpt"
        "common/dpaax"
        "common/octeontx"
        "common/octeontx2"
        "common/qat"
        "common/sfc_efx"
        "compress/*"
        "compress/mlx5"
        "compress/zlib"
        "crypto/*"
        "crypto/aesni_gcm"
        "crypto/aesni_mb"
        "crypto/bcmfs"
        "crypto/ccp"
        "crypto/kasumi"
        "crypto/mlx5"
        "crypto/nitrox"
        "crypto/null"
        "crypto/openssl"
        "crypto/scheduler"
        "crypto/snow3g"
        "crypto/virtio"
        "crypto/zuc"
        "event/dlb"
        "event/dsw"
        "event/opdl"
        "event/skeleton"
        "event/sw"
        "net/acc100"
        "net/af_packet"
        "net/af_xdp"
        "net/ark"
        "net/atlantic"
        "net/avp"
        "net/axgbe"
        "net/bcmfs"
        "net/bnx2x"
        "net/bnxt"
        "net/bond"
        "net/caam_jr"
        "net/ccp"
        "net/cnxk"
        "net/cnxk_bphy"
        "net/cpt"
        "net/cxgbe"
        "net/dlb2"
        "net/dpaa"
        "net/dpaa2"
        "net/dpaa2_cmdif"
        "net/dpaa2_qdma"
        "net/dpaa2_sec"
        "net/dpaa_sec"
        "net/dpaax"
        "net/dsw"
        "net/ena"
        "net/enetc"
        "net/enic"
        "net/failsafe"
        "net/fm10k"
        "net/fpga_5gnr_fec"
        "net/fpga_lte_fec"
        "net/fslmc"
        "net/hinic"
        "net/hns3"
        "net/ifc"
        "net/ifpga"
        "net/igc"
        "net/ioat"
        "net/ionic"
        "net/ipn3ke"
        "net/kasumi"
        "net/kni"
        "net/liquidio"
        "net/memif"
        "net/mlx4"
        "net/netvsc"
        "net/nfp"
        "net/ngbe"
        "net/nitrox"
        "net/ntb"
        "net/null"
        "net/octeontx"
        "net/octeontx2"
        "net/octeontx2_dma"
        "net/octeontx2_ep"
        "net/octeontx_ep"
        "net/opdl"
        "net/pcap"
        "net/pfe"
        "net/qede"
        "net/sfc"
        "net/sfc_efx"
        "net/skeleton"
        "net/snow3g"
        "net/softnic"
        "net/tap"
        "net/thunderx"
        "net/turbo_sw"
        "net/txgbe"
        "net/vdev"
        "net/vdev_netvsc"
        "net/vmbus"
        "net/vmxnet3"
        "net/zuc"
        "raw/*"
        "raw/ioat"
        "raw/ntb"
        "raw/skeleton"
        "regex/*"
        "regex/mlx5"
        "vdpa/*"
        "vdpa/ifc"
      ];
      enabledDrivers = [
        "bus/auxiliary"
        "bus/pci"
        "common/mlx5"
        "mempool/bucket"
        "mempool/ring"
        "mempool/stack"
        "net/auxiliary"
        "net/dmadev"
        "net/intel/e1000"
        "net/intel/i40e"
        "net/intel/iavf"
        "net/intel/ixgbe"
        "net/mlx5"
        "net/ring"
        "net/vhost"
        "net/virtio"
        "vdpa/mlx5"
      ];
      arch = stdenv.hostPlatform.parsed.cpu.name;
      cpu = stdenv.hostPlatform.parsed.cpu.arch;
      kernel = stdenv.hostPlatform.parsed.kernel.name;
      endian =
        {
          littleEndian = "little";
          bigEndian = "big";
        }
        .${stdenv.hostPlatform.parsed.cpu.significantByte.name};
      libc-vendor =
        {
          glibc = "gnu";
          musl = "musl";
        }
        .${stdenv.hostPlatform.libc};
      isCrossCompile = stdenv.buildPlatform.parsed != stdenv.hostPlatform.parsed;
      cross-prefix = "${arch}-unknown-${kernel}-${libc-vendor}";
      cross-file = writeText "cross-file.ini" ''
        [binaries]
        c = '${cross-prefix}-cc'
        cpp = '${cross-prefix}-c++'
        ar = '${cross-prefix}-ar'
        strip = '${cross-prefix}-strip'
        pkgconfig = '${cross-prefix}-pkg-config'
        pkg-config = '${cross-prefix}-pkg-config'

        [host_machine]
        system = '${kernel}'
        cpu_family = '${arch}'
        cpu = '${cpu}'
        endian = '${endian}'

        [properties]
        platform = '${build-params.platform}'
        libc = '${libc-vendor}'
      '';
    in
    with build-params;
    [
      "--buildtype=${build-type}"
      "-Dauto_features=disabled"
      "-Db_colorout=never"
      "-Db_lto=${lto}"
      "-Db_lundef=false"
      "-Db_pgo=off"
      "-Db_pie=true"
      "-Dbackend=ninja"
      "-Ddefault_library=static"
      "-Denable_docs=false"
      "-Denable_driver_sdk=false"
      "-Dmax_numa_nodes=8"
      "-Dtests=false" # Running DPDK tests in CI is usually silly
      "-Duse_hpet=false"
      "-Ddebug=false"
      ''-Ddisable_drivers=${lib.concatStringsSep "," disabledDrivers}''
      ''-Denable_drivers=${lib.concatStringsSep "," enabledDrivers}''
      ''-Denable_libs=${lib.concatStringsSep "," enabledLibs}''
      ''-Ddisable_libs=${lib.concatStringsSep "," disabledLibs}''
    ]
    ++ (if isCrossCompile then [ ''--cross-file=${cross-file}'' ] else [ ]);

  outputs = [
    "dev"
    "out"
    "share"
    "static"
  ];

  CFLAGS = if stdenv.targetPlatform.parsed.cpu.name == "aarch64" then "-ffat-lto-objects" else "";

  postInstall = ''
    # Remove docs.  We don't build these anyway
    rm -rf $out/share/doc
    mkdir -p $static/lib $share;
    mv $out/lib/*.a $static/lib
    mv $out/share $share
  '';

  meta = with lib; {
    description = "Set of libraries and drivers for fast packet processing";
    homepage = "http://dpdk.org/";
    license = with licenses; [
      lgpl21
      gpl2
      bsd2
    ];
    platforms = platforms.linux;
  };
}
