FROM archlinux

SHELL ["/bin/bash", "-eu", "-o", "pipefail", "-c"]

RUN pacman --sync --refresh --sysupgrade --noconfirm \
 && pacman --sync --noconfirm \
    autoconf \
    automake \
    clang \
    cmake \
    git \
    linux-headers \
    lld \
    llvm \
    make \
    meson \
    mold \
    ninja \
    pkgconf \
    python-pyelftools \
    wget \
; \
:;

WORKDIR /usr/src

ENV IDEAL_LTO_TYPE="thin"
ENV IDEAL_OPT_LEVEL="3"
ENV IDEAL_CPU_ARCH="x86-64-v4"
#ENV CPU_ARCH="znver4"
ENV IDEAL_CPU_TUNE="znver4"

ENV DEV_LTO_TYPE="thin"
# -Og optimizes for debugging
ENV DEV_OPT_LEVEL="g"
ENV DEV_CPU_ARCH="generic"
ENV DEV_CPU_TUNE="generic"

ENV IDEAL_CC="clang"
ENV IDEAL_CPP="clang-cpp"
ENV IDEAL_LD="mold"
ENV IDEAL_CXX="clang++"
ENV IDEAL_AR="llvm-ar"
ENV IDEAL_NM="llvm-nm"
ENV IDEAL_RANLIB="llvm-ranlib"

ENV DEV_CC="${IDEAL_CC}"
ENV DEV_CPP="${IDEAL_CPP}"
ENV DEV_LD="${IDEAL_LD}"
ENV DEV_CXX="${IDEAL_CXX}"
ENV DEV_AR="${IDEAL_AR}"
ENV DEV_NM="${IDEAL_NM}"
ENV DEV_RANLIB="${IDEAL_RANLIB}"
#
ENV IDEAL_CFLAGS_OPT_LEVEL="-O${IDEAL_OPT_LEVEL}"
ENV IDEAL_CFLAGS_MARCH="-march=${IDEAL_CPU_ARCH}"
ENV IDEAL_CFLAGS_TUNE="-mtune=${IDEAL_CPU_TUNE}"
ENV IDEAL_CFLAGS_LTO="-flto=${IDEAL_LTO_TYPE}"
ENV IDEAL_CFLAGS_WERROR="-Werror=odr -Werror=strict-aliasing"
ENV IDEAL_CFLAGS_PIC="-fPIC"
# TODO: when rustc stabilizes support for safe-stack and cfi we should enable this
# TODO: poke ibverbs and figure out why it is mad at the safe-stack and cfi sanitizers.
# It's not a priority right now, but it would be nice to have when it stabilizes in rustc.
#ENV IDEAL_CFLAGS_SECURITY_FLAGS="-fstack-protector-strong -fsanitize=safe-stack -fsanitize=cfi"
ENV IDEAL_CFLAGS_SECURITY_FLAGS="-fstack-protector-strong"

ENV DEV_CFLAGS_OPT_LEVEL="-O${DEV_OPT_LEVEL}"
ENV DEV_CFLAGS_MARCH="-march=${DEV_CPU_ARCH}"
ENV DEV_CFLAGS_TUNE="-mtune=${DEV_CPU_TUNE}"
ENV DEV_CFLAGS_LTO="-flto=${DEV_LTO_TYPE}"
ENV DEV_CFLAGS_WERROR="${IDEAL_CFLAGS_WERROR}"
ENV DEV_CFLAGS_PIC="${IDEAL_CFLAGS_PIC}"
# TODO: when rustc stabilizes support for safe-stack and cfi we should enable this
# TODO: poke ibverbs and figure out why it is mad at the safe-stack and cfi sanitizers.
# It's not a priority right now, but it would be nice to have when it stabilizes in rustc.
#ENV DEV_CFLAGS_SECURITY_FLAGS="-fstack-protector-strong -fsanitize=safe-stack -fsanitize=cfi"
#ENV DEV_CFLAGS_SANITIZE_FLAGS="-fstack-protector-all -fsanitize=address -fno-inline -fno-omit-frame-pointer"
ENV DEV_CFLAGS_SANITIZE_FLAGS=""

ENV IDEAL_CFLAGS="${IDEAL_CFLAGS} ${IDEAL_CFLAGS_OPT_LEVEL}"
#ENV IDEAL_CFLAGS="${IDEAL_CFLAGS} ${IDEAL_CFLAGS_MARCH}"
#ENV IDEAL_CFLAGS="${IDEAL_CFLAGS} ${IDEAL_CFLAGS_TUNE}"
ENV IDEAL_CFLAGS="${IDEAL_CFLAGS} ${IDEAL_CFLAGS_LTO}"
ENV IDEAL_CFLAGS="${IDEAL_CFLAGS} ${IDEAL_CFLAGS_WERROR}"
ENV IDEAL_CFLAGS="${IDEAL_CFLAGS} ${IDEAL_CFLAGS_PIC}"
ENV IDEAL_CFLAGS="${IDEAL_CFLAGS} ${IDEAL_CFLAGS_SECURITY_FLAGS}"

ENV DEV_CFLAGS="${DEV_CFLAGS} ${DEV_CFLAGS_OPT_LEVEL}"
#ENV DEV_CFLAGS="${DEV_CFLAGS} ${DEV_CFLAGS_MARCH}"
#ENV DEV_CFLAGS="${DEV_CFLAGS} ${DEV_CFLAGS_TUNE}"
ENV DEV_CFLAGS="${DEV_CFLAGS} ${DEV_CFLAGS_LTO}"
ENV DEV_CFLAGS="${DEV_CFLAGS} ${DEV_CFLAGS_WERROR}"
ENV DEV_CFLAGS="${DEV_CFLAGS} ${DEV_CFLAGS_PIC}"
ENV DEV_CFLAGS="${DEV_CFLAGS} ${DEV_CFLAGS_SANITIZE_FLAGS} -ggdb3"

ENV IDEAL_CXXFLAGS="${IDEAL_CFLAGS}"
ENV DEV_CXXFLAGS="${DEV_CFLAGS}"

ENV IDEAL_LDFLAGS_USE_LD="-fuse-ld=${IDEAL_LD}"
ENV IDEAL_LDFLAGS_OPT_LEVEL="-Wl,-O2"
ENV IDEAL_LDFLAGS_GC_SECTIONS="-Wl,-gc-sections"
# Sadly we need this for DPDK
ENV IDEAL_LDFLAGS_AS_WHOLE_ARCHIVE="-Wl,--whole-archive"
ENV IDEAL_LDFLAGS_SECURITY_FLAGS="-Wl,-z,relro,-z,now"

ENV IDEAL_LDFLAGS=""
ENV IDEAL_LDFLAGS="${IDEAL_LDFLAGS} ${IDEAL_LDFLAGS_USE_LD}"
ENV IDEAL_LDFLAGS="${IDEAL_LDFLAGS} ${IDEAL_LDFLAGS_OPT_LEVEL}"
ENV IDEAL_LDFLAGS="${IDEAL_LDFLAGS} ${IDEAL_LDFLAGS_GC_SECTIONS}"
ENV IDEAL_LDFLAGS="${IDEAL_LDFLAGS} ${IDEAL_LDFLAGS_AS_WHOLE_ARCHIVE}"
ENV IDEAL_LDFLAGS="${IDEAL_LDFLAGS} ${IDEAL_LDFLAGS_SECURITY_FLAGS}"
#ENV IDEAL_LDFLAGS="${IDEAL_LDFLAGS} -L/usr/lib"

ENV DEV_LDFLAGS_USE_LD="-fuse-ld=${DEV_LD}"
ENV DEV_LDFLAGS_OPT_LEVEL="-Wl,-O2"
ENV DEV_LDFLAGS_GC_SECTIONS="-Wl,-gc-sections"
# Sadly we need this for DPDK
ENV DEV_LDFLAGS_AS_WHOLE_ARCHIVE="-Wl,--whole-archive"
ENV DEV_LDFLAGS_SECURITY_FLAGS="${DEV_CFLAGS_SANITIZE_FLAGS} -Wl,-z,relro,-z,now"

ENV DEV_LDFLAGS=""
ENV DEV_LDFLAGS="${DEV_LDFLAGS} ${DEV_LDFLAGS_USE_LD}"
ENV DEV_LDFLAGS="${DEV_LDFLAGS} ${DEV_LDFLAGS_OPT_LEVEL}"
ENV DEV_LDFLAGS="${DEV_LDFLAGS} ${DEV_LDFLAGS_GC_SECTIONS}"
ENV DEV_LDFLAGS="${DEV_LDFLAGS} ${DEV_LDFLAGS_AS_WHOLE_ARCHIVE}"
ENV DEV_LDFLAGS="${DEV_LDFLAGS} ${DEV_LDFLAGS_SECURITY_FLAGS}"
#ENV DEV_LDFLAGS="${DEV_LDFLAGS} -L/usr/lib"

ENV CC="${IDEAL_CC}"
ENV LD="${IDEAL_LD}"
ENV CPP="${IDEAL_CPP}"
ENV CXX="${IDEAL_CXX}"
ENV AR="${IDEAL_AR}"
ENV NM="${IDEAL_NM}"
ENV RANLIB="${IDEAL_RANLIB}"

ENV CFLAGS="${IDEAL_CFLAGS}"
ENV CXXFLAGS="${CFLAGS}"
ENV LDFLAGS="${IDEAL_LDFLAGS} -fuse-ld=mold"

ENV NUMACTL_VERSION="2.0.18"
RUN mkdir --parent /usr/src/ \
 && cd /usr/src \
 && git clone --depth 1 --branch "v${NUMACTL_VERSION}" "https://github.com/numactl/numactl.git" \
 && cd /usr/src/numactl \
 && ./autogen.sh \
 && ./configure --prefix=/usr --disable-static --enable-shared \
 && make --jobs="$(nproc)" \
 && make install

ENV CFLAGS="${IDEAL_CFLAGS} -ffat-lto-objects -funified-lto"
ENV CXXFLAGS="${CFLAGS}"

ENV LD="${IDEAL_LD}"
ENV LDFLAGS="${IDEAL_LDFLAGS}"

ENV RDMA_CORE_VERSION="53.0"
RUN mkdir --parent /usr/src/ \
 && wget --output-document=- "https://github.com/linux-rdma/rdma-core/releases/download/v${RDMA_CORE_VERSION}/rdma-core-${RDMA_CORE_VERSION}.tar.gz" \
  | tar --extract --file - --gzip --directory=/usr/src \
 && ln --relative --symbolic /usr/src/rdma-core-"${RDMA_CORE_VERSION}" /usr/src/rdma-core \
 && mkdir /usr/src/rdma-core/build \
 && cd /usr/src/rdma-core/build \
 && cmake \
    -DNO_PYVERBS=1 \
    -DNO_MAN_PAGES=1 \
    -DENABLE_STATIC=1 \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX:PATH=/usr \
    -G Ninja \
    .. \
 && ninja

RUN cd /usr/src/rdma-core/build \
 && ninja install

#RUN pacman --sync --refresh --sysupgrade --noconfirm \
# && pacman --sync --noconfirm libdrm;
#
#RUN mkdir --parent /usr/src \
# && wget --output-document=- "https://www.mellanox.com/downloads/ofed/MLNX_OFED-24.07-0.6.1.0/MLNX_OFED_SRC-debian-24.07-0.6.1.0.tgz" \
#  | tar --extract --file - --gzip --directory=/usr/src \
# && ln --relative --symbolic /usr/src/MLNX_OFED_SRC-24.07-0.6.1.0 ofed \
# && cd /usr/src/ofed/SOURCES \
# && tar --extract --file=rdma-core_2407mlnx52.orig.tar.gz \
# && cd /usr/src/ofed/SOURCES/rdma-core-2407mlnx52 \
# && mkdir build \
# && cd build \
# && cmake \
#   -DDRM_INCLUDE_DIRS=/usr/include/libdrm \
#   -DNO_PYVERBS=1 \
#   -DNO_MAN_PAGES=1 \
#   -DENABLE_STATIC=1 \
#   -DCMAKE_BUILD_TYPE=Release \
#   -DCMAKE_INSTALL_PREFIX:PATH=/usr \
#   -G Ninja \
#   .. \
# && ninja install

ENV DEV_LDFLAGS=""
ENV DEV_LDFLAGS="${DEV_LDFLAGS} ${DEV_LDFLAGS_USE_LD}"
ENV DEV_LDFLAGS="${DEV_LDFLAGS} ${DEV_LDFLAGS_OPT_LEVEL}"
ENV DEV_LDFLAGS="${DEV_LDFLAGS} ${DEV_LDFLAGS_GC_SECTIONS}"
ENV DEV_LDFLAGS="${DEV_LDFLAGS} ${DEV_LDFLAGS_AS_WHOLE_ARCHIVE}"
ENV DEV_LDFLAGS="${DEV_LDFLAGS} ${DEV_LDFLAGS_SECURITY_FLAGS}"

ENV LD="lld"
ENV LDFLAGS="${DEV_LDFLAGS}"
ENV CPU_ARCH="${DEV_CPU_ARCH}"
ENV CFLAGS="${DEV_CFLAGS}"
ENV CXXFLAGS="${CFLAGS}"

# Fetch DPDK
ENV DPDK_ARCH="x86_64"
ENV DPDK_EXECENV="linuxapp"
ENV DPDK_MACHINE="native"
ENV DPDK_TOOLCHAIN="clang"
ENV DPDK_VERSION="24.07"
ENV DPDK_TARGET="${DPDK_ARCH}-${DPDK_MACHINE}-${DPDK_EXECENV}-${DPDK_TOOLCHAIN}"
RUN mkdir --parent /usr/src/ \
 && wget --output-document=- "https://fast.dpdk.org/rel/dpdk-${DPDK_VERSION}.tar.xz" \
  | tar --extract --file - --xz --directory=/usr/src \
 && ln --relative --symbolic "/usr/src/dpdk-${DPDK_VERSION}" /usr/src/dpdk

ENV _disabled_drivers=""
ENV _disabled_drivers="${_disabled_drivers}baseband/*,"
ENV _disabled_drivers="${_disabled_drivers}bus/ifpga,"
ENV _disabled_drivers="${_disabled_drivers}bus/vdev,"
ENV _disabled_drivers="${_disabled_drivers}bus/vmbus,"
ENV _disabled_drivers="${_disabled_drivers}common/cnxk,"
ENV _disabled_drivers="${_disabled_drivers}common/cpt,"
ENV _disabled_drivers="${_disabled_drivers}common/dpaax,"
ENV _disabled_drivers="${_disabled_drivers}common/iavf,"
ENV _disabled_drivers="${_disabled_drivers}common/octeontx,"
ENV _disabled_drivers="${_disabled_drivers}common/octeontx2"
ENV _disabled_drivers="${_disabled_drivers}common/qat,"
ENV _disabled_drivers="${_disabled_drivers}common/sfc_efx,"
ENV _disabled_drivers="${_disabled_drivers}compress/mlx5,"
ENV _disabled_drivers="${_disabled_drivers}compress/zlib,"
ENV _disabled_drivers="${_disabled_drivers}crypto/aesni_gcm,"
ENV _disabled_drivers="${_disabled_drivers}crypto/aesni_mb,"
ENV _disabled_drivers="${_disabled_drivers}crypto/bcmfs,"
ENV _disabled_drivers="${_disabled_drivers}crypto/ccp,"
ENV _disabled_drivers="${_disabled_drivers}crypto/kasumi,"
ENV _disabled_drivers="${_disabled_drivers}crypto/mlx5,"
ENV _disabled_drivers="${_disabled_drivers}crypto/nitrox,"
ENV _disabled_drivers="${_disabled_drivers}crypto/null,"
ENV _disabled_drivers="${_disabled_drivers}crypto/openssl,"
ENV _disabled_drivers="${_disabled_drivers}crypto/scheduler,"
ENV _disabled_drivers="${_disabled_drivers}crypto/snow3g,"
ENV _disabled_drivers="${_disabled_drivers}crypto/virtio,"
ENV _disabled_drivers="${_disabled_drivers}crypto/zuc,"
ENV _disabled_drivers="${_disabled_drivers}event/dlb,"
ENV _disabled_drivers="${_disabled_drivers}event/dsw,"
ENV _disabled_drivers="${_disabled_drivers}event/opdl,"
ENV _disabled_drivers="${_disabled_drivers}event/skeleton,"
ENV _disabled_drivers="${_disabled_drivers}event/sw,"
ENV _disabled_drivers="${_disabled_drivers}net/acc100,"
ENV _disabled_drivers="${_disabled_drivers}net/af_packet,"
ENV _disabled_drivers="${_disabled_drivers}net/af_xdp,"
ENV _disabled_drivers="${_disabled_drivers}net/ark,"
ENV _disabled_drivers="${_disabled_drivers}net/atlantic,"
ENV _disabled_drivers="${_disabled_drivers}net/avp,"
ENV _disabled_drivers="${_disabled_drivers}net/axgbe,"
ENV _disabled_drivers="${_disabled_drivers}net/bcmfs,"
ENV _disabled_drivers="${_disabled_drivers}net/bnx2x,"
ENV _disabled_drivers="${_disabled_drivers}net/bnxt,"
ENV _disabled_drivers="${_disabled_drivers}net/bond,"
ENV _disabled_drivers="${_disabled_drivers}net/caam_jr,"
ENV _disabled_drivers="${_disabled_drivers}net/ccp,"
ENV _disabled_drivers="${_disabled_drivers}net/cnxk,"
ENV _disabled_drivers="${_disabled_drivers}net/cnxk_bphy,"
ENV _disabled_drivers="${_disabled_drivers}net/cpt,"
ENV _disabled_drivers="${_disabled_drivers}net/cxgbe,"
ENV _disabled_drivers="${_disabled_drivers}net/dlb2,"
ENV _disabled_drivers="${_disabled_drivers}net/dpaa,"
ENV _disabled_drivers="${_disabled_drivers}net/dpaa2,"
ENV _disabled_drivers="${_disabled_drivers}net/dpaa2_cmdif,"
ENV _disabled_drivers="${_disabled_drivers}net/dpaa2_qdma,"
ENV _disabled_drivers="${_disabled_drivers}net/dpaa2_sec,"
ENV _disabled_drivers="${_disabled_drivers}net/dpaa_sec,"
ENV _disabled_drivers="${_disabled_drivers}net/dpaax,"
ENV _disabled_drivers="${_disabled_drivers}net/dsw,"
ENV _disabled_drivers="${_disabled_drivers}net/e1000,"
ENV _disabled_drivers="${_disabled_drivers}net/ena,"
ENV _disabled_drivers="${_disabled_drivers}net/enetc,"
ENV _disabled_drivers="${_disabled_drivers}net/enic,"
ENV _disabled_drivers="${_disabled_drivers}net/failsafe,"
ENV _disabled_drivers="${_disabled_drivers}net/fm10k,"
ENV _disabled_drivers="${_disabled_drivers}net/fpga_5gnr_fec,"
ENV _disabled_drivers="${_disabled_drivers}net/fpga_lte_fec,"
ENV _disabled_drivers="${_disabled_drivers}net/fslmc,"
ENV _disabled_drivers="${_disabled_drivers}net/hinic,"
ENV _disabled_drivers="${_disabled_drivers}net/hns3,"
ENV _disabled_drivers="${_disabled_drivers}net/i40e,"
ENV _disabled_drivers="${_disabled_drivers}net/iavf,"
ENV _disabled_drivers="${_disabled_drivers}net/ifc,"
ENV _disabled_drivers="${_disabled_drivers}net/ifpga,"
ENV _disabled_drivers="${_disabled_drivers}net/igc,"
ENV _disabled_drivers="${_disabled_drivers}net/ioat,"
ENV _disabled_drivers="${_disabled_drivers}net/ionic,"
ENV _disabled_drivers="${_disabled_drivers}net/ipn3ke,"
ENV _disabled_drivers="${_disabled_drivers}net/ixgbe,"
ENV _disabled_drivers="${_disabled_drivers}net/kasumi,"
ENV _disabled_drivers="${_disabled_drivers}net/kni,"
ENV _disabled_drivers="${_disabled_drivers}net/liquidio,"
ENV _disabled_drivers="${_disabled_drivers}net/memif,"
ENV _disabled_drivers="${_disabled_drivers}net/mlx4,"
ENV _disabled_drivers="${_disabled_drivers}net/netvsc,"
ENV _disabled_drivers="${_disabled_drivers}net/nfp,"
ENV _disabled_drivers="${_disabled_drivers}net/ngbe,"
ENV _disabled_drivers="${_disabled_drivers}net/nitrox,"
ENV _disabled_drivers="${_disabled_drivers}net/ntb,"
ENV _disabled_drivers="${_disabled_drivers}net/null,"
ENV _disabled_drivers="${_disabled_drivers}net/octeontx,"
ENV _disabled_drivers="${_disabled_drivers}net/octeontx2,"
ENV _disabled_drivers="${_disabled_drivers}net/octeontx2_dma,"
ENV _disabled_drivers="${_disabled_drivers}net/octeontx2_ep,"
ENV _disabled_drivers="${_disabled_drivers}net/octeontx_ep,"
ENV _disabled_drivers="${_disabled_drivers}net/opdl,"
ENV _disabled_drivers="${_disabled_drivers}net/pcap,"
ENV _disabled_drivers="${_disabled_drivers}net/pfe,"
ENV _disabled_drivers="${_disabled_drivers}net/qede,"
ENV _disabled_drivers="${_disabled_drivers}net/sfc,"
ENV _disabled_drivers="${_disabled_drivers}net/sfc_efx,"
ENV _disabled_drivers="${_disabled_drivers}net/skeleton,"
ENV _disabled_drivers="${_disabled_drivers}net/snow3g,"
ENV _disabled_drivers="${_disabled_drivers}net/softnic,"
ENV _disabled_drivers="${_disabled_drivers}net/tap,"
ENV _disabled_drivers="${_disabled_drivers}net/thunderx,"
ENV _disabled_drivers="${_disabled_drivers}net/turbo_sw,"
ENV _disabled_drivers="${_disabled_drivers}net/txgbe,"
ENV _disabled_drivers="${_disabled_drivers}net/vdev,"
ENV _disabled_drivers="${_disabled_drivers}net/vdev_netvsc,"
ENV _disabled_drivers="${_disabled_drivers}net/vhost,"
ENV _disabled_drivers="${_disabled_drivers}net/virtio,"
ENV _disabled_drivers="${_disabled_drivers}net/vmbus,"
ENV _disabled_drivers="${_disabled_drivers}net/vmxnet3,"
ENV _disabled_drivers="${_disabled_drivers}net/zuc,"
ENV _disabled_drivers="${_disabled_drivers}raw/ioat,"
ENV _disabled_drivers="${_disabled_drivers}raw/ntb,"
ENV _disabled_drivers="${_disabled_drivers}raw/skeleton,"
ENV _disabled_drivers="${_disabled_drivers}regex/mlx5,"
ENV _disabled_drivers="${_disabled_drivers}vdpa/ifc,"
ENV _disabled_drivers="${_disabled_drivers}vdpa/mlx5,"

ENV _enabled_drivers=""
ENV _enabled_drivers="${_enabled_drivers}bus/auxiliary,"
ENV _enabled_drivers="${_enabled_drivers}bus/pci,"
ENV _enabled_drivers="${_enabled_drivers}common/mlx5,"
ENV _enabled_drivers="${_enabled_drivers}mempool/bucket,"
ENV _enabled_drivers="${_enabled_drivers}mempool/ring,"
ENV _enabled_drivers="${_enabled_drivers}mempool/stack,"
ENV _enabled_drivers="${_enabled_drivers}net/auxiliary,"
ENV _enabled_drivers="${_enabled_drivers}net/mlx5,"
ENV _enabled_drivers="${_enabled_drivers}net/ring,"

# Mandatory core dpdk libraries (as of 2024-08-19)
# cmdline
# eal
# ethdev
# hash
# kvargs
# log
# mbuf
# mempool
# meter
# net
# pci
# rcu
# ring
# stack
# telemetry

# Deliberately enabled libraries

### NONE ###

# Expressly disabled libraries

ENV _disabled_libs=""
ENV _disabled_libs="${_disabled_libs},acl"
ENV _disabled_libs="${_disabled_libs},argparse"
ENV _disabled_libs="${_disabled_libs},bbdev"
ENV _disabled_libs="${_disabled_libs},bitratestats"
ENV _disabled_libs="${_disabled_libs},bpf"
ENV _disabled_libs="${_disabled_libs},cfgfile"
ENV _disabled_libs="${_disabled_libs},compressdev"
ENV _disabled_libs="${_disabled_libs},cryptodev"
ENV _disabled_libs="${_disabled_libs},dispatcher"
ENV _disabled_libs="${_disabled_libs},distributor"
ENV _disabled_libs="${_disabled_libs},dmadev"
ENV _disabled_libs="${_disabled_libs},efd"
ENV _disabled_libs="${_disabled_libs},eventdev"
ENV _disabled_libs="${_disabled_libs},fib"
ENV _disabled_libs="${_disabled_libs},gpudev"
ENV _disabled_libs="${_disabled_libs},graph"
ENV _disabled_libs="${_disabled_libs},gro"
ENV _disabled_libs="${_disabled_libs},gso"
ENV _disabled_libs="${_disabled_libs},ip_frag"
ENV _disabled_libs="${_disabled_libs},ipsec"
ENV _disabled_libs="${_disabled_libs},jobstats"
ENV _disabled_libs="${_disabled_libs},latencystats"
ENV _disabled_libs="${_disabled_libs},lpm"
ENV _disabled_libs="${_disabled_libs},member"
ENV _disabled_libs="${_disabled_libs},metrics"
ENV _disabled_libs="${_disabled_libs},mldev"
ENV _disabled_libs="${_disabled_libs},node"
ENV _disabled_libs="${_disabled_libs},pcapng"
ENV _disabled_libs="${_disabled_libs},pdcp"
ENV _disabled_libs="${_disabled_libs},pdump"
ENV _disabled_libs="${_disabled_libs},pipeline"
ENV _disabled_libs="${_disabled_libs},port"
ENV _disabled_libs="${_disabled_libs},power"
ENV _disabled_libs="${_disabled_libs},ptr_compress"
ENV _disabled_libs="${_disabled_libs},rawdev"
ENV _disabled_libs="${_disabled_libs},regexdev"
ENV _disabled_libs="${_disabled_libs},reorder"
ENV _disabled_libs="${_disabled_libs},rib"
ENV _disabled_libs="${_disabled_libs},sched"
ENV _disabled_libs="${_disabled_libs},security"
ENV _disabled_libs="${_disabled_libs},table"
ENV _disabled_libs="${_disabled_libs},timer"
ENV _disabled_libs="${_disabled_libs},vhost"

RUN rm /usr/lib/libjansson.a
RUN rm /usr/lib/libelf.a

RUN cd /usr/src/dpdk; \
meson setup --reconfigure build \
  -Dauto_features=auto \
  -Db_colorout=always \
  -Db_coverage=false \
  -Db_lto=true \
  -Db_lundef=true \
  -Db_pch=true `#pch means pre-compiled headers which never seem to work out for me` \
  -Db_pgo=off `#turn this on later when we have a workload to test ` \
  -Db_pie=true `#not clear if I still need this` \
  -Db_sanitize=none `#see if we can't bully DPDK et al into building with -fsanitize=cfi` \
  -Dbackend=ninja \
  -Dbackend_max_links="$(nproc)" \
  -Ddefault_library=shared \
  -Denable_docs=false \
  -Denable_driver_sdk=false \
  -Dibverbs_link=static `#should help with lto for mlx5` \
  -Dmax_numa_nodes=4 `#adjust for target platform and UEFI setting for platform (zen4 lets you adjust numa nodes as f(ccx))` \
  -Dprefer_static=true \
  -Dprefix=/usr \
  -Dstrip=false \
  -Dtests=false `#TODO: adjust when CI is set up` \
  -Duse_hpet=false `#TODO: compile kernel with CONFIG_HPET_MMAP=Y` \
  -Ddisable_drivers="${_disabled_drivers}" \
  -Ddisable_libs="${_disabled_libs}" \
  -Denable_drivers="${_enabled_drivers}" \
  -Db_lto_mode="$([ "${IDEAL_LTO_TYPE}" = "thin" ] && echo thin || echo default)" \
  -Dc_args="${CFLAGS}" \
  -Dc_link_args="${LDFLAGS}" \
  -Dcpu_instruction_set="${CPU_ARCH}" \
  -Doptimization="${IDEAL_OPT_LEVEL}" \
; \
cd /usr/src/dpdk/build; \
nice --adjustment=15 ninja; \
nice --adjustment=15 ninja install; \
:;

RUN pacman --sync --clean --noconfirm --clean \
 && pacman --sync --noconfirm --refresh --sysupgrade \
 && pacman --sync --noconfirm --clean --clean \
 && pacman --sync --noconfirm jdk-openjdk


RUN <<'EOS'
pacman --sync --noconfirm \
  rustup \
;
rustup install stable-x86_64-unknown-linux-gnu
rustup install stable-x86_64-unknown-linux-musl
rustup install beta-x86_64-unknown-linux-gnu
rustup install beta-x86_64-unknown-linux-musl
EOS

RUN <<'EOS'
rustup install nightly-x86_64-unknown-linux-gnu
rustup install nightly-x86_64-unknown-linux-musl
EOS

#RUN pacman -S --noconfirm libc++ libc++abi
#RUN ln -s /usr/lib /usr/lib/x86_64-pc-linux-gnu
#
#RUN groupadd builder --gid 1000
#RUN useradd --create-home --gid builder --uid 1000 --shell /bin/bash --skel /dev/null builder
#
#USER builder:builder
#
#RUN <<'EOS'
#rustup install stable-x86_64-unknown-linux-gnu
#rustup install stable-x86_64-unknown-linux-musl
#rustup install beta-x86_64-unknown-linux-gnu
#rustup install beta-x86_64-unknown-linux-musl
#rustup install nightly-x86_64-unknown-linux-gnu
#rustup install nightly-x86_64-unknown-linux-musl
#EOS

CMD ["sleep", "infinity"]

