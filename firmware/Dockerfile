FROM debian:bookworm-slim AS firmware

SHELL ["/bin/bash", "-euxo", "pipefail", "-c"]

RUN apt update \
 && apt install --yes --no-install-recommends \
    automake \
    build-essential \
    ca-certificates \
    git \
    iproute2 \
    libibmad-dev \
    libibumad-dev \
    libssl-dev \
    python3 \
    sudo \
    wget \
    zlib1g-dev \
;

ENV MSTFLINT_VERSION=4.29.0
ENV MSTFLINT_REVISION=1

RUN mkdir -p /usr/src/mstflint \
 && cd /usr/src \
 && wget -O- "https://github.com/Mellanox/mstflint/releases/download/v${MSTFLINT_VERSION}-${MSTFLINT_REVISION}/mstflint-${MSTFLINT_VERSION}-${MSTFLINT_REVISION}.tar.gz" \
  | tar -xzf - -C /usr/src/mstflint --strip-components=1

RUN cd /usr/src/mstflint \
 && ./configure \
 && make -j$(nproc) \
 && make install

RUN wget -O /usr/bin/mlxup https://www.mellanox.com/downloads/firmware/mlxup/4.29.0/SFX/linux_x64/mlxup  \
 && chmod +x /usr/bin/mlxup

COPY ./assets/bin/configure-nic.sh /usr/bin/configure-nic.sh

CMD ["/usr/bin/configure-nic.sh"]

RUN apt-get install -y --no-install-recommends \
    pciutils
