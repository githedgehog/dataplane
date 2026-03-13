FROM ubuntu:25.10

SHELL ["/bin/bash", "-euo", "pipefail", "-c"]

RUN \
    apt update; \
    apt upgrade --yes; \
:;

RUN \
    apt update; \
    apt upgrade --yes; \
    apt install --yes --no-install-recommends \
      ca-certificates \
      curl \
      docker.io \
      git \
      golang `#just bump recipe depends on golang compiler` \
      just `#for invoking logic from the fabricator justfile` \
      less \
      neovim \
      openssh-client \
      openssl \
      qemu-kvm \
      qemu-utils `#for qemu-img` \
      socat \
      sudo \
      wget \
    ; \
:;

RUN \
    mkdir /vlab; \
:;

WORKDIR /vlab
VOLUME ["/vlab"]

RUN \
    wget -O /usr/bin/zot 'https://github.com/project-zot/zot/releases/download/v2.1.14/zot-linux-amd64'; \
    chmod +x /usr/bin/zot; \
    chown root:root /usr/bin/zot; \
:;

RUN \
    curl -fsSL 'https://i.hhdev.io/oras' | bash; \
:;

RUN \
    cd /vlab; \
    curl -fsSL 'https://i.hhdev.io/hhfab' | USE_SUDO=false INSTALL_DIR=. VERSION=master bash; \
:;
