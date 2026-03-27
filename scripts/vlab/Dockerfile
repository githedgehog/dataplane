ARG BASE_IMAGE=ubuntu:25.10
FROM $BASE_IMAGE

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
      iproute2 \
      jq \
      less \
      neovim \
      openssh-client \
      openssl \
      qemu-kvm \
      qemu-utils `#for qemu-img` \
      socat \
      sudo \
      wget \
      yq \
    ; \
:;

RUN \
    mkdir /vlab; \
:;

WORKDIR /vlab
VOLUME ["/vlab"]

RUN \
    wget -O /usr/bin/zot 'https://github.com/project-zot/zot/releases/download/v2.1.15/zot-linux-amd64'; \
    chmod +x /usr/bin/zot; \
    chown root:root /usr/bin/zot; \
:;

RUN \
    curl -fsSL 'https://i.hhdev.io/oras' | bash; \
:;
