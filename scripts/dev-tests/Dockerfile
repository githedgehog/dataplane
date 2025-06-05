# SPDX-License-Identifier: Apache-2.0
# Copyright Open Network Fabric Authors

ARG _USER
ARG _GROUP=$_USER
ARG UID
ARG GID
ARG BASE
ARG VERSION

FROM archlinux:$VERSION AS archlinux

SHELL ["/bin/bash", "-euxlo", "pipefail", "-c"]

RUN pacman -Syu --noconfirm \
 && pacman -S --noconfirm \
      binutils `# for ld` \
      ca-certificates `# for rustup` \
      curl `# for rustup` \
      docker `# for launching tests` \
      gcc `# needed for linking` \
      libcap `# needed for test-runner.sh` \
      sudo `# needed for test-runner.sh`

ARG UID
ARG GID
ARG _USER
ARG _GROUP
RUN groupadd --gid $GID $_GROUP
RUN useradd --uid $UID -g $_GROUP $_USER

FROM ubuntu:$VERSION AS ubuntu

SHELL ["/bin/bash", "-euxlo", "pipefail", "-c"]

RUN apt update \
 && apt upgrade --yes \
 && apt dist-upgrade --yes \
 && apt install --yes --no-install-recommends \
      binutils-common `# for ld` \
      ca-certificates `# for rustup` \
      curl `# for rustup` \
      docker.io `# for launching tests` \
      gcc `# needed for linking` \
      libc6-dev `# needed for linking` \
      libcap2-bin `# needed for test-runner.sh` \
      sudo `# needed for test-runner.sh` \
    ;

ARG UID
ARG GID
ARG _USER
ARG _GROUP
RUN userdel ubuntu || true
RUN groupadd --gid $GID $_GROUP
RUN useradd --uid $UID -g $_GROUP $_USER

FROM debian:$VERSION AS debian

SHELL ["/bin/bash", "-euxlo", "pipefail", "-c"]

RUN apt update \
 && apt upgrade --yes \
 && apt dist-upgrade --yes \
 && apt install --yes --no-install-recommends \
      binutils-common `# for ld` \
      ca-certificates `# for rustup` \
      curl `# for rustup` \
      docker.io `# for launching tests` \
      gcc `# needed for linking` \
      libc6-dev `# needed for linking` \
      libcap2-bin `# needed for test-runner.sh` \
      sudo `# needed for test-runner.sh` \
    ;

ARG UID
ARG GID
ARG _USER
ARG _GROUP
RUN groupadd --gid $GID $_GROUP
RUN useradd --uid $UID -g $_GROUP $_USER

FROM fedora:$VERSION AS fedora

SHELL ["/bin/bash", "-euxlo", "pipefail", "-c"]

RUN dnf update -y \
 && dnf upgrade --refresh -y

RUN dnf install -y \
      binutils `# for ld` \
      curl `# for rustup` \
      docker `# for launching tests` \
      gcc `# needed for linking` \
      libcap `# needed for test-runner.sh` \
      sudo `# needed for test-runner.sh`

ARG UID
ARG GID
ARG _USER
ARG _GROUP
RUN groupadd --gid $GID $_GROUP
RUN useradd --uid $UID -g $_GROUP $_USER

FROM alpine:$VERSION AS alpine

RUN apk update \
 && apk upgrade --no-cache \
 && apk add --no-cache \
     bash `# needed for test-runer.sh` \
     binutils `# for ld` \
     curl `# for rustup` \
     docker `# for launching tests` \
     gcc `# needed for linking` \
     libcap `# needed for test-runner.sh` \
     musl-dev `# needed for linking` \
     sudo `# needed for test-runner.sh`

ARG UID
ARG GID
ARG _USER
ARG _GROUP
RUN addgroup -g $GID $_GROUP \
 && adduser -D -u $UID -G $_GROUP $_USER


FROM $BASE AS user

RUN mkdir --parent /home/$_USER \
 && chown -R $_USER:$_GROUP /home/$_USER

RUN echo "ALL ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/dangerous \
 && chmod 0444 /etc/sudoers.d/dangerous \
 && chmod 4755 /usr/bin/sudo \
 && mkdir -p /etc/pam.d \
 && chmod 555 /etc/pam.d \
 && echo auth requisite pam_permit.so > /etc/pam.d/sudo \
 && echo account requisite pam_permit.so >> /etc/pam.d/sudo \
 && echo session requisite pam_permit.so >> /etc/pam.d/sudo \
 && chmod 444 /etc/pam.d/*

USER $_USER

FROM user AS rustup

# install vanilla rust, everything default
RUN curl --proto '=https' --tlsv1.3 -sSf 'https://sh.rustup.rs' | sh -s -- -y
RUN echo 'source $HOME/.cargo/env' >> $HOME/.bash_profile
RUN echo 'source $HOME/.cargo/env' >> $HOME/.bashrc

RUN source $HOME/.cargo/env \
 && cargo install cargo-binstall \
 && cargo binstall --no-confirm just \
 && cargo binstall --no-confirm cargo-bolero \
 && cargo binstall --no-confirm cargo-nextest

ENTRYPOINT ["/bin/bash", "-l", "-c"]
