ARG DPDK_SYS_COMMIT
FROM ghcr.io/githedgehog/dpdk-sys/libc-env:${DPDK_SYS_COMMIT}.rust-stable as dataplane
ARG ARTIFACT
COPY --link --chown=0:0 "${ARTIFACT}" /dataplane
WORKDIR /
ENTRYPOINT ["/dataplane"]
