ARG BASE
FROM $BASE AS dataplane
ARG ARTIFACT
ARG ARTIFACT_INIT
ARG ARTIFACT_CLI
COPY ./target/x86_64-unknown-linux-gnu/debug/dataplane-init /bin/dataplane-init
COPY --link --chown=0:0 "${ARTIFACT}" /bin/dataplane
COPY --link --chown=0:0 "${ARTIFACT_CLI}" /bin/dataplane-cli
WORKDIR /
ENTRYPOINT ["/bin/dataplane-init"]
