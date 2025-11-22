ARG BASE
FROM $BASE AS dataplane
ARG ARTIFACT
ARG ARTIFACT_CLI
ARG ARTIFACT_INIT
COPY --link --chown=0:0 "${ARTIFACT}" /bin/dataplane
COPY --link --chown=0:0 "${ARTIFACT_INIT}" /bin/dataplane-init
COPY --link --chown=0:0 "${ARTIFACT_CLI}" /bin/dataplane-cli
WORKDIR /
ENTRYPOINT ["/bin/dataplane-init"]
