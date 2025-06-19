ARG BASE
FROM $BASE AS dataplane
ARG ARTIFACT
ARG ARTIFACT_CLI
COPY --link --chown=0:0 "${ARTIFACT}" /dataplane
COPY --link --chown=0:0 "${ARTIFACT_CLI}" /dataplane-cli
WORKDIR /
ENTRYPOINT ["/dataplane"]
