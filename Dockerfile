ARG BASE
FROM $BASE AS dataplane
ARG ARTIFACT
COPY --link --chown=0:0 "${ARTIFACT}" /dataplane
WORKDIR /
ENTRYPOINT ["/dataplane"]
