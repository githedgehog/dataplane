FROM scratch AS dataplane
ARG ARTIFACT
COPY --link --chown=0:0 "${ARTIFACT}" /bin/dataplane
WORKDIR /
ENTRYPOINT ["/bin/dataplane"]
