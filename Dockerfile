# SPDX-License-Identifier: Apache-2.0
# Copyright Open Network Fabric Authors

# WARNING: This Dockerfile produces NON-STERILE images for local development only.
# These images must NEVER be shipped or pushed to any shared registry.
# Use `just build-container` for production-quality (nix-built) images.

FROM debug-tools:dev

ARG PROFILE=debug
LABEL sterile=false
COPY --link --chown=0:0 ./target/${PROFILE}/dataplane /bin/dataplane
COPY --link --chown=0:0 ./target/${PROFILE}/dataplane-init /bin/dataplane-init
COPY --link --chown=0:0 ./target/${PROFILE}/cli /bin/cli

WORKDIR /
# this is a privileged container, we really do want to run as root
USER root # nosem
ENTRYPOINT ["/bin/dataplane"]
