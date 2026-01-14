#!/usr/bin/env bash

set -euo pipefail

pushd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null

vulnix \
  --closure \
  --json \
  --show-description /tmp/dataplane-tar | \
jq --slurpfile acks <(yq . ./acks2.yml) --raw-output -f sbom2.jq
