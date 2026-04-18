#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright Open Network Fabric Authors

set -euxo pipefail

pushd "$(dirname "${BASH_SOURCE[0]}")/.."

declare MERMAID_VERSION
MERMAID_VERSION="$(jq --exit-status --raw-output .pins.mermaid.version ./npins/sources.json | sed 's/mermaid@//')"
declare -r MERMAID_VERSION
declare KATEX_VERSION
KATEX_VERSION="$(jq --exit-status --raw-output .pins.KaTeX.version ./npins/sources.json | sed 's/^v//')"
declare -r KATEX_VERSION

declare -rx MERMAID_JS_URL="https://cdn.jsdelivr.net/npm/mermaid@${MERMAID_VERSION}/dist/mermaid.min.js"
declare -rx KATEX_JS_URL="https://cdn.jsdelivr.net/npm/katex@${KATEX_VERSION}/dist/katex.min.js"
declare -rx KATEX_CSS_URL="https://cdn.jsdelivr.net/npm/katex@${KATEX_VERSION}/dist/katex.min.css"
declare -rx KATEX_AUTO_RENDER_URL="https://cdn.jsdelivr.net/npm/katex@${KATEX_VERSION}/dist/contrib/auto-render.min.js"

declare MERMAID_INTEGRITY
MERMAID_INTEGRITY="sha384-$(wget -O- "${MERMAID_JS_URL}" | openssl dgst -sha384 -binary | openssl base64 -A)"
declare -rx MERMAID_INTEGRITY

declare KATEX_JS_INTEGRITY
KATEX_JS_INTEGRITY="sha384-$(wget -O- "${KATEX_JS_URL}" | openssl dgst -sha384 -binary | openssl base64 -A)"
declare -rx KATEX_JS_INTEGRITY

declare KATEX_CSS_INTEGRITY
KATEX_CSS_INTEGRITY="sha384-$(wget -O- "${KATEX_CSS_URL}" | openssl dgst -sha384 -binary | openssl base64 -A)"
declare -rx KATEX_CSS_INTEGRITY

declare KATEX_AUTO_RENDER_INTEGRITY
KATEX_AUTO_RENDER_INTEGRITY="sha384-$(wget -O- "${KATEX_AUTO_RENDER_URL}" | openssl dgst -sha384 -binary | openssl base64 -A)"
declare -rx KATEX_AUTO_RENDER_INTEGRITY

declare -rx EDIT_WARNING="automatically generated file, do not edit!"

envsubst < ./scripts/templates/custom-header.template.html > ./scripts/doc/custom-header.html
