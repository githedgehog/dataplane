#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright Open Network Fabric Authors

set -euxo pipefail

declare -r MERMAID_VERSION="11.12.0"
declare -r KATEX_VERSION="0.16.25"

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

envsubst < ./templates/custom-header.template.html > ./doc/custom-header.html
