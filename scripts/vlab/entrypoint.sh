#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright Open Network Fabric Authors

set -euo pipefail

declare -r CERT_DIR=/etc/zot/certs
declare -r SECRETS_DIR=/var/lib/vlab
declare -r CREDS_FILE="${SECRETS_DIR}/creds.json"
declare -r CONFIG_FILE=/etc/zot/config.json
declare -r CERT_INI=/etc/zot/cert.ini
# Merged CA bundle: nixpkgs cacert's system CAs plus the freshly-minted zot
# CA. The image sets SSL_CERT_FILE to this path via config.Env so hhfab and
# every other TLS client inside the container trusts zot.loc without the
# Debian-style update-ca-certificates tool (which isn't in the nix closure).
declare -r CA_BUNDLE=/run/vlab/ca-bundle.pem
declare -r SYSTEM_CA_BUNDLE=/etc/ssl/certs/ca-bundle.crt
declare -ri RSA_BITS="${RSA_BIT_LENGTH:-4096}"
declare -ri CERT_DAYS="${CERT_DAYS:-30}"

init_ca_bundle() {
    # The image config sets SSL_CERT_FILE to ${CA_BUNDLE}, but that file does
    # not exist until gen_certs writes it.  The `check` and `provision`
    # one-shots do not run gen_certs, so seed the bundle with just the system
    # CAs here; gen_certs overwrites it with system CAs + zot CA in run mode.
    install -d -m 0755 "$(dirname "${CA_BUNDLE}")"
    cp -f "${SYSTEM_CA_BUNDLE}" "${CA_BUNDLE}"
}

gen_certs() {
    install -d -m 0700 "${CERT_DIR}"
    (
        umask 077

        openssl genrsa -out "${CERT_DIR}/ca.key" "${RSA_BITS}"

        openssl req \
            -x509 \
            -new \
            -nodes \
            -sha256 \
            -days "${CERT_DAYS}" \
            -key "${CERT_DIR}/ca.key" \
            -subj "/CN=loc" \
            -out "${CERT_DIR}/ca.crt"

        openssl req \
            -new \
            -nodes \
            -sha256 \
            -newkey "rsa:${RSA_BITS}" \
            -keyout "${CERT_DIR}/zot.key" \
            -out "${CERT_DIR}/zot.csr" \
            -config "${CERT_INI}"

        openssl x509 \
            -req \
            -in "${CERT_DIR}/zot.csr" \
            -CA "${CERT_DIR}/ca.crt" \
            -CAkey "${CERT_DIR}/ca.key" \
            -CAcreateserial \
            -subj "/C=US/ST=CO/L=Longmont/O=githedgehog/CN=zot.loc" \
            -extfile <(printf 'subjectAltName=DNS:zot,DNS:zot.loc,IP:192.168.19.1') \
            -out "${CERT_DIR}/zot.crt" \
            -days "${CERT_DAYS}" \
            -sha256
    )

    install -d -m 0755 "$(dirname "${CA_BUNDLE}")"
    cat "${SYSTEM_CA_BUNDLE}" "${CERT_DIR}/ca.crt" > "${CA_BUNDLE}"
}

validate_creds() {
    local f=$1
    [ -f "${f}" ] || return 1

    local username password
    username=$(jq -r '."ghcr.io".username // ""' "${f}" 2>/dev/null) || return 1
    password=$(jq -r '."ghcr.io".password // ""' "${f}" 2>/dev/null) || return 1
    if [ -z "${username}" ] || [ -z "${password}" ]; then
        return 1
    fi

    # --dump-header - writes the response header block to stdout;
    # --write-out '%{http_code}' appends the status code after the body (which
    # we discard).  The combined stdout is header-block + final status.
    local response status
    response=$(curl \
        --silent \
        --output /dev/null \
        --dump-header - \
        --write-out '%{http_code}' \
        --max-time 10 \
        --header "Authorization: Bearer ${password}" \
        'https://api.github.com/user' 2>/dev/null) || return 1

    status="${response##*$'\n'}"
    [ "${status}" = "200" ] || return 1

    # For classic PATs, X-OAuth-Scopes enumerates granted OAuth scopes, so we
    # can catch "authenticated but not scoped for packages" early.  For
    # fine-grained PATs the header is absent; we have no cheap way to probe
    # Packages:read from here, so we proceed and let zot surface any
    # permission error at sync time.
    local scopes
    scopes=$(printf '%s' "${response}" | awk -F': ' '
        BEGIN { IGNORECASE = 1 }
        /^X-OAuth-Scopes:/ {
            sub(/\r$/, "", $2)
            print $2
            exit
        }
    ')

    if [ -n "${scopes}" ]; then
        case ",${scopes// /}," in
            *,read:packages,*|*,write:packages,*|*,delete:packages,*)
                ;;
            *)
                printf 'token authenticates but is missing a packages scope (have: %s)\n' "${scopes}" >&2
                return 1
                ;;
        esac
    fi

    return 0
}

prompt_creds() {
    cat >&2 <<'HELP'

==============================================================================
vlab: ghcr.io credentials required
==============================================================================

Zot needs a GitHub token to proxy ghcr.io/githedgehog/* images.

Open this pre-filled URL to generate a classic personal access token with
exactly the read:packages scope (nothing more):

  https://github.com/settings/tokens/new?scopes=read:packages&description=vlab-zot

Click Generate, copy the token, paste it below. The token is stored in a
root-owned docker volume (vlab-secrets), not on your host filesystem in a
user-readable location.

Fine-grained PATs work too, but their scopes can't be URL-prefilled, so the
classic flow above is the one-click path.

==============================================================================

HELP

    local token response username
    while :; do
        IFS= read -rsp 'paste token: ' token < /dev/tty
        printf '\n' >&2

        if [ -z "${token}" ]; then
            printf 'empty input, try again\n\n' >&2
            continue
        fi

        if ! response=$(curl \
            --silent \
            --fail \
            --max-time 10 \
            --header "Authorization: Bearer ${token}" \
            'https://api.github.com/user' 2>/dev/null); then
            printf 'token rejected by api.github.com, try again\n\n' >&2
            continue
        fi

        username=$(jq -r '.login // ""' <<< "${response}")
        if [ -z "${username}" ]; then
            printf 'could not determine GitHub username, try again\n\n' >&2
            continue
        fi

        break
    done

    install -d -m 0700 "${SECRETS_DIR}"
    (
        umask 077
        jq \
            --null-input \
            --arg u "${username}" \
            --arg p "${token}" \
            '{ "ghcr.io": { username: $u, password: $p } }' \
            > "${CREDS_FILE}"
    )
    printf 'saved credentials for %s\n' "${username}" >&2
}

case "${1:-run}" in
    check)
        init_ca_bundle
        validate_creds "${CREDS_FILE}"
        ;;
    provision)
        init_ca_bundle
        if validate_creds "${CREDS_FILE}"; then
            printf 'existing credentials in %s are valid\n' "${CREDS_FILE}" >&2
            exit 0
        fi
        prompt_creds
        ;;
    run)
        gen_certs
        if ! validate_creds "${CREDS_FILE}"; then
            printf 'no valid credentials in %s\n' "${CREDS_FILE}" >&2
            printf 'run the provisioning step first\n' >&2
            exit 1
        fi
        exec zot serve "${CONFIG_FILE}"
        ;;
    *)
        printf 'unknown mode: %s (expected check, provision, or run)\n' "$1" >&2
        exit 1
        ;;
esac
