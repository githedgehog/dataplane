#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright Open Network Fabric Authors

set -euxo pipefail

# Config params

declare -ri RSA_BIT_LENGTH="${RSA_BIT_LENGTH:-4096}"
declare -ri CERT_DAYS="${CERT_DAYS:-30}"

# end config

declare SOURCE_DIR
SOURCE_DIR="$(dirname "${BASH_SOURCE}")"
declare -r SOURCE_DIR

declare -r CERTS_DIR="${SOURCE_DIR}/root/etc/zot"

mkdir -p "${CERTS_DIR}"

pushd "${SOURCE_DIR}"

chmod go=rw "${SOURCE_DIR}/root//etc/zot/"{*.key,*.crt,*.csr}

openssl genrsa \
  -out "${CERTS_DIR}/ca.key" \
  "${RSA_BIT_LENGTH}"

chmod u=rw,go= "${CERTS_DIR}/ca.key"

openssl req \
  -x509 \
  -new \
  -nodes \
  -sha256 \
  -days "${CERT_DAYS}" \
  -key "${CERTS_DIR}/ca.key" \
  -subj "/CN=loc" \
  -out "${CERTS_DIR}/ca.crt"

openssl req \
   -new \
   -nodes \
   -sha256 \
   -newkey "rsa:${RSA_BIT_LENGTH}" \
   -keyout "${CERTS_DIR}/zot.key" \
   -out "${CERTS_DIR}/zot.csr" \
   -config "${CERTS_DIR}/cert.ini"

openssl x509 \
  -req \
  -in "${CERTS_DIR}/zot.csr" \
  -CA "${CERTS_DIR}/ca.crt" \
  -CAkey "${CERTS_DIR}/ca.key" \
  -CAcreateserial \
  -subj "/C=CN/ST=GD/L=SZ/O=githedgehog/CN=zot.loc" \
  -extfile <(printf "subjectAltName=DNS:zot,DNS:zot.loc,IP:192.168.19.1") \
  -out "${CERTS_DIR}/zot.crt" \
  -days "${CERT_DAYS}" \
  -sha256


docker stop vlab || true
docker network rm zot || true
docker rm vlab || true

docker network create --attachable --driver bridge --ipv4 --ip-range 192.168.19.0/31 --subnet 192.168.19.0/31 zot

declare -r base="${1:-"ubuntu:25.10"}"

docker pull "${base}"

docker build \
    --build-arg BASE_IMAGE="${base}" \
    --tag vlab \
    "${SOURCE_DIR}"

docker run \
  --network zot \
  --privileged \
  --mount type=bind,source="${CERTS_DIR}",target=/etc/zot/,readonly \
  --mount type=bind,source=/var/run/docker.sock,target=/var/run/docker.sock \
  --mount type=volume,source=vlab,target=/vlab \
  --mount type=volume,source=zot,target=/zot \
  --env DOCKER_HOST="unix:///var/run/docker.sock" \
  --volume ~/.docker:/root/.docker:ro \
  --name vlab \
  --add-host zot:192.168.19.1 \
  --add-host zot.loc:192.168.19.1 \
  --rm \
  --interactive \
  --tty \
  --detach \
  vlab \
  zot serve /etc/zot/config.json

### part 2 (in container)

docker exec vlab cp /etc/zot/ca.crt /usr/local/share/ca-certificates/
docker exec vlab update-ca-certificates
docker exec vlab /bin/bash -c "curl -fsSL 'https://i.hhdev.io/hhfab' | USE_SUDO=false INSTALL_DIR=. VERSION=master bash;"
docker exec vlab /vlab/hhfab init --dev --registry-repo 192.168.19.1:30000 --gateway --import-host-upstream --force
docker exec vlab mv fab.yaml fab.orig.yaml
docker exec vlab bash -euxo pipefail -c "
  yq . fab.orig.yaml \
    | jq --slurp '
      . as \$input |
      \$input |
      ([\$input[0] | setpath([\"spec\", \"config\", \"registry\", \"upstream\", \"noTLSVerify\"]; true)] +  \$input[1:])
    ' \
    | yq -y '.[]' \
    | tee fab.yaml
"
docker exec vlab /vlab/hhfab vlab gen
docker exec vlab /vlab/hhfab vlab up -v --controls-restricted=false -m=manual --recreate
