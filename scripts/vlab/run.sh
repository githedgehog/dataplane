#!/usr/bin/env bash

set -euxo pipefail

# Config params

declare -ri RSA_BIT_LENGTH="${RSA_BIT_LENGTH:-4096}"
declare -ri CERT_DAYS="${CERT_DAYS:-30}"
declare -rx DOCKER_HOST="${DOCKER_HOST:-unix:///var/run/docker.sock}"

# end config

declare SOURCE_DIR
SOURCE_DIR="$(dirname "${BASH_SOURCE}")"
declare -r SOURCE_DIR

declare -r CERTS_DIR="${SOURCE_DIR}/root/etc/zot/cert"

mkdir -p "${CERTS_DIR}"

pushd "${SOURCE_DIR}"

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
  -extfile <(printf "subjectAltName=DNS:zot,DNS:zot.loc,IP:172.17.0.1") \
  -out "${CERTS_DIR}/zot.crt" \
  -days "${CERT_DAYS}" \
  -sha256

chmod go-rwx root/etc/zot/{*.key,*.crt,*.csr}

docker build -t vlab .

docker run \
  --network host \
  --privileged \
  --mount type=bind,source="${CERTS_DIR}",target=/etc/zot/,readonly \
  --mount type=bind,"${DOCKER_HOST}:/var/run/docker.sock" \
  --mount type=volume,source=vlab,target=/vlab \
  --env DOCKER_HOST="unix:///var/run/docker.sock" \
  --volume ~/.docker:/root/.docker:ro \
  --mount source=zot,target=/zot \
  --name vlab \
  --add-host zot:172.17.0.1 \
  --add-host zot.loc:172.17.0.1 \
  --rm \
  --interactive \
  --tty \
  vlab

### part 2 (in container)

cp /etc/zot/zot-ca.crt /usr/local/share/ca-certificates/
update-ca-certificates

/vlab/hhfab init --dev --registry-repo 172.17.0.1:30000 --gateway --import-host-upstream --force
/vlab/hhfab vlab gen
/vlab/hhfab vlab up -v --controls-restricted=false -m=manual -f

# /vlab/hhfab init --dev --gateway --import-host-upstream --force
# /vlab/hhfab vlab up -v --controls-restricted=false -m=manual -f
