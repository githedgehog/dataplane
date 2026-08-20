# SPDX-License-Identifier: Apache-2.0
# Copyright Open Network Fabric Authors

# Runs Loki, Prometheus, Pyroscope and Grafana as one unit.
#
# Four processes in one container is not the usual advice, but the alternative here is four
# containers whose only relationship is that they are useless apart. Grafana talks to the other
# three over loopback, everything shares one volume, and the whole stack starts and stops as the
# single thing an operator actually thinks about.
#
# No supervisor: if any of the four dies the container exits, and the restart policy takes it from
# there. A partially-running telemetry stack is worse than a restarting one, because it looks like
# an absence of data rather than an absence of collector.

declare -r DATA_DIR="${TELEMETRY_DATA_DIR:-/telemetry}"

mkdir -p \
    "${DATA_DIR}/loki/chunks" \
    "${DATA_DIR}/loki/rules" \
    "${DATA_DIR}/prometheus" \
    "${DATA_DIR}/pyroscope" \
    "${DATA_DIR}/grafana"

declare -a pids=()

shutdown() {
    # SIGTERM every child, then let `wait` below reap them. Killing an already-dead pid is not an
    # error worth failing the shutdown over.
    for pid in "${pids[@]}"; do
        kill "${pid}" 2>/dev/null || true
    done
}
trap shutdown TERM INT

loki -config.file=/etc/loki/config.yaml &
pids+=("$!")

prometheus \
    --config.file=/etc/prometheus/prometheus.yml \
    --storage.tsdb.path="${DATA_DIR}/prometheus" \
    --web.listen-address=:9090 \
    --web.enable-remote-write-receiver \
    --web.enable-lifecycle &
pids+=("$!")

pyroscope -config.file=/etc/pyroscope/config.yaml &
pids+=("$!")

grafana server \
    --config=/etc/grafana/grafana.ini \
    --homepath="${GF_PATHS_HOME}" &
pids+=("$!")

# Return as soon as any one of them exits, whatever its status.
wait -n
declare -r first_exit="$?"
shutdown
wait || true
exit "${first_exit}"
