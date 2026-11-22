#!/usr/bin/env bash
set -Eeuo pipefail

compose_file="${1:-lab/compose.yml}"
compose=(docker compose -f "$compose_file")

token_from_cli() {
  local service=$1
  local name=$2
  local scope=$3
  "${compose[@]}" exec -T "$service" /usr/local/x-ui/x-ui setting \
    -tokenName "$name" -tokenScope "$scope" -getApiToken \
    | sed -n 's/^apiToken: //p' | tail -n 1
}

entry_token=$(token_from_cli entry lab-controller admin)
exit_token=$(token_from_cli exit lab-master node-sync)
exit_pin=$("${compose[@]}" exec -T exit sh -c \
  "openssl x509 -in /etc/x-ui/panel.crt -outform DER | sha256sum | awk '{print \$1}'")
if [[ -z "$entry_token" || -z "$exit_token" || ! "$exit_pin" =~ ^[0-9a-f]{64}$ ]]; then
  echo "failed to create scoped 3x-ui API tokens" >&2
  exit 1
fi

printf '%s' "$entry_token" | "${compose[@]}" exec -T entry sh -eu -c \
  'umask 077; cat > /run/lab-entry-token'
printf '%s' "$exit_token" | "${compose[@]}" exec -T entry sh -eu -c \
  'umask 077; cat > /run/lab-exit-token'
printf '%s' "$exit_pin" | "${compose[@]}" exec -T entry sh -eu -c \
  'umask 077; cat > /run/lab-exit-pin'
unset entry_token exit_token exit_pin

"${compose[@]}" exec -T entry sh -eu -c '
  umask 077
  entry_token=$(cat /run/lab-entry-token)
  printf "header = \"Authorization: Bearer %s\"\n" "$entry_token" > /run/lab-curl.conf
  printf "header = \"Content-Type: application/json\"\n" >> /run/lab-curl.conf
  unset entry_token

  jq -n --rawfile token /run/lab-exit-token --rawfile pin /run/lab-exit-pin '\''{
    name: "lab-exit",
    remark: "isolated container lab",
    scheme: "https",
    address: "172.29.10.11",
    port: 2053,
    basePath: "/exit/",
    apiToken: ($token | rtrimstr("\n")),
    tlsVerifyMode: "pin",
    pinnedCertSha256: ($pin | rtrimstr("\n")),
    clearApiToken: false,
    enable: true,
    allowPrivateAddress: true
  }'\'' > /run/lab-node.json

  base=http://127.0.0.1:2053/entry/panel/api/nodes
  curl --fail-with-body -sS --config /run/lab-curl.conf \
    -X POST --data @/run/lab-node.json "$base/test" > /run/lab-node-test.json
  jq -e '\''.success == true'\'' /run/lab-node-test.json >/dev/null

  curl --fail-with-body -sS --config /run/lab-curl.conf \
    "$base/list" > /run/lab-node-list.json
  node_id=$(jq -r '\''.obj[]? | select(.name == "lab-exit") | .id'\'' /run/lab-node-list.json | head -n 1)
  if [ -n "$node_id" ]; then
    endpoint="$base/update/$node_id"
  else
    endpoint="$base/add"
  fi
  curl --fail-with-body -sS --config /run/lab-curl.conf \
    -X POST --data @/run/lab-node.json "$endpoint" > /run/lab-node-save.json
  jq -e '\''.success == true'\'' /run/lab-node-save.json >/dev/null
  node_id=$(jq -r '\''.obj.id // empty'\'' /run/lab-node-save.json)
  if [ -z "$node_id" ]; then
    curl --fail-with-body -sS --config /run/lab-curl.conf \
      "$base/list" > /run/lab-node-list.json
    node_id=$(jq -r '\''.obj[]? | select(.name == "lab-exit") | .id'\'' /run/lab-node-list.json | head -n 1)
  fi
  test -n "$node_id"

  curl --fail-with-body -sS --config /run/lab-curl.conf \
    -X POST "$base/probe/$node_id" > /run/lab-node-probe.json
  jq -e '\''.success == true'\'' /run/lab-node-probe.json >/dev/null
  status=$(jq -r '\''.obj.status // "unknown"'\'' /run/lab-node-probe.json)
  printf "3XUI_NODE_READY id=%s status=%s\n" "$node_id" "$status"

  rm -f /run/lab-entry-token /run/lab-exit-token /run/lab-exit-pin /run/lab-curl.conf \
    /run/lab-node.json /run/lab-node-test.json /run/lab-node-list.json \
    /run/lab-node-save.json /run/lab-node-probe.json
'
