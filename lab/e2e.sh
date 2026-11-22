#!/usr/bin/env bash
set -Eeuo pipefail

compose_file="${1:-lab/compose.yml}"
compose=(docker compose -f "$compose_file")
script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

token=$(
  "${compose[@]}" exec -T entry /usr/local/x-ui/x-ui setting \
    -tokenName lab-e2e -tokenScope admin -getApiToken \
    | sed -n 's/^apiToken: //p' | tail -n 1
)
test -n "$token"
printf '%s' "$token" | "${compose[@]}" exec -T entry sh -eu -c 'umask 077; cat > /run/lab-api-token'
unset token

"${compose[@]}" exec -T entry sh -eu -c 'umask 077; cat > /run/container-e2e.sh' < "$script_dir/container-e2e.sh"
"${compose[@]}" exec -T entry sh -eu /run/container-e2e.sh
