#!/usr/bin/env bash
set -Eeuo pipefail

compose_file="${1:-lab/compose.yml}"
compose=(docker compose -f "$compose_file")
script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

token_from_cli() {
  local service=$1 name=$2 scope=$3
  "${compose[@]}" exec -T "$service" /usr/local/x-ui/x-ui setting \
    -tokenName "$name" -tokenScope "$scope" -getApiToken \
    | sed -n 's/^apiToken: //p' | tail -n 1
}

entry_token=$(token_from_cli entry lab-controller admin)
exit_token=$(token_from_cli exit lab-verifier admin)
test -n "$entry_token"
test -n "$exit_token"
printf '%s' "$entry_token" | "${compose[@]}" exec -T entry sh -eu -c 'umask 077; cat > /run/lab-api-token'
printf '%s' "$exit_token" | "${compose[@]}" exec -T exit sh -eu -c 'umask 077; cat > /run/lab-api-token'
unset entry_token exit_token

"${compose[@]}" exec -T entry sh -eu -c 'umask 077; cat > /run/container-configure-entry.sh' < "$script_dir/container-configure-entry.sh"
"${compose[@]}" exec -T exit sh -eu -c 'umask 077; cat > /run/container-verify-exit.sh' < "$script_dir/container-verify-exit.sh"
"${compose[@]}" exec -T entry sh -eu /run/container-configure-entry.sh
"${compose[@]}" exec -T exit sh -eu /run/container-verify-exit.sh
