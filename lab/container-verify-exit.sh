#!/bin/sh
set -eu
umask 077
token=$(cat /run/lab-api-token)
printf 'Authorization: Bearer %s\n' "$token" > /run/lab-api-header
unset token
curl --fail-with-body -k -sS -H @/run/lab-api-header https://127.0.0.1:2053/exit/panel/api/server/getConfigJson > /run/runtime.json
jq -e '.success == true and (.obj.inbounds | any(.tag == "in-cascade-exit"))' /run/runtime.json >/dev/null
echo 3XUI_EXIT_CONFIG_READY
rm -f /run/lab-api-token /run/lab-api-header /run/container-verify-exit.sh /run/runtime.json
