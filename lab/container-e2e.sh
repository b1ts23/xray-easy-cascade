#!/bin/sh
set -eu
umask 077

cleanup() {
  status=$?
  if [ -n "${client_pid:-}" ]; then
    kill "$client_pid" 2>/dev/null || true
    wait "$client_pid" 2>/dev/null || true
  fi
  rm -f /run/lab-api-token /run/lab-api-header /run/e2e-inbounds.json \
    /run/e2e-client.json /run/e2e-client.log /run/container-e2e.sh
  exit "$status"
}
trap cleanup EXIT INT TERM

token=$(cat /run/lab-api-token)
printf 'Authorization: Bearer %s\n' "$token" > /run/lab-api-header
unset token

curl --fail-with-body -sS -H @/run/lab-api-header \
  http://127.0.0.1:2053/entry/panel/api/inbounds/list > /run/e2e-inbounds.json
jq -e '.success == true' /run/e2e-inbounds.json >/dev/null

settings=$(jq -r '.obj[] | select(.remark == "lab-client-entry") | .settings' /run/e2e-inbounds.json)
stream=$(jq -r '.obj[] | select(.remark == "lab-client-entry") | .streamSettings' /run/e2e-inbounds.json)
client_id=$(printf '%s' "$settings" | jq -r '.clients[0].id')
public_key=$(printf '%s' "$stream" | jq -r '.realitySettings.settings.publicKey')
server_name=$(printf '%s' "$stream" | jq -r '.realitySettings.serverNames[0]')
short_id=$(printf '%s' "$stream" | jq -r '.realitySettings.shortIds[0]')

jq -n \
  --arg id "$client_id" \
  --arg public "$public_key" \
  --arg sni "$server_name" \
  --arg sid "$short_id" \
  '{
    log:{loglevel:"warning"},
    inbounds:[{tag:"e2e-socks",listen:"127.0.0.1",port:10808,protocol:"socks",settings:{udp:false}}],
    outbounds:[{
      tag:"entry",
      protocol:"vless",
      settings:{vnext:[{address:"172.29.10.10",port:10443,users:[{id:$id,encryption:"none",flow:"xtls-rprx-vision"}]}]},
      streamSettings:{network:"tcp",security:"reality",realitySettings:{serverName:$sni,fingerprint:"chrome",publicKey:$public,shortId:$sid,spiderX:"/"}}
    }]
  }' > /run/e2e-client.json

/usr/local/x-ui/bin/xray-linux-amd64 run -test -config /run/e2e-client.json >/dev/null
/usr/local/x-ui/bin/xray-linux-amd64 run -config /run/e2e-client.json > /run/e2e-client.log 2>&1 &
client_pid=$!

ready=false
for _ in 1 2 3 4 5 6 7 8 9 10; do
  if ss -ltn | grep -q '127.0.0.1:10808'; then
    ready=true
    break
  fi
  sleep 1
done
test "$ready" = true

http_code=$(curl --fail -sS --max-time 20 --socks5-hostname 127.0.0.1:10808 \
  -o /dev/null -w '%{http_code}' https://www.cloudflare.com/cdn-cgi/trace)
test "$http_code" = 200
echo "3XUI_CASCADE_E2E_READY http=$http_code"
