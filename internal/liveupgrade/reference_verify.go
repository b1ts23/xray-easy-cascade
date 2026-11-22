// SPDX-License-Identifier: GPL-3.0-only

package liveupgrade

import (
	"errors"
	"fmt"
	"net/netip"
)

type ReferenceVerifyOptions struct {
	InboundTag       string
	ClientPort       int
	SubscriptionPort int
	EntryAddress     string
	ExpectedExitIPv4 string
	ExpectedExitIPv6 string
}

// ReferenceVerifyScript verifies the existing reference cascade without
// changing its persistent configuration. Its API token and synthetic client
// files are ephemeral and removed by the cleanup trap.
func ReferenceVerifyScript(panel Options, verify ReferenceVerifyOptions) (string, error) {
	if err := panel.validate(); err != nil {
		return "", err
	}
	if !safeTag.MatchString(verify.InboundTag) {
		return "", errors.New("reference inbound tag is unsafe")
	}
	if verify.ClientPort < 1 || verify.ClientPort > 65535 || verify.SubscriptionPort < 1 || verify.SubscriptionPort > 65535 {
		return "", errors.New("reference client and subscription ports must be valid")
	}
	exitIP, err := netip.ParseAddr(verify.ExpectedExitIPv4)
	if err != nil || !exitIP.Is4() || !exitIP.IsGlobalUnicast() {
		return "", errors.New("expected exit must be a global IPv4 address")
	}
	entryIP, err := netip.ParseAddr(verify.EntryAddress)
	if err != nil {
		return "", errors.New("reference entry must be an IP address")
	}
	exitIPv6, err := netip.ParseAddr(verify.ExpectedExitIPv6)
	if err != nil || !exitIPv6.Is6() || !exitIPv6.IsGlobalUnicast() {
		return "", errors.New("expected exit IPv6 must be a global IPv6 address")
	}
	return fmt.Sprintf(`set -eu
umask 077
stage=init
work=$(mktemp -d /run/xray-cascade-reference-verify-XXXXXX)
cd /usr/local/x-ui
token_name=xray-cascade-reference-verify-$(openssl rand -hex 8)
token=$(./x-ui setting -tokenName "$token_name" -tokenScope admin -getApiToken | sed -n 's/^apiToken: //p' | tail -n 1)
test -n "$token"
printf 'Authorization: Bearer %%s\n' "$token" > "$work/header"
unset token
api=%s://127.0.0.1:%d%sapi
client_pid=
delete_token() {
  test -s "$work/header" || return 0
  curl --fail-with-body -sS %s -H @"$work/header" "$api/setting/apiTokens" > "$work/tokens.json"
  token_id=$(jq -r --arg name "$token_name" '.obj[]?|select(.name==$name)|.id' "$work/tokens.json" | head -n 1)
  test -n "$token_id"
  printf '{"expectedScope":"admin"}' > "$work/delete-request.json"
  curl --fail-with-body -sS %s -H @"$work/header" -H 'Content-Type: application/json' -X POST --data @"$work/delete-request.json" "$api/setting/apiTokens/delete/$token_id" > "$work/delete.json"
  jq -e '.success==true' "$work/delete.json" >/dev/null
  rm -f "$work/header"
}
cleanup() {
  status=$?
  if [ -n "$client_pid" ]; then kill "$client_pid" 2>/dev/null || true; wait "$client_pid" 2>/dev/null || true; fi
  delete_token >/dev/null 2>&1 || true
  rm -rf "$work"
  if [ "$status" -ne 0 ]; then echo "3XUI_REFERENCE_VERIFY_FAILED stage=$stage status=$status" >&2; fi
  exit "$status"
}
trap cleanup EXIT INT TERM

stage=read-runtime
curl --fail-with-body -sS %s -H @"$work/header" "$api/server/getConfigJson" > "$work/runtime.json"
jq -e --arg tag %q --argjson port %d '
  .success==true
  and (.obj.inbounds|any(.tag==$tag and .port==$port and .protocol=="vless" and .streamSettings.security=="reality"))
' "$work/runtime.json" >/dev/null
curl --fail-with-body -sS %s -H @"$work/header" "$api/inbounds/list" > "$work/inbounds.json"
settings=$(jq -r --argjson port %d '.obj[]|select(.port==$port)|.settings' "$work/inbounds.json")
stream=$(jq -r --argjson port %d '.obj[]|select(.port==$port)|.streamSettings' "$work/inbounds.json")
client_id=$(printf '%%s' "$settings" | jq -r '.clients[0].id')
flow=$(printf '%%s' "$settings" | jq -r '.clients[0].flow')
public_key=$(printf '%%s' "$stream" | jq -r '.realitySettings.settings.publicKey')
server_name=$(printf '%%s' "$stream" | jq -r '.realitySettings.serverNames[0]')
short_id=$(printf '%%s' "$stream" | jq -r '.realitySettings.shortIds[0]')
test -n "$client_id"; test "$client_id" != null
test -n "$public_key"; test "$public_key" != null
test -n "$server_name"; test "$server_name" != null
test -n "$short_id"; test "$short_id" != null
stage=build-client
jq -n --arg id "$client_id" --arg flow "$flow" --arg public "$public_key" --arg sni "$server_name" --arg sid "$short_id" --arg address %q --argjson port %d '{log:{loglevel:"warning"},inbounds:[{tag:"reference-socks",listen:"127.0.0.1",port:10889,protocol:"socks",settings:{udp:false}}],outbounds:[{tag:"entry",protocol:"vless",settings:{vnext:[{address:$address,port:$port,users:[{id:$id,encryption:"none",flow:$flow}]}]},streamSettings:{network:"tcp",security:"reality",realitySettings:{serverName:$sni,fingerprint:"chrome",publicKey:$public,shortId:$sid,spiderX:"/"}}}]}' > "$work/client.json"
bin=/usr/local/x-ui/bin/xray-linux-amd64
stage=test-client
if ! "$bin" run -test -config "$work/client.json" > "$work/test.log" 2>&1; then
  tail -n 5 "$work/test.log" | sed -E 's/[0-9a-fA-F]{8}-[0-9a-fA-F-]{27,}/<redacted-uuid>/g' >&2
  exit 1
fi
stage=start-client
"$bin" run -config "$work/client.json" > "$work/client.log" 2>&1 &
client_pid=$!
ready=false
for _ in 1 2 3 4 5 6 7 8 9 10; do if ss -ltn | grep -q '127.0.0.1:10889'; then ready=true; break; fi; sleep 1; done
test "$ready" = true
stage=cascade-probe
if ! curl --fail -sS --max-time 20 --socks5-hostname 127.0.0.1:10889 https://www.cloudflare.com/cdn-cgi/trace > "$work/trace"; then
  echo 3XUI_REFERENCE_CASCADE_CONNECT_FAILED >&2
  exit 1
fi
observed_ip=$(awk -F= '$1=="ip"{print $2}' "$work/trace" | tail -n 1)
case "$observed_ip" in %q|%q) ;; *) echo "3XUI_REFERENCE_CASCADE_EGRESS_MISMATCH observed=${observed_ip:-missing}" >&2; exit 1 ;; esac
echo 3XUI_REFERENCE_CASCADE_E2E_READY

stage=ru-site-probes
ru_passed=0
ru_total=0
for url in https://www.yandex.ru/ https://www.nalog.gov.ru/ https://www.mos.ru/ https://vk.com/; do
  ru_total=$((ru_total + 1))
  code=$(curl -sS -o /dev/null -w '%%{http_code}' --connect-timeout 8 --max-time 20 --socks5-hostname 127.0.0.1:10889 "$url" || true)
  case "$code" in
    2??|3??) ru_passed=$((ru_passed + 1)) ;;
  esac
done
if [ "$ru_passed" -lt 3 ]; then
  echo "3XUI_REFERENCE_RU_SITES_FAILED passed=$ru_passed total=$ru_total" >&2
  exit 1
fi
echo "3XUI_REFERENCE_RU_SITES_READY passed=$ru_passed total=$ru_total"

stage=read-subscription-settings
curl --fail-with-body -sS %s -H @"$work/header" -X POST "$api/setting/all" > "$work/settings.json"
jq -e '.success==true and .obj.subEnable==true and .obj.subEnableRouting==true and .obj.subHappAutoDetect==true' "$work/settings.json" >/dev/null
sub_path=$(jq -r '.obj.subPath' "$work/settings.json")
sub_id=$(printf '%%s' "$settings" | jq -r '.clients[0].subId')
test -n "$sub_path"; test -n "$sub_id"; test "$sub_id" != null
stage=fetch-subscription
curl --fail -k -sS --max-time 20 -A 'Happ/4.0' -D "$work/sub-headers" -o "$work/sub-body" "https://127.0.0.1:%d${sub_path}${sub_id}"
routing_enabled=$(awk -F': ' 'tolower($1)=="routing-enable" {gsub("\r", "", $2); print tolower($2)}' "$work/sub-headers" | tail -n 1)
routing_header=$(awk -F': ' 'tolower($1)=="routing" {sub(/^[^:]*: /, ""); sub(/\r$/, ""); print}' "$work/sub-headers" | tail -n 1)
test "$routing_enabled" = true
test -n "$routing_header"
stage=delete-token
delete_token
echo 3XUI_REFERENCE_HAPP_READY
`, panel.Scheme, panel.Port, panel.BasePath, panel.CurlTLS, panel.CurlTLS, panel.CurlTLS,
		verify.InboundTag, verify.ClientPort, panel.CurlTLS, verify.ClientPort, verify.ClientPort,
		entryIP.String(), verify.ClientPort, exitIP.String(), exitIPv6.String(), panel.CurlTLS, verify.SubscriptionPort), nil
}
