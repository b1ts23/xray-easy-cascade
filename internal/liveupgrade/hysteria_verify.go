// SPDX-License-Identifier: GPL-3.0-only

package liveupgrade

import (
	"errors"
	"fmt"
	"net/netip"
)

type HysteriaVerifyOptions struct {
	Transport        HysteriaOptions
	SubscriptionPort int
	ExpectedExitIPv4 string
	ExpectedExitIPv6 string
}

// HysteriaVerifyScript proves the UDP listener, trusted TLS, cascade egress,
// routing coverage and HAPP subscription publication before operator commit.
func HysteriaVerifyScript(panel Options, verify HysteriaVerifyOptions) (string, error) {
	if err := panel.validate(); err != nil {
		return "", err
	}
	if err := verify.Transport.validate(); err != nil {
		return "", err
	}
	if verify.SubscriptionPort < 1 || verify.SubscriptionPort > 65535 {
		return "", errors.New("subscription port must be valid")
	}
	exitIPv4, err := netip.ParseAddr(verify.ExpectedExitIPv4)
	if err != nil || !exitIPv4.Is4() || !exitIPv4.IsGlobalUnicast() {
		return "", errors.New("expected exit must be a global IPv4 address")
	}
	exitIPv6, err := netip.ParseAddr(verify.ExpectedExitIPv6)
	if err != nil || !exitIPv6.Is6() || !exitIPv6.IsGlobalUnicast() {
		return "", errors.New("expected exit IPv6 must be a global IPv6 address")
	}
	return fmt.Sprintf(`set -eu
umask 077
stage=init
work=$(mktemp -d /run/xray-cascade-hysteria-verify-XXXXXX)
cd /usr/local/x-ui
token_name=xray-cascade-hysteria-verify-$(openssl rand -hex 8)
token=$(./x-ui setting -tokenName "$token_name" -tokenScope admin -getApiToken | sed -n 's/^apiToken: //p' | tail -n 1)
test -n "$token"
printf 'Authorization: Bearer %%s\n' "$token" > "$work/header"
unset token
api=%[1]s://127.0.0.1:%[2]d%[3]sapi
client_pid=
delete_token() {
  test -s "$work/header" || return 0
  curl --fail-with-body -sS %[4]s -H @"$work/header" "$api/setting/apiTokens" > "$work/tokens.json"
  token_id=$(jq -r --arg name "$token_name" '.obj[]?|select(.name==$name)|.id' "$work/tokens.json" | head -n 1)
  test -n "$token_id"
  printf '{"expectedScope":"admin"}' > "$work/delete-request.json"
  curl --fail-with-body -sS %[4]s -H @"$work/header" -H 'Content-Type: application/json' -X POST --data @"$work/delete-request.json" "$api/setting/apiTokens/delete/$token_id" > "$work/delete.json"
  jq -e '.success==true' "$work/delete.json" >/dev/null
  rm -f "$work/header"
}
cleanup() {
  status=$?
  if [ -n "$client_pid" ]; then kill "$client_pid" 2>/dev/null || true; wait "$client_pid" 2>/dev/null || true; fi
  delete_token >/dev/null 2>&1 || true
  rm -rf "$work"
  if [ "$status" -ne 0 ]; then echo "3XUI_REFERENCE_HYSTERIA_VERIFY_FAILED stage=$stage status=$status" >&2; fi
  exit "$status"
}
trap cleanup EXIT INT TERM
stage=read-runtime
curl --fail-with-body -sS %[4]s -H @"$work/header" "$api/server/getConfigJson" > "$work/runtime.json"
jq -e --arg primary %[5]q --arg tag %[6]q --arg bal %[7]q --argjson port %[8]d '.success==true and (.obj.inbounds|any(.tag==$tag and .port==$port and .protocol=="hysteria" and .streamSettings.network=="hysteria" and .streamSettings.security=="tls")) and (.obj.routing.rules|any(.balancerTag==$bal and ((.inboundTag//[])|index($primary)!=null) and ((.inboundTag//[])|index($tag)!=null)))' "$work/runtime.json" >/dev/null
ss -H -lun "sport = :%[8]d" | grep -q .
curl --fail-with-body -sS %[4]s -H @"$work/header" "$api/inbounds/list" > "$work/inbounds.json"
settings=$(jq -r --arg tag %[6]q '.obj[]|select(.tag==$tag)|.settings' "$work/inbounds.json")
stream=$(jq -r --arg tag %[6]q '.obj[]|select(.tag==$tag)|.streamSettings' "$work/inbounds.json")
auth=$(printf '%%s' "$settings" | jq -r '.clients[0].auth')
sub_id=$(printf '%%s' "$settings" | jq -r '.clients[0].subId')
sni=$(printf '%%s' "$stream" | jq -r '.tlsSettings.serverName')
pin=$(printf '%%s' "$stream" | jq -r '.tlsSettings.settings.pinnedPeerCertSha256[0]//""')
test -n "$auth"; test "$auth" != null
test -n "$sub_id"; test "$sub_id" != null
test "$sni" = %[9]q
stage=build-client
jq -n --arg auth "$auth" --arg sni "$sni" --arg pin "$pin" --arg address %[9]q --argjson port %[8]d '{log:{loglevel:"warning"},inbounds:[{tag:"reference-hysteria-socks",listen:"127.0.0.1",port:10891,protocol:"socks",settings:{udp:true}}],outbounds:[{tag:"entry-hysteria",protocol:"hysteria",settings:{address:$address,port:$port,version:2},streamSettings:{network:"hysteria",security:"tls",hysteriaSettings:{version:2,auth:$auth,udpIdleTimeout:60},tlsSettings:({serverName:$sni,alpn:["h3"]}+if $pin=="" then {} else {pinnedPeerCertSha256:$pin} end)}}]}' > "$work/client.json"
bin=/usr/local/x-ui/bin/xray-linux-amd64
"$bin" run -test -config "$work/client.json" > "$work/test.log" 2>&1
stage=start-client
"$bin" run -config "$work/client.json" > "$work/client.log" 2>&1 &
client_pid=$!
ready=false
for _ in 1 2 3 4 5 6 7 8 9 10; do if ss -ltn | grep -q '127.0.0.1:10891'; then ready=true; break; fi; sleep 1; done
test "$ready" = true
stage=cascade-probe
curl --fail -sS --max-time 25 --socks5-hostname 127.0.0.1:10891 https://www.cloudflare.com/cdn-cgi/trace > "$work/trace"
observed_ip=$(awk -F= '$1=="ip"{print $2}' "$work/trace" | tail -n 1)
case "$observed_ip" in %[10]q|%[11]q) ;; *) echo "3XUI_REFERENCE_HYSTERIA_EGRESS_MISMATCH observed=${observed_ip:-missing}" >&2; exit 1 ;; esac
echo 3XUI_REFERENCE_HYSTERIA_E2E_READY
stage=read-subscription-settings
curl --fail-with-body -sS %[4]s -H @"$work/header" -X POST "$api/setting/all" > "$work/panel-settings.json"
jq -e '.success==true and .obj.subEnable==true and .obj.subEnableRouting==true and .obj.subHappAutoDetect==true' "$work/panel-settings.json" >/dev/null
sub_path=$(jq -r '.obj.subPath' "$work/panel-settings.json")
test -n "$sub_path"
stage=fetch-subscription
curl --fail -k -sS --max-time 20 -A 'Happ/4.6.1' -D "$work/sub-headers" -o "$work/sub-body" "https://127.0.0.1:%[12]d${sub_path}${sub_id}"
routing_enabled=$(awk -F': ' 'tolower($1)=="routing-enable" {gsub("\r", "", $2); print tolower($2)}' "$work/sub-headers" | tail -n 1)
test "$routing_enabled" = true
if ! base64 -d < "$work/sub-body" > "$work/sub-links" 2>/dev/null; then cp "$work/sub-body" "$work/sub-links"; fi
grep -q '^hysteria2://' "$work/sub-links"
grep -q 'type=tcp' "$work/sub-links"
grep -q 'type=xhttp' "$work/sub-links"
hysteria_links=$(grep -c '^hysteria2://' "$work/sub-links" || true)
test "$hysteria_links" -ge 1
matching_hysteria=$(grep -E '^hysteria2://[^@]+@%[9]s:%[8]d\?' "$work/sub-links" | head -n 1 || true)
test -n "$matching_hysteria"
case "$matching_hysteria" in *'security=tls'*) ;; *) exit 1;; esac
case "$matching_hysteria" in *'sni=%[9]s'*) ;; *) exit 1;; esac
case "$matching_hysteria" in *'alpn=h3'*) ;; *) exit 1;; esac
stage=delete-token
delete_token
echo "3XUI_REFERENCE_HYSTERIA_SUBSCRIPTION_READY hysteria2=$hysteria_links"
`, panel.Scheme, panel.Port, panel.BasePath, panel.CurlTLS,
		verify.Transport.PrimaryInboundTag, verify.Transport.InboundTag, verify.Transport.BalancerTag,
		verify.Transport.Port, verify.Transport.EntryAddress, exitIPv4.String(), exitIPv6.String(), verify.SubscriptionPort), nil
}
