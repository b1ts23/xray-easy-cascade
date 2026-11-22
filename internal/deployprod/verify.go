// SPDX-License-Identifier: GPL-3.0-only

package deployprod

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/b1ts23/xray-easy-cascade/internal/inventory"
)

const verifyBundlePrefix = "3XUI_PRODUCTION_VERIFY_BUNDLE\t"

func verificationBundleScript(inv inventory.Inventory) string {
	return fmt.Sprintf(`set -eu
umask 077
cd /usr/local/x-ui
token=$(./x-ui setting -tokenName xray-cascade-production-verify -tokenScope admin -getApiToken | sed -n 's/^apiToken: //p' | tail -n 1)
test -n "$token"
printf 'Authorization: Bearer %%s\n' "$token" > /run/xray-cascade-verify-header
unset token
trap 'rm -f /run/xray-cascade-verify-header /run/xray-cascade-verify-inbounds.json /run/xray-cascade-verify-settings.json /run/xray-cascade-verify-bundle.json' EXIT INT TERM
api=https://127.0.0.1:%d/entry/panel/api
curl --fail-with-body --insecure -sS -H @/run/xray-cascade-verify-header "$api/inbounds/list" > /run/xray-cascade-verify-inbounds.json
curl --fail-with-body --insecure -sS -H @/run/xray-cascade-verify-header -X POST "$api/setting/all" > /run/xray-cascade-verify-settings.json
jq -e '.success==true' /run/xray-cascade-verify-inbounds.json >/dev/null
jq -e '.success==true and .obj.subEnable==true and .obj.subEnableRouting==true and .obj.subHappAutoDetect==true' /run/xray-cascade-verify-settings.json >/dev/null
jq -n --argjson inbounds "$(jq -c '.obj' /run/xray-cascade-verify-inbounds.json)" --arg subPath "$(jq -r '.obj.subPath' /run/xray-cascade-verify-settings.json)" '
  ($inbounds[]|select(.remark=="xray-cascade-client")) as $tcp
  | (($inbounds[]|select(.remark=="xray-cascade-client-xhttp")) // null) as $xhttp
  | {tcp:{settings:($tcp.settings|fromjson),stream:($tcp.streamSettings|fromjson)},xhttp:(if $xhttp==null then null else {settings:($xhttp.settings|fromjson),stream:($xhttp.streamSettings|fromjson)} end),subPath:$subPath,subId:($tcp.settings|fromjson|.clients[0].subId)}
' > /run/xray-cascade-verify-bundle.json
jq -e '.tcp.settings.clients[0].id|length>0' /run/xray-cascade-verify-bundle.json >/dev/null
printf '3XUI_PRODUCTION_VERIFY_BUNDLE\t'
base64 -w0 /run/xray-cascade-verify-bundle.json
printf '\n'
`, inv.Panel.Port)
}

func parseVerificationBundle(raw string) (string, error) {
	value := ""
	for _, line := range strings.Split(raw, "\n") {
		if !strings.HasPrefix(line, verifyBundlePrefix) {
			continue
		}
		if value != "" {
			return "", errors.New("entry returned more than one verification bundle")
		}
		value = strings.TrimPrefix(line, verifyBundlePrefix)
	}
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(decoded) == 0 || len(decoded) > 256*1024 {
		return "", errors.New("entry returned an invalid verification bundle")
	}
	var document map[string]any
	if err := json.Unmarshal(decoded, &document); err != nil {
		return "", errors.New("entry returned malformed verification JSON")
	}
	return value, nil
}

func productionE2EScript(inv inventory.Inventory, happSHA, bundle string) (string, error) {
	input, err := json.Marshal(map[string]any{
		"entry": inv.Entry.CascadeAddress, "exit": inv.Exit.CascadeAddress,
		"tcpPort": inv.Transport.ClientPort, "xhttpPort": inv.ClientAlternativePort("reality-xhttp"),
		"subscriptionPort": inv.Subscription.Port, "happSHA": happSHA, "bundle": bundle,
	})
	if err != nil {
		return "", err
	}
	payload := base64.StdEncoding.EncodeToString(input)
	return `set -eu
umask 077
cd /usr/local/x-ui
printf '%s' '` + payload + `' | base64 -d > /run/xray-cascade-production-e2e-input.json
jq -r '.bundle' /run/xray-cascade-production-e2e-input.json | base64 -d > /run/xray-cascade-production-e2e-bundle.json
client_pid=
cleanup() {
  status=$?
  if [ -n "$client_pid" ]; then kill "$client_pid" 2>/dev/null || true; wait "$client_pid" 2>/dev/null || true; fi
  rm -f /run/xray-cascade-production-e2e-*
  exit "$status"
}
trap cleanup EXIT INT TERM
bin=/usr/local/x-ui/bin/xray-linux-amd64
entry=$(jq -r '.entry' /run/xray-cascade-production-e2e-input.json)
expected_exit=$(jq -r '.exit' /run/xray-cascade-production-e2e-input.json)
tcp_port=$(jq -r '.tcpPort' /run/xray-cascade-production-e2e-input.json)
settings=$(jq -c '.tcp.settings' /run/xray-cascade-production-e2e-bundle.json)
stream=$(jq -c '.tcp.stream' /run/xray-cascade-production-e2e-bundle.json)
client_id=$(printf '%s' "$settings" | jq -r '.clients[0].id')
public_key=$(printf '%s' "$stream" | jq -r '.realitySettings.settings.publicKey')
server_name=$(printf '%s' "$stream" | jq -r '.realitySettings.serverNames[0]')
short_id=$(printf '%s' "$stream" | jq -r '.realitySettings.shortIds[0]')
jq -n --arg id "$client_id" --arg public "$public_key" --arg sni "$server_name" --arg sid "$short_id" --arg address "$entry" --argjson port "$tcp_port" '{log:{loglevel:"warning"},inbounds:[{tag:"verify-socks",listen:"127.0.0.1",port:10808,protocol:"socks",settings:{udp:false}}],outbounds:[{tag:"entry",protocol:"vless",settings:{vnext:[{address:$address,port:$port,users:[{id:$id,encryption:"none",flow:"xtls-rprx-vision"}]}]},streamSettings:{network:"tcp",security:"reality",realitySettings:{serverName:$sni,fingerprint:"chrome",publicKey:$public,shortId:$sid,spiderX:"/"}}}]}' > /run/xray-cascade-production-e2e-tcp.json
$bin run -test -config /run/xray-cascade-production-e2e-tcp.json >/dev/null
$bin run -config /run/xray-cascade-production-e2e-tcp.json > /run/xray-cascade-production-e2e-xray.log 2>&1 &
client_pid=$!
ready=false
for _ in 1 2 3 4 5 6 7 8 9 10; do if ss -ltn | grep -q '127.0.0.1:10808'; then ready=true; break; fi; sleep 1; done
test "$ready" = true
trace=$(curl --fail -sS --max-time 20 --socks5-hostname 127.0.0.1:10808 https://www.cloudflare.com/cdn-cgi/trace)
actual_exit=$(printf '%s\n' "$trace" | sed -n 's/^ip=//p' | tail -n 1)
test "$actual_exit" = "$expected_exit"
echo "3XUI_PRODUCTION_TCP_E2E_READY exit=$actual_exit"
xhttp_port=$(jq -r '.xhttpPort' /run/xray-cascade-production-e2e-input.json)
if [ "$xhttp_port" -gt 0 ]; then
  kill "$client_pid" 2>/dev/null || true; wait "$client_pid" 2>/dev/null || true; client_pid=
  xsettings=$(jq -c '.xhttp.settings' /run/xray-cascade-production-e2e-bundle.json)
  xstream=$(jq -c '.xhttp.stream' /run/xray-cascade-production-e2e-bundle.json)
  test "$xsettings" != null
  xid=$(printf '%s' "$xsettings" | jq -r '.clients[0].id')
  test "$xid" = "$client_id"
  xpublic=$(printf '%s' "$xstream" | jq -r '.realitySettings.settings.publicKey')
  xsni=$(printf '%s' "$xstream" | jq -r '.realitySettings.serverNames[0]')
  xsid=$(printf '%s' "$xstream" | jq -r '.realitySettings.shortIds[0]')
  xpath=$(printf '%s' "$xstream" | jq -r '.xhttpSettings.path')
  xhost=$(printf '%s' "$xstream" | jq -r '.xhttpSettings.host')
  xmode=$(printf '%s' "$xstream" | jq -r '.xhttpSettings.mode')
  jq -n --arg id "$xid" --arg public "$xpublic" --arg sni "$xsni" --arg sid "$xsid" --arg address "$entry" --arg path "$xpath" --arg host "$xhost" --arg mode "$xmode" --argjson port "$xhttp_port" '{log:{loglevel:"warning"},inbounds:[{tag:"verify-xhttp-socks",listen:"127.0.0.1",port:10810,protocol:"socks",settings:{udp:false}}],outbounds:[{tag:"entry-xhttp",protocol:"vless",settings:{vnext:[{address:$address,port:$port,users:[{id:$id,encryption:"none",flow:""}]}]},streamSettings:{network:"xhttp",security:"reality",xhttpSettings:{path:$path,host:$host,mode:$mode},realitySettings:{serverName:$sni,fingerprint:"chrome",publicKey:$public,shortId:$sid,spiderX:"/"}}}]}' > /run/xray-cascade-production-e2e-xhttp.json
  $bin run -test -config /run/xray-cascade-production-e2e-xhttp.json >/dev/null
  $bin run -config /run/xray-cascade-production-e2e-xhttp.json > /run/xray-cascade-production-e2e-xray.log 2>&1 &
  client_pid=$!
  ready=false
  for _ in 1 2 3 4 5 6 7 8 9 10; do if ss -ltn | grep -q '127.0.0.1:10810'; then ready=true; break; fi; sleep 1; done
  test "$ready" = true
  trace=$(curl --fail -sS --max-time 20 --socks5-hostname 127.0.0.1:10810 https://www.cloudflare.com/cdn-cgi/trace)
  actual_exit=$(printf '%s\n' "$trace" | sed -n 's/^ip=//p' | tail -n 1)
  test "$actual_exit" = "$expected_exit"
  echo "3XUI_PRODUCTION_XHTTP_E2E_READY exit=$actual_exit"
fi
sub_port=$(jq -r '.subscriptionPort' /run/xray-cascade-production-e2e-input.json)
sub_path=$(jq -r '.subPath' /run/xray-cascade-production-e2e-bundle.json)
sub_id=$(jq -r '.subId' /run/xray-cascade-production-e2e-bundle.json)
curl --fail -sS --max-time 20 -A 'Happ/4.0' -D /run/xray-cascade-production-e2e-headers -o /run/xray-cascade-production-e2e-body "https://${entry}:${sub_port}${sub_path}${sub_id}"
routing_enabled=$(awk -F': ' 'tolower($1)=="routing-enable" {gsub("\r", "", $2); print tolower($2)}' /run/xray-cascade-production-e2e-headers | tail -n 1)
routing_header=$(awk -F': ' 'tolower($1)=="routing" {sub(/^[^:]*: /, ""); sub(/\r$/, ""); print}' /run/xray-cascade-production-e2e-headers | tail -n 1)
actual_sha=$(printf '%s\n' "$routing_header" | sha256sum | awk '{print $1}')
expected_sha=$(jq -r '.happSHA' /run/xray-cascade-production-e2e-input.json)
test "$routing_enabled" = true
test "$actual_sha" = "$expected_sha"
if base64 -d /run/xray-cascade-production-e2e-body > /run/xray-cascade-production-e2e-links 2>/dev/null; then :; else cp /run/xray-cascade-production-e2e-body /run/xray-cascade-production-e2e-links; fi
test "$(grep -c 'type=tcp' /run/xray-cascade-production-e2e-links || true)" -ge 1
if [ "$xhttp_port" -gt 0 ]; then test "$(grep -c 'type=xhttp' /run/xray-cascade-production-e2e-links || true)" -ge 1; fi
echo 3XUI_PRODUCTION_SUBSCRIPTION_E2E_READY
echo 3XUI_PRODUCTION_E2E_READY
`, nil
}

// VerifyProduction runs from the exit VPS so the client probe crosses the
// public entry edge and then returns through the managed interserver cascade.
func VerifyProduction(ctx context.Context, runner Runner, inv inventory.Inventory, happSHA string, out io.Writer) error {
	entryCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	raw, err := runner.Run(entryCtx, target(inv.Entry), verificationBundleScript(inv))
	cancel()
	if err != nil {
		return fmt.Errorf("collect production verification bundle: %w", err)
	}
	bundle, err := parseVerificationBundle(raw)
	if err != nil {
		return err
	}
	script, err := productionE2EScript(inv, happSHA, bundle)
	if err != nil {
		return err
	}
	verifyCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	raw, err = runner.Run(verifyCtx, target(inv.Exit), script)
	cancel()
	if err != nil {
		return fmt.Errorf("production cascade E2E: %w", err)
	}
	for _, marker := range []string{"3XUI_PRODUCTION_TCP_E2E_READY", "3XUI_PRODUCTION_SUBSCRIPTION_E2E_READY", "3XUI_PRODUCTION_E2E_READY"} {
		if !strings.Contains(raw, marker) {
			return fmt.Errorf("production cascade E2E returned no %s marker", marker)
		}
		fmt.Fprintln(out, marker)
	}
	return nil
}
