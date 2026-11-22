// SPDX-License-Identifier: GPL-3.0-only

// Package liveupgrade builds the narrowly scoped 3x-ui runtime migration used
// to adopt an existing two-path cascade without reinstalling either panel.
package liveupgrade

import (
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

var safeTag = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._() -]{0,95}$`)
var safeInterval = regexp.MustCompile(`^[1-9][0-9]*[smh]$`)
var safeID = regexp.MustCompile(`^[0-9a-f]{32}$`)

type Options struct {
	Scheme                string
	Port                  int
	BasePath              string
	CurlTLS               string
	IPv4OutboundTag       string
	IPv6OutboundTag       string
	BalancerTag           string
	ClientInboundTag      string
	ObservatoryInterval   string
	RequireOperatorCommit bool
}

func rollbackScript(o Options, txID string) string {
	return fmt.Sprintf(`set -eu
umask 077
root=/var/lib/xray-cascade-live-upgrade
tx=%s
txdir="$root/transactions/$tx"
exec 9>"$txdir/rollback.lock"
flock 9
status=$(jq -r '.status' "$txdir/metadata.json")
case "$status" in pending|verified_waiting_confirmation) ;; *) exit 0 ;; esac
cd /usr/local/x-ui
token_name=xray-cascade-live-rollback-$(openssl rand -hex 8)
token=$(./x-ui setting -tokenName "$token_name" -tokenScope admin -getApiToken | sed -n 's/^apiToken: //p' | tail -n 1)
test -n "$token"
printf 'Authorization: Bearer %%s\n' "$token" > "$txdir/rollback-header"
unset token
api=%s://127.0.0.1:%d%sapi
curl --fail-with-body -sS %s -H @"$txdir/rollback-header" -F keepHostSettings=false -F "db=@$txdir/x-ui.db" "$api/server/importDB" > "$txdir/import.json"
jq -e '.success==true' "$txdir/import.json" >/dev/null
ready=false
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30; do
  sleep 1
  if curl --fail-with-body -sS %s -H @"$txdir/snapshot-header" "$api/setting/apiTokens" > "$txdir/tokens.json" 2>/dev/null; then ready=true; break; fi
done
test "$ready" = true
snapshot_name=$(jq -r '.snapshotTokenName' "$txdir/metadata.json")
snapshot_id=$(jq -r --arg name "$snapshot_name" '.obj[]?|select(.name==$name)|.id' "$txdir/tokens.json" | head -n 1)
test -n "$snapshot_id"
printf '{"expectedScope":"admin"}' > "$txdir/delete-request.json"
curl --fail-with-body -sS %s -H @"$txdir/snapshot-header" -H 'Content-Type: application/json' -X POST --data @"$txdir/delete-request.json" "$api/setting/apiTokens/delete/$snapshot_id" > "$txdir/delete.json"
jq -e '.success==true' "$txdir/delete.json" >/dev/null
jq '.status="rolled_back" | .rolledBackAt=(now|todateiso8601)' "$txdir/metadata.json" > "$txdir/metadata.new"
chmod 0600 "$txdir/metadata.new"
mv -f "$txdir/metadata.new" "$txdir/metadata.json"
rm -f "$txdir/snapshot-header" "$txdir/rollback-header" "$txdir/delete-request.json"
rm -rf "$root/lock"
echo 3XUI_LIVE_ROLLBACK_READY
`, txID, o.Scheme, o.Port, o.BasePath, o.CurlTLS, o.CurlTLS, o.CurlTLS)
}

func workerScript(txID, applyScript, verifyScript string, simulateFailure, requireOperatorCommit bool) string {
	simulate := "false"
	if simulateFailure {
		simulate = "true"
	}
	manualCommit := "false"
	if requireOperatorCommit {
		manualCommit = "true"
	}
	applyPayload := base64.StdEncoding.EncodeToString([]byte(applyScript))
	verifyPayload := base64.StdEncoding.EncodeToString([]byte(verifyScript))
	return fmt.Sprintf(`set -eu
umask 077
root=/var/lib/xray-cascade-live-upgrade
tx=%s
txdir="$root/transactions/$tx"
rollback_unit=xray-cascade-live-rollback-$tx
rollback_now() {
  status=$?
  if [ "$status" -ne 0 ]; then /bin/bash "$txdir/rollback.sh" || true; fi
  exit "$status"
}
trap rollback_now EXIT INT TERM
printf '%%s' '%s' | base64 -d > "$txdir/apply.sh"
printf '%%s' '%s' | base64 -d > "$txdir/verify.sh"
chmod 0700 "$txdir/apply.sh" "$txdir/verify.sh" "$txdir/rollback.sh"
/bin/bash "$txdir/apply.sh"
if [ %s = true ]; then exit 97; fi
/bin/bash "$txdir/verify.sh"
exec 8>"$txdir/rollback.lock"
flock 8
test "$(jq -r '.status' "$txdir/metadata.json")" = pending
if [ %s = true ]; then
  jq '.status="verified_waiting_confirmation" | .verifiedAt=(now|todateiso8601)' "$txdir/metadata.json" > "$txdir/metadata.new"
  chmod 0600 "$txdir/metadata.new"
  mv -f "$txdir/metadata.new" "$txdir/metadata.json"
  echo 3XUI_LIVE_UPGRADE_WAITING_CONFIRMATION
  trap - EXIT INT TERM
  exit 0
fi
systemctl stop "$rollback_unit.timer" 2>/dev/null || true
systemctl stop "$rollback_unit.service" 2>/dev/null || true
jq '.status="committed" | .committedAt=(now|todateiso8601)' "$txdir/metadata.json" > "$txdir/metadata.new"
chmod 0600 "$txdir/metadata.new"
mv -f "$txdir/metadata.new" "$txdir/metadata.json"
rm -f "$txdir/snapshot-header"
rm -rf "$root/lock"
echo 3XUI_LIVE_UPGRADE_COMMITTED
trap - EXIT INT TERM
`, txID, applyPayload, verifyPayload, simulate, manualCommit)
}

// LauncherScript prepares a consistent API export, removes its temporary token
// from the live database, arms an independent systemd rollback timer, and then
// starts the worker as a transient service. It returns before the worker can
// restart Xray, so losing the operator's VPN/SSH session cannot stop recovery.
func LauncherScript(o Options, txID, verifyScript string, simulateFailure bool) (string, error) {
	if err := o.validate(); err != nil {
		return "", err
	}
	if !safeID.MatchString(txID) {
		return "", errors.New("transaction ID must be 32 lowercase hexadecimal characters")
	}
	if strings.TrimSpace(verifyScript) == "" {
		return "", errors.New("verification script is required")
	}
	applyScript, err := ApplyScript(o)
	if err != nil {
		return "", err
	}
	return LauncherWithApplyScript(o, txID, applyScript, verifyScript, simulateFailure)
}

// LauncherWithApplyScript wraps a separately validated, narrowly scoped
// mutation in the same database snapshot, independent worker, dead-man
// rollback, and manual-commit protocol used by LauncherScript. It is kept
// internal to this module and is not exposed through vpnctl production
// commands.
func LauncherWithApplyScript(o Options, txID, applyScript, verifyScript string, simulateFailure bool) (string, error) {
	if err := o.validate(); err != nil {
		return "", err
	}
	if !safeID.MatchString(txID) {
		return "", errors.New("transaction ID must be 32 lowercase hexadecimal characters")
	}
	if strings.TrimSpace(applyScript) == "" {
		return "", errors.New("apply script is required")
	}
	if strings.TrimSpace(verifyScript) == "" {
		return "", errors.New("verification script is required")
	}
	rollback := rollbackScript(o, txID)
	worker := workerScript(txID, applyScript, verifyScript, simulateFailure, o.RequireOperatorCommit)
	rollbackPayload := base64.StdEncoding.EncodeToString([]byte(rollback))
	workerPayload := base64.StdEncoding.EncodeToString([]byte(worker))
	return fmt.Sprintf(`set -eu
umask 077
stage=init
command -v systemd-run >/dev/null
command -v flock >/dev/null
root=/var/lib/xray-cascade-live-upgrade
tx=%s
txdir="$root/transactions/$tx"
lock="$root/lock"
install -d -m 0700 "$root" "$root/transactions"
if ! mkdir "$lock" 2>/dev/null; then echo 'live-upgrade lock already exists' >&2; exit 1; fi
begin_ok=false
watchdog_armed=false
snapshot_created=false
snapshot_deleted=false
snapshot_name=
api=
cleanup_snapshot_token() {
  test "$snapshot_created" = true || return 0
  test "$snapshot_deleted" = false || return 0
  test -n "$api" || return 1
  cd /usr/local/x-ui
  cleanup_token=$(./x-ui setting -tokenName "$snapshot_name" -tokenScope admin -getApiToken | sed -n 's/^apiToken: //p' | tail -n 1)
  test -n "$cleanup_token"
  printf 'Authorization: Bearer %%s\n' "$cleanup_token" > "$txdir/snapshot-header"
  unset cleanup_token
  curl --fail-with-body -sS %s -H @"$txdir/snapshot-header" "$api/setting/apiTokens" > "$txdir/cleanup-tokens.json"
  cleanup_id=$(jq -r --arg name "$snapshot_name" '.obj[]?|select(.name==$name and .scope=="admin")|.id' "$txdir/cleanup-tokens.json" | head -n 1)
  test -n "$cleanup_id"
  printf '{"expectedScope":"admin"}' > "$txdir/cleanup-delete-request.json"
  curl --fail-with-body -sS %s -H @"$txdir/snapshot-header" -H 'Content-Type: application/json' -X POST --data @"$txdir/cleanup-delete-request.json" "$api/setting/apiTokens/delete/$cleanup_id" > "$txdir/cleanup-delete.json"
  jq -e '.success==true' "$txdir/cleanup-delete.json" >/dev/null
  snapshot_deleted=true
}
cleanup_begin() { status=$?; if [ "$begin_ok" != true ]; then if [ "$watchdog_armed" = true ]; then systemctl stop "$rollback_unit.timer" 2>/dev/null || true; systemctl stop "$rollback_unit.service" 2>/dev/null || true; fi; cleanup_ok=true; cleanup_snapshot_token >/dev/null 2>&1 || cleanup_ok=false; if [ "$cleanup_ok" = true ]; then rm -rf "$txdir" "$lock"; else echo "3XUI_LIVE_UPGRADE_CLEANUP_REQUIRED transaction=$tx" >&2; fi; fi; rm -f /run/xray-cascade-live-header; if [ "$status" -ne 0 ]; then echo "3XUI_LIVE_UPGRADE_LAUNCH_FAILED stage=$stage" >&2; fi; exit "$status"; }
trap cleanup_begin EXIT INT TERM
stage=prepare-directory
mkdir "$txdir"
printf '%%s' '%s' | base64 -d > "$txdir/rollback.sh"
printf '%%s' '%s' | base64 -d > "$txdir/worker.sh"
chmod 0700 "$txdir/rollback.sh" "$txdir/worker.sh"
cd /usr/local/x-ui
stage=create-snapshot-token
snapshot_name=xray-cascade-live-snapshot-$tx
token=$(./x-ui setting -tokenName "$snapshot_name" -tokenScope admin -getApiToken | sed -n 's/^apiToken: //p' | tail -n 1)
test -n "$token"
snapshot_created=true
printf 'Authorization: Bearer %%s\n' "$token" > "$txdir/snapshot-header"
unset token
api=%s://127.0.0.1:%d%sapi
stage=export-database
curl --fail-with-body -sS %s -H @"$txdir/snapshot-header" "$api/server/getDb" -o "$txdir/x-ui.db"
test -s "$txdir/x-ui.db"
db_sha=$(sha256sum "$txdir/x-ui.db" | awk '{print $1}')
stage=delete-snapshot-token
curl --fail-with-body -sS %s -H @"$txdir/snapshot-header" "$api/setting/apiTokens" > "$txdir/tokens.json"
token_id=$(jq -r --arg name "$snapshot_name" '.obj[]?|select(.name==$name)|.id' "$txdir/tokens.json" | head -n 1)
test -n "$token_id"
printf '{"expectedScope":"admin"}' > "$txdir/delete-request.json"
curl --fail-with-body -sS %s -H @"$txdir/snapshot-header" -H 'Content-Type: application/json' -X POST --data @"$txdir/delete-request.json" "$api/setting/apiTokens/delete/$token_id" > "$txdir/delete.json"
jq -e '.success==true' "$txdir/delete.json" >/dev/null
snapshot_deleted=true
jq -n --arg id "$tx" --arg sha "$db_sha" --arg tokenName "$snapshot_name" --arg created "$(date -u +%%Y-%%m-%%dT%%H:%%M:%%SZ)" '{schema:1,id:$id,status:"pending",databaseSHA256:$sha,snapshotTokenName:$tokenName,createdAt:$created}' > "$txdir/metadata.json"
chmod 0600 "$txdir"/*
stage=arm-watchdog
rollback_unit=xray-cascade-live-rollback-$tx
worker_unit=xray-cascade-live-worker-$tx
systemd-run --quiet --unit "$rollback_unit" --on-active=5m /bin/bash "$txdir/rollback.sh"
watchdog_armed=true
stage=start-worker
systemd-run --quiet --unit "$worker_unit" --collect /bin/bash "$txdir/worker.sh"
begin_ok=true
echo "3XUI_LIVE_UPGRADE_ARMED transaction=$tx"
trap - EXIT INT TERM
`, txID, o.CurlTLS, o.CurlTLS, rollbackPayload, workerPayload, o.Scheme, o.Port, o.BasePath, o.CurlTLS, o.CurlTLS, o.CurlTLS), nil
}

// CommitScript confirms a manually gated live upgrade. It races safely with
// the rollback watchdog through the same flock; whichever obtains the lock
// first decides the transaction state.
func CommitScript(txID string) (string, error) {
	if !safeID.MatchString(txID) {
		return "", errors.New("transaction ID must be 32 lowercase hexadecimal characters")
	}
	return fmt.Sprintf(`set -eu
umask 077
root=/var/lib/xray-cascade-live-upgrade
tx=%s
txdir="$root/transactions/$tx"
test -f "$txdir/metadata.json"
exec 8>"$txdir/rollback.lock"
flock 8
test "$(jq -r '.status' "$txdir/metadata.json")" = verified_waiting_confirmation
rollback_unit=xray-cascade-live-rollback-$tx
systemctl stop "$rollback_unit.timer" 2>/dev/null || true
systemctl stop "$rollback_unit.service" 2>/dev/null || true
jq '.status="committed" | .committedAt=(now|todateiso8601)' "$txdir/metadata.json" > "$txdir/metadata.new"
chmod 0600 "$txdir/metadata.new"
mv -f "$txdir/metadata.new" "$txdir/metadata.json"
rm -f "$txdir/snapshot-header"
rm -rf "$root/lock"
echo 3XUI_LIVE_UPGRADE_COMMITTED
`, txID), nil
}

func StatusScript(txID string) (string, error) {
	if !safeID.MatchString(txID) {
		return "", errors.New("transaction ID must be 32 lowercase hexadecimal characters")
	}
	return fmt.Sprintf(`set -eu
tx=%s
txdir=/var/lib/xray-cascade-live-upgrade/transactions/$tx
test -f "$txdir/metadata.json"
jq -r '"3XUI_LIVE_UPGRADE_STATUS transaction="+.id+" status="+.status' "$txdir/metadata.json"
systemctl is-active "xray-cascade-live-worker-$tx.service" 2>/dev/null || true
systemctl is-active "xray-cascade-live-rollback-$tx.timer" 2>/dev/null || true
`, txID), nil
}

func (o Options) validate() error {
	if o.Scheme != "http" && o.Scheme != "https" {
		return errors.New("panel scheme must be http or https")
	}
	if o.Port < 1 || o.Port > 65535 {
		return errors.New("panel port must be between 1 and 65535")
	}
	if !strings.HasPrefix(o.BasePath, "/") || !strings.HasSuffix(o.BasePath, "/") || strings.ContainsAny(o.BasePath, "\r\n") {
		return errors.New("panel base path must start and end with slash")
	}
	if o.CurlTLS != "" && o.CurlTLS != "-k" {
		return errors.New("unsupported panel curl TLS option")
	}
	for name, value := range map[string]string{
		"IPv4 outbound": o.IPv4OutboundTag, "IPv6 outbound": o.IPv6OutboundTag,
		"balancer": o.BalancerTag, "client inbound": o.ClientInboundTag,
	} {
		if !safeTag.MatchString(value) {
			return fmt.Errorf("%s tag is unsafe", name)
		}
	}
	if !safeInterval.MatchString(o.ObservatoryInterval) {
		return errors.New("observatory interval must be a positive s, m, or h duration")
	}
	return nil
}

// ApplyScript changes only the existing balancer, observatory, and order of
// the existing BitTorrent rule. It does not create or replace inbounds,
// outbounds, clients, subscriptions, certificates, or panel settings.
func ApplyScript(o Options) (string, error) {
	if err := o.validate(); err != nil {
		return "", err
	}
	return fmt.Sprintf(`set -eu
umask 077
stage=init
work=$(mktemp -d /run/xray-cascade-live-apply-XXXXXX)
cd /usr/local/x-ui
token_name=xray-cascade-live-apply-$(openssl rand -hex 8)
token=$(./x-ui setting -tokenName "$token_name" -tokenScope admin -getApiToken | sed -n 's/^apiToken: //p' | tail -n 1)
test -n "$token"
printf 'Authorization: Bearer %%s\n' "$token" > "$work/header"
unset token
api=%s://127.0.0.1:%d%sapi
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
  delete_token >/dev/null 2>&1 || true
  rm -rf "$work"
  if [ "$status" -ne 0 ]; then echo "3XUI_LIVE_RUNTIME_UPDATE_FAILED stage=$stage" >&2; fi
  exit "$status"
}
trap cleanup EXIT INT TERM

stage=read-template
curl --fail-with-body -sS %s -H @"$work/header" -X POST "$api/xray/" > "$work/template-response.json"
jq -e '.success==true' "$work/template-response.json" >/dev/null
jq -r '.obj|fromjson|.xraySetting' "$work/template-response.json" > "$work/before.json"
stage=validate-before
if ! jq -e --arg v4 %q --arg v6 %q --arg bal %q --arg inbound %q '
  (.outbounds|map(select(.tag==$v4))|length)==1
  and (.outbounds|map(select(.tag==$v6))|length)==1
  and (.routing.balancers//[]|map(select(.tag==$bal))|length)==1
  and (.routing.rules|map(select(.balancerTag==$bal and ((.inboundTag//[])|index($inbound)!=null)))|length)==1
  and (.routing.rules|map(select(((.protocol//[])|index("bittorrent"))!=null))|length)>=1
  and (.observatory==null or ((.observatory.subjectSelector//[])|all(.==$v4 or .==$v6)))
' "$work/before.json" >/dev/null; then
  jq -c --arg bal %q --arg inbound %q '{outboundTags:[.outbounds[].tag],balancers:[(.routing.balancers//[])[]|{tag,selector,fallbackTag}],catchRules:(.routing.rules|map(select(.balancerTag==$bal and ((.inboundTag//[])|index($inbound)!=null)))|length),bittorrentRules:(.routing.rules|map(select(((.protocol//[])|index("bittorrent"))!=null))|length),observatorySelectors:(.observatory.subjectSelector//[])}' "$work/before.json" >&2
  exit 1
fi

stage=build-after
jq --arg v4 %q --arg v6 %q --arg bal %q --arg inbound %q --arg interval %q '
  def isbt: (((.protocol//[])|index("bittorrent"))!=null);
  def iscatch: (.balancerTag==$bal and (((.inboundTag//[])|index($inbound))!=null));
  .routing.balancers |= map(if .tag==$bal then .selector=[$v4] | .fallbackTag=$v6 | .strategy={type:"roundRobin"} else . end)
  | .routing.rules as $rules
  | ($rules|map(select(isbt))) as $bt
  | ($rules|map(select(isbt|not))) as $base
  | ($base|map(iscatch)|index(true)) as $catch
  | .routing.rules=($base[0:$catch]+$bt+$base[$catch:])
  | .observatory={subjectSelector:[$v4,$v6],probeURL:"https://www.google.com/generate_204",probeInterval:$interval,enableConcurrency:true}
' "$work/before.json" > "$work/after.json"

stage=validate-after
jq -e --arg v4 %q --arg v6 %q --arg bal %q --arg inbound %q --arg interval %q '
  (.routing.balancers|any(.tag==$bal and .selector==[$v4] and .fallbackTag==$v6 and .strategy.type=="roundRobin"))
  and .observatory.subjectSelector==[$v4,$v6]
  and .observatory.probeInterval==$interval
  and ((.routing.rules|map(((.protocol//[])|index("bittorrent"))!=null)|index(true)) < (.routing.rules|map(.balancerTag==$bal and (((.inboundTag//[])|index($inbound))!=null))|index(true)))
' "$work/after.json" >/dev/null

stage=update-template
curl --fail-with-body -sS %s -H @"$work/header" -X POST --data-urlencode xraySetting@"$work/after.json" "$api/xray/update" > "$work/update.json"
jq -e '.success==true' "$work/update.json" >/dev/null
stage=restart-xray
curl --fail-with-body -sS %s -H @"$work/header" -X POST "$api/server/restartXrayService" > "$work/restart.json"
jq -e '.success==true' "$work/restart.json" >/dev/null

stage=verify-runtime
ready=false
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
  if curl --fail-with-body -sS %s -H @"$work/header" "$api/server/getConfigJson" > "$work/runtime.json" 2>/dev/null \
    && jq -e --arg v4 %q --arg v6 %q --arg bal %q --arg inbound %q --arg interval %q '
      .success==true
      and (.obj.routing.balancers|any(.tag==$bal and .selector==[$v4] and .fallbackTag==$v6 and .strategy.type=="roundRobin"))
      and .obj.observatory.subjectSelector==[$v4,$v6]
      and .obj.observatory.probeInterval==$interval
      and ((.obj.routing.rules|map(((.protocol//[])|index("bittorrent"))!=null)|index(true)) < (.obj.routing.rules|map(.balancerTag==$bal and (((.inboundTag//[])|index($inbound))!=null))|index(true)))
    ' "$work/runtime.json" >/dev/null; then ready=true; break; fi
  sleep 1
done
test "$ready" = true
stage=delete-token
delete_token
echo 3XUI_LIVE_RUNTIME_UPDATED
`, o.Scheme, o.Port, o.BasePath, o.CurlTLS, o.CurlTLS, o.CurlTLS,
		o.IPv4OutboundTag, o.IPv6OutboundTag, o.BalancerTag, o.ClientInboundTag, o.BalancerTag, o.ClientInboundTag,
		o.IPv4OutboundTag, o.IPv6OutboundTag, o.BalancerTag, o.ClientInboundTag, o.ObservatoryInterval,
		o.IPv4OutboundTag, o.IPv6OutboundTag, o.BalancerTag, o.ClientInboundTag, o.ObservatoryInterval,
		o.CurlTLS, o.CurlTLS, o.CurlTLS,
		o.IPv4OutboundTag, o.IPv6OutboundTag, o.BalancerTag, o.ClientInboundTag, o.ObservatoryInterval), nil
}
