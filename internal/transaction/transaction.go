// SPDX-License-Identifier: GPL-3.0-only

// Package transaction builds the remote, fail-closed transaction protocol used
// around 3x-ui mutations. Backups stay root-only on the managed node and never
// cross stdout.
package transaction

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

const StateRoot = "/var/lib/xray-cascade"

var safeName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`)

const currentIDPrefix = "3XUI_TRANSACTION_ID\t"

type Endpoint struct {
	Scheme   string
	BasePath string
	CurlTLS  string
	Port     int
}

func (e Endpoint) port() int {
	if e.Port == 0 {
		return 2053
	}
	return e.Port
}

type ownership struct {
	Schema           int      `json:"schema"`
	Cluster          string   `json:"cluster"`
	Role             string   `json:"role"`
	Manager          string   `json:"manager"`
	ManagedFiles     []string `json:"managedFiles"`
	ProtectedFiles   []string `json:"protectedFiles"`
	ManagedResources []string `json:"managedResources"`
}

func NewID() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate transaction ID: %w", err)
	}
	return hex.EncodeToString(raw), nil
}

func validate(cluster, role, id string, endpoint Endpoint) error {
	if !safeName.MatchString(cluster) {
		return errors.New("cluster name is unsafe for transaction metadata")
	}
	if role != "entry" && role != "exit" {
		return errors.New("transaction role must be entry or exit")
	}
	if len(id) != 32 || regexp.MustCompile(`^[0-9a-f]{32}$`).FindString(id) == "" {
		return errors.New("transaction ID must be 32 lowercase hexadecimal characters")
	}
	if endpoint.Scheme != "http" && endpoint.Scheme != "https" {
		return errors.New("transaction endpoint scheme must be http or https")
	}
	if endpoint.BasePath == "" || endpoint.BasePath[0] != '/' || endpoint.BasePath[len(endpoint.BasePath)-1] != '/' {
		return errors.New("transaction endpoint base path must start and end with slash")
	}
	if endpoint.CurlTLS != "" && endpoint.CurlTLS != "-k" {
		return errors.New("unsupported transaction curl TLS option")
	}
	if endpoint.port() < 1 || endpoint.port() > 65535 {
		return errors.New("transaction endpoint port must be between 1 and 65535")
	}
	return nil
}

func validateIdentity(cluster, role string, endpoint Endpoint) error {
	return validate(cluster, role, strings.Repeat("0", 32), endpoint)
}

func CurrentIDScript(cluster, role string, endpoint Endpoint) (string, error) {
	if err := validateIdentity(cluster, role, endpoint); err != nil {
		return "", err
	}
	return fmt.Sprintf(`set -eu
root=%s
if [ ! -f "$root/lock/id" ]; then printf '3XUI_TRANSACTION_NONE\n'; exit 0; fi
id=$(cat "$root/lock/id")
case "$id" in (*[!0-9a-f]*|'') exit 1;; esac
test "${#id}" -eq 32
jq -e --arg id "$id" --arg cluster %s --arg role %s '.schema==1 and .id==$id and .cluster==$cluster and .role==$role and .status=="pending"' "$root/transactions/$id/metadata.json" >/dev/null
printf '3XUI_TRANSACTION_ID\t%%s\n' "$id"
`, StateRoot, cluster, role), nil
}

func ParseCurrentID(raw string) (string, error) {
	if strings.Contains(raw, "3XUI_TRANSACTION_NONE") {
		if strings.Contains(raw, currentIDPrefix) {
			return "", errors.New("node returned both pending and empty transaction markers")
		}
		return "", nil
	}
	var id string
	for _, line := range strings.Split(raw, "\n") {
		if !strings.HasPrefix(line, currentIDPrefix) {
			continue
		}
		if id != "" {
			return "", errors.New("node returned more than one transaction ID")
		}
		id = strings.TrimPrefix(line, currentIDPrefix)
	}
	if len(id) != 32 || regexp.MustCompile(`^[0-9a-f]{32}$`).FindString(id) == "" {
		return "", errors.New("node did not return a valid pending transaction ID")
	}
	return id, nil
}

func manifestPayload(cluster, role string) (string, error) {
	manifest := ownership{
		Schema:       1,
		Cluster:      cluster,
		Role:         role,
		Manager:      "vpnctl",
		ManagedFiles: []string{"/usr/local/x-ui/bin/roscom-geoip.dat", "/usr/local/x-ui/bin/roscom-geosite.dat", "/usr/local/share/ca-certificates/xray-cascade-exit.crt", "/etc/x-ui/exit-node-ca.crt"},
		ProtectedFiles: []string{
			"/etc/x-ui/subscription.crt",
			"/etc/x-ui/subscription.key",
			"/etc/x-ui/panel.crt",
			"/etc/x-ui/panel.key",
			"/etc/x-ui/panel-ca.crt",
			"/etc/x-ui/panel-ca.key",
			"/etc/systemd/system/x-ui.service",
			"/etc/systemd/system/x-ui.service.d/10-xui-sandbox.conf",
			"/etc/ufw/user.rules",
			"/etc/ufw/user6.rules",
		},
		ManagedResources: []string{
			"3x-ui:node:lab-exit",
			"3x-ui:node:xray-cascade-exit",
			"3x-ui:inbound:lab-client-entry",
			"3x-ui:inbound:lab-cascade-exit",
			"3x-ui:inbound:xray-cascade-client",
			"3x-ui:inbound:xray-cascade-exit",
			"3x-ui:outbound:cascade-exit-ipv4",
			"3x-ui:outbound:cascade-exit-ipv6",
			"3x-ui:balancer:cascade-exit",
			"3x-ui:observatory:cascade-exit",
		},
	}
	raw, err := json.Marshal(manifest)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(raw), nil
}

// BeginScript acquires a per-node lock, verifies ownership and exports a
// consistent database through the pinned 3x-ui API before any managed change.
func BeginScript(cluster, role, id string, endpoint Endpoint) (string, error) {
	if err := validate(cluster, role, id, endpoint); err != nil {
		return "", err
	}
	payload, err := manifestPayload(cluster, role)
	if err != nil {
		return "", fmt.Errorf("encode ownership manifest: %w", err)
	}
	return fmt.Sprintf(`set -eu
umask 077
root=%s
tx=%s
cluster=%s
role=%s
txdir="$root/transactions/$tx"
lock="$root/lock"
install -d -m 0700 "$root" "$root/transactions"
if ! mkdir "$lock" 2>/dev/null; then echo 'transaction lock already exists' >&2; exit 1; fi
printf '%%s\n' "$tx" > "$lock/id"
begin_ok=false
cleanup_begin() { if [ "$begin_ok" != true ]; then rm -rf "$txdir" "$lock"; fi; rm -f /run/xray-cascade-tx-header /run/xray-cascade-ownership.new; }
trap cleanup_begin EXIT INT TERM
printf '%%s' '%s' | base64 -d > /run/xray-cascade-ownership.new
if [ -e "$root/ownership.json" ]; then
  test ! -L "$root/ownership.json"
  jq -e --arg cluster "$cluster" --arg role "$role" '.schema==1 and .manager=="vpnctl" and .cluster==$cluster and .role==$role' "$root/ownership.json" >/dev/null
  if ! cmp -s /run/xray-cascade-ownership.new "$root/ownership.json"; then install -m 0600 /run/xray-cascade-ownership.new "$root/ownership.json"; fi
else
  install -m 0600 /run/xray-cascade-ownership.new "$root/ownership.json"
fi
mkdir "$txdir"
cd /usr/local/x-ui
token=$(./x-ui setting -tokenName xray-cascade-transaction -tokenScope admin -getApiToken | sed -n 's/^apiToken: //p' | tail -n 1)
test -n "$token"
printf 'Authorization: Bearer %%s\n' "$token" > /run/xray-cascade-tx-header
unset token
api=%s://127.0.0.1:%d%sapi
curl --fail-with-body -sS %s -H @/run/xray-cascade-tx-header "$api/server/getDb" -o "$txdir/x-ui.db"
test -s "$txdir/x-ui.db"
db_sha=$(sha256sum "$txdir/x-ui.db" | awk '{print $1}')
snapshot_file() {
  source=$1 name=$2
  if [ -e "$source" ]; then
    test -f "$source"
    test ! -L "$source"
    cp -p "$source" "$txdir/$name"
    printf present > "$txdir/$name.state"
  else
    printf absent > "$txdir/$name.state"
  fi
}
while IFS='|' read -r source name; do
  snapshot_file "$source" "$name"
done <<'XCASCADE_FILES'
/usr/local/x-ui/bin/roscom-geoip.dat|roscom-geoip.dat
/usr/local/x-ui/bin/roscom-geosite.dat|roscom-geosite.dat
/etc/x-ui/subscription.crt|subscription.crt
/etc/x-ui/subscription.key|subscription.key
/etc/x-ui/panel.crt|panel.crt
/etc/x-ui/panel.key|panel.key
/etc/x-ui/panel-ca.crt|panel-ca.crt
/etc/x-ui/panel-ca.key|panel-ca.key
/etc/systemd/system/x-ui.service|x-ui.service
/etc/systemd/system/x-ui.service.d/10-xui-sandbox.conf|x-ui-sandbox.conf
/etc/ufw/user.rules|ufw-user.rules
/etc/ufw/user6.rules|ufw-user6.rules
/usr/local/share/ca-certificates/xray-cascade-exit.crt|exit-trust.crt
/etc/x-ui/exit-node-ca.crt|exit-node-ca.crt
XCASCADE_FILES
snapshot_file "$root/operator/bootstrap-credentials-$role" bootstrap-credentials
jq -n --arg id "$tx" --arg cluster "$cluster" --arg role "$role" --arg sha "$db_sha" --arg created "$(date -u +%%Y-%%m-%%dT%%H:%%M:%%SZ)" '{schema:1,id:$id,cluster:$cluster,role:$role,status:"pending",createdAt:$created,databaseSHA256:$sha}' > "$txdir/metadata.json"
chmod 0600 "$txdir"/*
begin_ok=true
echo "3XUI_TRANSACTION_SNAPSHOT_READY role=$role"
`, StateRoot, id, cluster, role, payload, endpoint.Scheme, endpoint.port(), endpoint.BasePath, endpoint.CurlTLS), nil
}

func CommitScript(cluster, role, id string, endpoint Endpoint) (string, error) {
	if err := validate(cluster, role, id, endpoint); err != nil {
		return "", err
	}
	return fmt.Sprintf(`set -eu
umask 077
root=%s
tx=%s
role=%s
txdir="$root/transactions/$tx"
test "$(cat "$root/lock/id")" = "$tx"
jq -e --arg cluster %s --arg role %s '.schema==1 and .cluster==$cluster and .role==$role and .status=="pending"' "$txdir/metadata.json" >/dev/null
jq '.status="committed" | .committedAt=(now|todateiso8601)' "$txdir/metadata.json" > "$txdir/metadata.new"
chmod 0600 "$txdir/metadata.new"
mv -f "$txdir/metadata.new" "$txdir/metadata.json"
rm -rf "$root/lock"
echo "3XUI_TRANSACTION_COMMITTED role=%s"
`, StateRoot, id, role, cluster, role, role), nil
}

// RollbackScript restores the exact database through 3x-ui's validated import
// endpoint, restores/removes only files declared in the ownership manifest and
// then waits for the scheduled panel restart.
func RollbackScript(cluster, role, id string, endpoint Endpoint) (string, error) {
	if err := validate(cluster, role, id, endpoint); err != nil {
		return "", err
	}
	return fmt.Sprintf(`set -eu
umask 077
stage=init
root=%s
tx=%s
role=%s
txdir="$root/transactions/$tx"
if [ ! -d "$txdir" ]; then echo "3XUI_TRANSACTION_ROLLBACK_SKIPPED role=%s"; exit 0; fi
jq -e --arg cluster %s --arg role %s '.schema==1 and .cluster==$cluster and .role==$role and (.status=="pending" or .status=="committed")' "$txdir/metadata.json" >/dev/null
expected=$(jq -r '.databaseSHA256' "$txdir/metadata.json")
actual=$(sha256sum "$txdir/x-ui.db" | awk '{print $1}')
test "$actual" = "$expected"
cd /usr/local/x-ui
token=$(./x-ui setting -tokenName xray-cascade-transaction -tokenScope admin -getApiToken | sed -n 's/^apiToken: //p' | tail -n 1)
test -n "$token"
printf 'Authorization: Bearer %%s\n' "$token" > /run/xray-cascade-tx-header
unset token
cleanup_rollback() {
  status=$?
  rm -f /run/xray-cascade-tx-header /run/xray-cascade-import.json /run/xray-cascade-rollback-*.json
  if [ "$status" -ne 0 ]; then echo "3XUI_TRANSACTION_ROLLBACK_FAILED role=%s stage=$stage" >&2; fi
  exit "$status"
}
trap cleanup_rollback EXIT INT TERM
api=%s://127.0.0.1:%d%sapi
stage=wait-before-import
ready=false
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
  if curl --fail -sS %s -H @/run/xray-cascade-tx-header "$api/server/getDb" -o /dev/null 2>/dev/null; then ready=true; break; fi
  sleep 1
done
test "$ready" = true
stage=import-database
old_pid=$(pgrep -xo x-ui 2>/dev/null || true)
curl --fail-with-body -sS %s -H @/run/xray-cascade-tx-header -F keepHostSettings=false -F "db=@$txdir/x-ui.db" "$api/server/importDB" > /run/xray-cascade-import.json
jq -e '.success==true' /run/xray-cascade-import.json >/dev/null
stage=restore-managed-files
restore_file() {
  destination=$1 name=$2
  if [ "$(cat "$txdir/$name.state")" = present ]; then
    install -d -m 0755 "$(dirname "$destination")"
    cp -p "$txdir/$name" "$destination"
  else
    rm -f "$destination"
  fi
}
while IFS='|' read -r destination name; do
  restore_file "$destination" "$name"
done <<'XCASCADE_FILES'
/usr/local/x-ui/bin/roscom-geoip.dat|roscom-geoip.dat
/usr/local/x-ui/bin/roscom-geosite.dat|roscom-geosite.dat
/etc/x-ui/subscription.crt|subscription.crt
/etc/x-ui/subscription.key|subscription.key
/etc/x-ui/panel.crt|panel.crt
/etc/x-ui/panel.key|panel.key
/etc/x-ui/panel-ca.crt|panel-ca.crt
/etc/x-ui/panel-ca.key|panel-ca.key
/etc/systemd/system/x-ui.service|x-ui.service
/etc/systemd/system/x-ui.service.d/10-xui-sandbox.conf|x-ui-sandbox.conf
/etc/ufw/user.rules|ufw-user.rules
/etc/ufw/user6.rules|ufw-user6.rules
/usr/local/share/ca-certificates/xray-cascade-exit.crt|exit-trust.crt
/etc/x-ui/exit-node-ca.crt|exit-node-ca.crt
XCASCADE_FILES
restore_file "$root/operator/bootstrap-credentials-$role" bootstrap-credentials
if command -v update-ca-certificates >/dev/null 2>&1; then update-ca-certificates >/dev/null; fi
stage=request-explicit-restart
token_name=xray-cascade-rollback-$(openssl rand -hex 8)
token=$(./x-ui setting -tokenName "$token_name" -tokenScope admin -getApiToken | sed -n 's/^apiToken: //p' | tail -n 1)
test -n "$token"
printf 'Authorization: Bearer %%s\n' "$token" > /run/xray-cascade-tx-header
unset token
curl --fail-with-body -sS %s -H @/run/xray-cascade-tx-header -X POST "$api/setting/restartPanel" > /run/xray-cascade-rollback-restart.json
jq -e '.success==true' /run/xray-cascade-rollback-restart.json >/dev/null
stage=wait-after-import
restarted=false
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
  new_pid=$(pgrep -xo x-ui 2>/dev/null || true)
  if [ -n "$old_pid" ] && [ "$new_pid" != "$old_pid" ]; then restarted=true; break; fi
  if ! curl --fail -sS %s "%s://127.0.0.1:%d%s" -o /dev/null 2>/dev/null; then restarted=true; break; fi
  sleep 1
done
test "$restarted" = true
ready=false
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
  sleep 1
  if curl --fail -sS %s "%s://127.0.0.1:%d%s" -o /dev/null 2>/dev/null; then ready=true; break; fi
done
test "$ready" = true
stage=remove-ephemeral-token
curl --fail-with-body -sS %s -H @/run/xray-cascade-tx-header "$api/setting/apiTokens" > /run/xray-cascade-rollback-tokens.json
token_id=$(jq -r --arg name "$token_name" '.obj[]|select(.name==$name)|.id' /run/xray-cascade-rollback-tokens.json)
test -n "$token_id"
printf '{"expectedScope":"admin"}' > /run/xray-cascade-rollback-delete-request.json
curl --fail-with-body -sS %s -H @/run/xray-cascade-tx-header -H 'Content-Type: application/json' -X POST --data @/run/xray-cascade-rollback-delete-request.json "$api/setting/apiTokens/delete/$token_id" > /run/xray-cascade-rollback-delete.json
jq -e '.success==true' /run/xray-cascade-rollback-delete.json >/dev/null
stage=finalize
jq '.status="rolled_back" | .rolledBackAt=(now|todateiso8601)' "$txdir/metadata.json" > "$txdir/metadata.new"
chmod 0600 "$txdir/metadata.new"
mv -f "$txdir/metadata.new" "$txdir/metadata.json"
if [ -f "$root/lock/id" ] && [ "$(cat "$root/lock/id")" = "$tx" ]; then rm -rf "$root/lock"; fi
echo "3XUI_TRANSACTION_ROLLED_BACK role=%s"
trap - EXIT
`, StateRoot, id, role, role, cluster, role, role, endpoint.Scheme, endpoint.port(), endpoint.BasePath, endpoint.CurlTLS, endpoint.CurlTLS, endpoint.CurlTLS, endpoint.CurlTLS, endpoint.Scheme, endpoint.port(), endpoint.BasePath, endpoint.CurlTLS, endpoint.Scheme, endpoint.port(), endpoint.BasePath, endpoint.CurlTLS, endpoint.CurlTLS, role), nil
}
