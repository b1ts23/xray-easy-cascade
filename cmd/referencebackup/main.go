// SPDX-License-Identifier: GPL-3.0-only

// Command referencebackup creates an age-encrypted, off-host backup of the
// two explicitly named reference nodes. It is an internal operator tool, not
// part of the public vpnctl surface.
package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/b1ts23/xray-cascade/internal/backup"
)

type node struct {
	role, host, port, user, sshPassword string
}

func main() {
	var envPath, identityPath, outputPath string
	flag.StringVar(&envPath, "env", "../cascade-access.env", "reference access dotenv")
	flag.StringVar(&identityPath, "identity", ".cascade/reference-backup-age-identity.txt", "age identity")
	flag.StringVar(&outputPath, "output", "", "new encrypted backup path")
	flag.Parse()
	if flag.NArg() != 0 || outputPath == "" {
		fatal(errors.New("--output is required and positional arguments are not accepted"))
	}
	values, err := parseDotenv(envPath)
	if err != nil {
		fatal(err)
	}
	nodes := []node{
		makeNode("entry", "RU", values),
		makeNode("exit", "NL", values),
	}
	for _, n := range nodes {
		if err := n.validate(); err != nil {
			fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Dir(identityPath), 0o700); err != nil {
		fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o700); err != nil {
		fatal(err)
	}
	recipient := ""
	if _, err := os.Lstat(identityPath); errors.Is(err, os.ErrNotExist) {
		recipient, err = backup.GenerateIdentity(identityPath)
		if err != nil {
			fatal(err)
		}
	} else if err != nil {
		fatal(err)
	} else {
		recipient, err = backup.Recipient(identityPath)
		if err != nil {
			fatal(err)
		}
	}
	exports := make(map[string][]byte, 2)
	for _, n := range nodes {
		raw, err := exportNode(n)
		if err != nil {
			fatal(fmt.Errorf("export %s: %w", n.role, err))
		}
		exports[n.role] = raw
		fmt.Printf("3XUI_REFERENCE_BACKUP_EXPORT_READY role=%s\n", n.role)
	}
	if err := backup.Create(outputPath, recipient, "reference-cascade", exports["entry"], exports["exit"], time.Now()); err != nil {
		fatal(err)
	}
	manifest, err := backup.Verify(outputPath, identityPath)
	if err != nil {
		fatal(err)
	}
	abs, err := filepath.Abs(outputPath)
	if err != nil {
		fatal(err)
	}
	fmt.Printf("3XUI_REFERENCE_BACKUP_READY output=%s members=%d encryption=age\n", abs, len(manifest.Members))
}

func parseDotenv(path string) (map[string]string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	values := make(map[string]string)
	for _, line := range strings.Split(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return nil, errors.New("invalid dotenv line")
		}
		values[strings.TrimSpace(key)] = value
	}
	return values, nil
}

func makeNode(role, prefix string, values map[string]string) node {
	host := values[prefix+"_SSH_HOST"]
	if host == "" {
		host = values[prefix+"_IPV4"]
	}
	return node{
		role: role, host: host, port: values[prefix+"_SSH_PORT"], user: values[prefix+"_SSH_USER"],
		sshPassword: values[prefix+"_SSH_PASSWORD"],
	}
}

func (n node) validate() error {
	for name, value := range map[string]string{
		"host": n.host, "port": n.port, "SSH user": n.user, "SSH password": n.sshPassword,
	} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s %s is missing", n.role, name)
		}
	}
	if n.role != "entry" && n.role != "exit" {
		return errors.New("unsupported backup role")
	}
	return nil
}

func exportNode(n node) ([]byte, error) {
	script := exportScript(n)
	cmd := exec.Command("sshpass", "-e", "ssh", "-p", n.port, "-o", "BatchMode=no", "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=10", n.user+"@"+n.host, "bash", "-s")
	cmd.Env = append(os.Environ(), "SSHPASS="+n.sshPassword)
	cmd.Stdin = strings.NewReader(script)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("SSH export failed (stderr bytes=%d): %w", stderr.Len(), err)
	}
	if stdout.Len() == 0 || int64(stdout.Len()) > backup.MaxNodeExportBytes {
		return nil, fmt.Errorf("node archive size %d is outside safety limits", stdout.Len())
	}
	return stdout.Bytes(), nil
}

func exportScript(n node) string {
	return fmt.Sprintf(`set -eu
umask 077
role=%s
work=$(mktemp -d /run/xray-cascade-reference-export-XXXXXX)
token_name=xray-cascade-reference-backup-$(openssl rand -hex 8)
token_created=false
token_deleted=false
api=
cleanup_token() {
  test "$token_created" = true || return 0
  test "$token_deleted" = false || return 0
  test -n "$api" || return 1
  test -s "$work/api-header" || return 1
  curl --fail-with-body -k -sS -H @"$work/api-header" "$api/setting/apiTokens" > "$work/cleanup-tokens.json"
  token_id=$(jq -r --arg name "$token_name" '.obj[]?|select(.name==$name and .scope=="admin")|.id' "$work/cleanup-tokens.json" | head -n 1)
  test -n "$token_id"
  printf '{"expectedScope":"admin"}' > "$work/cleanup-delete.json"
  curl --fail-with-body -k -sS -H @"$work/api-header" -H 'Content-Type: application/json' -X POST --data @"$work/cleanup-delete.json" "$api/setting/apiTokens/delete/$token_id" > "$work/cleanup-result.json"
  jq -e '.success==true' "$work/cleanup-result.json" >/dev/null
  token_deleted=true
}
cleanup() { status=$?; cleanup_token >/dev/null 2>&1 || true; rm -rf "$work"; exit "$status"; }
trap cleanup EXIT INT TERM
read_setting() { python3 - "$1" <<'PY'
import sqlite3, sys
con=sqlite3.connect('file:/etc/x-ui/x-ui.db?mode=ro', uri=True)
row=con.execute('select value from settings where key=?',(sys.argv[1],)).fetchone()
if not row: raise SystemExit(1)
print(row[0], end='')
PY
}
panel_port=$(read_setting webPort)
panel_base=$(read_setting webBasePath)
case "$panel_port" in ''|*[!0-9]*) exit 1;; esac
case "$panel_base" in /*/) ;; *) exit 1;; esac
api="https://127.0.0.1:${panel_port}${panel_base}panel/api"
cd /usr/local/x-ui
token=$(./x-ui setting -tokenName "$token_name" -tokenScope admin -getApiToken | sed -n 's/^apiToken: //p' | tail -n 1)
test -n "$token"
token_created=true
printf 'Authorization: Bearer %%s\n' "$token" > "$work/api-header"
unset token
curl --fail-with-body -k -sS -H @"$work/api-header" "$api/server/getDb" -o "$work/x-ui.db"
test -s "$work/x-ui.db"
cleanup_token
python3 - "$work/x-ui.db" "$token_name" <<'PY'
import sqlite3, sys
con=sqlite3.connect(sys.argv[1])
name=sys.argv[2]
removed=0
for (table,) in con.execute("select name from sqlite_master where type='table'"):
    if table.replace('_','').lower() != 'apitokens':
        continue
    columns=[row[1] for row in con.execute('pragma table_info("'+table.replace('"','""')+'")')]
    if 'name' not in columns:
        continue
    before=con.total_changes
    con.execute('delete from "'+table.replace('"','""')+'" where name=?',(name,))
    removed += con.total_changes-before
con.commit()
if removed != 1:
    raise SystemExit('backup token sanitization failed')
PY
rm -f "$work/api-header" "$work/cleanup-"*.json "$work/cleanup-result.json" 2>/dev/null || true
copy_file() { source=$1 name=$2; if [ -f "$source" ] && [ ! -L "$source" ]; then cp -p "$source" "$work/$name"; fi; }
copy_file /var/lib/xray-cascade/ownership.json ownership.json
copy_file /etc/x-ui/node_token_key.json node_token_key.json
copy_file /etc/x-ui/subscription.crt subscription.crt
copy_file /etc/x-ui/subscription.key subscription.key
copy_file /etc/x-ui/panel.crt panel.crt
copy_file /etc/x-ui/panel.key panel.key
copy_file /etc/x-ui/panel-ca.crt panel-ca.crt
copy_file /etc/x-ui/panel-ca.key panel-ca.key
copy_file /etc/x-ui/exit-node-ca.crt exit-node-ca.crt
copy_file /usr/local/share/ca-certificates/xray-cascade-exit.crt exit-trust.crt
copy_file /usr/local/x-ui/bin/geoip_RU.dat roscom-geoip.dat
copy_file /usr/local/x-ui/bin/geosite_RU.dat roscom-geosite.dat
copy_file /etc/systemd/system/x-ui.service x-ui.service
copy_file /etc/systemd/system/x-ui.service.d/10-xui-sandbox.conf x-ui-sandbox.conf
copy_file /etc/ufw/user.rules ufw-user.rules
copy_file /etc/ufw/user6.rules ufw-user6.rules
jq -n --arg role "$role" --arg created "$(date -u +%%Y-%%m-%%dT%%H:%%M:%%SZ)" '{schema:1,role:$role,createdAt:$created}' > "$work/node-manifest.json"
(cd "$work" && sha256sum ./* > checksums.sha256)
tar -C "$work" -czf - .
`, n.role)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "reference backup failed:", err)
	os.Exit(1)
}
