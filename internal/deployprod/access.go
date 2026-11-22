// SPDX-License-Identifier: GPL-3.0-only

package deployprod

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/b1ts23/xray-easy-cascade/internal/access"
	"github.com/b1ts23/xray-easy-cascade/internal/inventory"
	"github.com/b1ts23/xray-easy-cascade/internal/production"
)

const handoffPrefix = "3XUI_PRODUCTION_HANDOFF\t"

type nodeHandoff struct {
	Username string `json:"username"`
	Password string `json:"password"`
	SubPath  string `json:"subPath,omitempty"`
	SubID    string `json:"subId,omitempty"`
}

func handoffScript(role string, panelPort int) string {
	entryPart := ""
	if role == "entry" {
		entryPart = fmt.Sprintf(`
token=$(./x-ui setting -tokenName xray-cascade-handoff -tokenScope admin -getApiToken | sed -n 's/^apiToken: //p' | tail -n 1)
test -n "$token"
printf 'Authorization: Bearer %%s\n' "$token" > /run/xray-cascade-handoff-header
trap 'rm -f /run/xray-cascade-handoff-header /run/xray-cascade-handoff-inbounds.json /run/xray-cascade-handoff-settings.json /run/xray-cascade-handoff.json' EXIT INT TERM
api=https://127.0.0.1:%d/entry/panel/api
curl --fail-with-body --insecure -sS -H @/run/xray-cascade-handoff-header "$api/inbounds/list" > /run/xray-cascade-handoff-inbounds.json
curl --fail-with-body --insecure -sS -H @/run/xray-cascade-handoff-header -X POST "$api/setting/all" > /run/xray-cascade-handoff-settings.json
sub_id=$(jq -r '.obj[]|select(.remark=="xray-cascade-client")|.settings|fromjson|.clients[0].subId' /run/xray-cascade-handoff-inbounds.json)
sub_path=$(jq -r '.obj.subPath' /run/xray-cascade-handoff-settings.json)
test -n "$sub_id"
`, panelPort)
	} else {
		entryPart = `sub_id=
sub_path=
trap 'rm -f /run/xray-cascade-handoff.json' EXIT INT TERM
`
	}
	return fmt.Sprintf(`set -eu
umask 077
cd /usr/local/x-ui
credentials=%s/operator/bootstrap-credentials-%s
test -f "$credentials"
username=$(sed -n 's/^username=//p' "$credentials")
password=$(sed -n 's/^password=//p' "$credentials")
test -n "$username"
test -n "$password"
%s
jq -n --arg username "$username" --arg password "$password" --arg subPath "$sub_path" --arg subId "$sub_id" '{username:$username,password:$password,subPath:$subPath,subId:$subId}' > /run/xray-cascade-handoff.json
printf '3XUI_PRODUCTION_HANDOFF\t'
base64 -w0 /run/xray-cascade-handoff.json
printf '\n'
`, production.StateRoot, role, entryPart)
}

func parseNodeHandoff(raw string) (nodeHandoff, error) {
	value := ""
	for _, line := range strings.Split(raw, "\n") {
		if !strings.HasPrefix(line, handoffPrefix) {
			continue
		}
		if value != "" {
			return nodeHandoff{}, errors.New("node returned more than one handoff")
		}
		value = strings.TrimPrefix(line, handoffPrefix)
	}
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(decoded) == 0 || len(decoded) > 64*1024 {
		return nodeHandoff{}, errors.New("node returned an invalid handoff")
	}
	var result nodeHandoff
	if err := json.Unmarshal(decoded, &result); err != nil {
		return nodeHandoff{}, errors.New("node returned malformed handoff JSON")
	}
	if strings.TrimSpace(result.Username) == "" || strings.TrimSpace(result.Password) == "" || strings.ContainsAny(result.Username+result.Password, "\r\n\t") {
		return nodeHandoff{}, errors.New("node returned invalid panel credentials")
	}
	return result, nil
}

// CollectAccess retrieves only the operator-facing panel credentials and
// subscription identifier. API and node tokens never enter the handoff.
func CollectAccess(ctx context.Context, runner Runner, inv inventory.Inventory) (access.Summary, error) {
	collect := func(role string, server inventory.Server) (nodeHandoff, error) {
		runCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		raw, err := runner.Run(runCtx, target(server), handoffScript(role, inv.Panel.Port))
		if err != nil {
			return nodeHandoff{}, fmt.Errorf("collect %s handoff: %w", role, err)
		}
		return parseNodeHandoff(raw)
	}
	entry, err := collect("entry", inv.Entry)
	if err != nil {
		return access.Summary{}, err
	}
	exit, err := collect("exit", inv.Exit)
	if err != nil {
		return access.Summary{}, err
	}
	if !strings.HasPrefix(entry.SubPath, "/") || strings.TrimSpace(entry.SubID) == "" {
		return access.Summary{}, errors.New("entry returned an invalid subscription endpoint")
	}
	summary := access.Summary{
		Cluster: inv.Cluster.Name,
		Entry: access.Panel{Role: "entry", Username: entry.Username, Password: entry.Password, Port: inv.Panel.Port,
			WebBasePath: "/entry/panel/", AccessURL: "http://127.0.0.1:12053/entry/panel/",
			OpenCommand: "vpnctl panel entry --inventory inventory.yml"},
		Exit: access.Panel{Role: "exit", Username: exit.Username, Password: exit.Password, Port: inv.Panel.Port,
			WebBasePath: "/exit/panel/", AccessURL: "https://127.0.0.1:12054/exit/panel/",
			OpenCommand: "vpnctl panel exit --inventory inventory.yml"},
		HappSubscription: fmt.Sprintf("https://%s:%d%s%s", inv.Entry.CascadeAddress, inv.Subscription.Port, entry.SubPath, entry.SubID),
	}
	if err := summary.Validate(); err != nil {
		return access.Summary{}, err
	}
	return summary, nil
}
