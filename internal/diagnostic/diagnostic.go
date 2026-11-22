// SPDX-License-Identifier: GPL-3.0-only

// Package diagnostic builds redacted, read-only runtime checks for the two
// managed 3x-ui roles. It never returns credentials or subscription URLs.
package diagnostic

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/b1ts23/xray-easy-cascade/internal/inventory"
)

const marker = "3XUI_STATUS\t"

type Listeners struct {
	Client       bool `json:"client"`
	XHTTP        bool `json:"xhttp"`
	XHTTPPQ      bool `json:"xhttpPq"`
	GRPC         bool `json:"grpc"`
	Hysteria2    bool `json:"hysteria2"`
	Subscription bool `json:"subscription"`
	Interserver  bool `json:"interserver"`
}

type Node struct {
	Present         bool   `json:"present"`
	Status          string `json:"status"`
	TLSVerifyMode   string `json:"tlsVerifyMode"`
	APITokenPresent bool   `json:"apiTokenPresent"`
}

type Subscription struct {
	Enabled    bool `json:"enabled"`
	Routing    bool `json:"routing"`
	HappDetect bool `json:"happDetect"`
}

type Status struct {
	Schema               int          `json:"schema"`
	Role                 string       `json:"role"`
	PanelReady           bool         `json:"panelReady"`
	XrayRunning          bool         `json:"xrayRunning"`
	InboundCount         int          `json:"inboundCount"`
	ExpectedAlternatives []string     `json:"expectedAlternatives,omitempty"`
	Listeners            Listeners    `json:"listeners"`
	Node                 Node         `json:"node"`
	Subscription         Subscription `json:"subscription"`
}

func Script(role string, inv inventory.Inventory) (string, error) {
	if role != "entry" && role != "exit" {
		return "", errors.New("diagnostic role must be entry or exit")
	}
	scheme, basePath, curlTLS := "http", "/entry/panel/", ""
	if role == "exit" {
		scheme, basePath, curlTLS = "https", "/exit/panel/", "-k"
	}
	xhttpPort := inv.ClientAlternativePort("reality-xhttp")
	xhttpPQPort := inv.ClientAlternativePort("reality-xhttp-pq")
	grpcPort := inv.ClientAlternativePort("reality-grpc")
	expectedAlternatives := []string{}
	if xhttpPort > 0 {
		expectedAlternatives = append(expectedAlternatives, "xhttp")
	}
	if xhttpPQPort > 0 {
		expectedAlternatives = append(expectedAlternatives, "xhttp-pq")
	}
	if grpcPort > 0 {
		expectedAlternatives = append(expectedAlternatives, "grpc")
	}
	hysteriaPort := 0
	if inv.Transport.Hysteria2.Enabled {
		hysteriaPort = inv.Transport.Hysteria2.Port
		expectedAlternatives = append(expectedAlternatives, "hysteria2")
	}
	expectedRaw, err := json.Marshal(expectedAlternatives)
	if err != nil {
		return "", fmt.Errorf("encode expected alternatives: %w", err)
	}
	return fmt.Sprintf(`set -eu
umask 077
role=%s
work=$(mktemp -d /run/xray-cascade-status-XXXXXX)
cleanup() { rm -rf "$work"; }
trap cleanup EXIT INT TERM
cd /usr/local/x-ui
token=$(./x-ui setting -tokenName xray-cascade-e2e -tokenScope admin -getApiToken | sed -n 's/^apiToken: //p' | tail -n 1)
test -n "$token"
printf 'Authorization: Bearer %%s\n' "$token" > "$work/header"
unset token
api=%s://127.0.0.1:2053%sapi
curl --fail-with-body -sS %s -H @"$work/header" "$api/inbounds/list" > "$work/inbounds.json"
jq -e '.success==true and (.obj|type=="array")' "$work/inbounds.json" >/dev/null
inbounds=$(jq '.obj|length' "$work/inbounds.json")
xray=false
# Linux comm is limited to 15 bytes, so xray-linux-amd64 appears as xray-linux-amd6.
if pgrep -x xray-linux-amd6 >/dev/null; then xray=true; fi
listener() { if [ "$1" -gt 0 ] && ss -H -ltn "sport = :$1" 2>/dev/null | grep -q .; then printf true; else printf false; fi; }
udp_listener() { if [ "$1" -gt 0 ] && ss -H -lun "sport = :$1" 2>/dev/null | grep -q .; then printf true; else printf false; fi; }
client=$(listener %d)
xhttp=$(listener %d)
xhttp_pq=$(listener %d)
grpc=$(listener %d)
hysteria2=$(udp_listener %d)
subscription=$(listener %d)
interserver=$(listener %d)
node='{"present":false,"status":"","tlsVerifyMode":"","apiTokenPresent":false}'
sub='{"enabled":false,"routing":false,"happDetect":false}'
if [ "$role" = entry ]; then
  curl --fail-with-body -sS -H @"$work/header" "$api/nodes/list" > "$work/nodes.json"
  jq -e '.success==true' "$work/nodes.json" >/dev/null
  node=$(jq -c '([.obj[]? | select(.name=="lab-exit")][0] // null) as $n | if $n==null then {present:false,status:"",tlsVerifyMode:"",apiTokenPresent:false} else {present:true,status:($n.status // ""),tlsVerifyMode:($n.tlsVerifyMode // ""),apiTokenPresent:($n.hasApiToken // false)} end' "$work/nodes.json")
  curl --fail-with-body -sS -H @"$work/header" -X POST "$api/setting/all" > "$work/settings.json"
  jq -e '.success==true' "$work/settings.json" >/dev/null
  sub=$(jq -c '{enabled:(.obj.subEnable // false),routing:(.obj.subEnableRouting // false),happDetect:(.obj.subHappAutoDetect // false)}' "$work/settings.json")
fi
jq -cn --arg role "$role" --argjson xray "$xray" --argjson inbounds "$inbounds" --argjson expected '%s' --argjson client "$client" --argjson xhttp "$xhttp" --argjson xhttpPq "$xhttp_pq" --argjson grpc "$grpc" --argjson hysteria2 "$hysteria2" --argjson subscription "$subscription" --argjson interserver "$interserver" --argjson node "$node" --argjson sub "$sub" '{schema:1,role:$role,panelReady:true,xrayRunning:$xray,inboundCount:$inbounds,expectedAlternatives:$expected,listeners:{client:$client,xhttp:$xhttp,xhttpPq:$xhttpPq,grpc:$grpc,hysteria2:$hysteria2,subscription:$subscription,interserver:$interserver},node:$node,subscription:$sub}' > "$work/status.json"
printf '3XUI_STATUS\t'
base64 -w0 "$work/status.json"
printf '\n'
`, role, scheme, basePath, curlTLS, inv.Transport.ClientPort, xhttpPort, xhttpPQPort, grpcPort, hysteriaPort, inv.Subscription.Port, inv.Transport.InterserverPort, string(expectedRaw)), nil
}

func Parse(output, expectedRole string) (Status, error) {
	var encoded string
	for _, line := range strings.Split(output, "\n") {
		if strings.HasPrefix(line, marker) {
			if encoded != "" {
				return Status{}, errors.New("remote returned duplicate status markers")
			}
			encoded = strings.TrimPrefix(line, marker)
		}
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(raw) == 0 {
		return Status{}, errors.New("remote did not return a valid status marker")
	}
	var status Status
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&status); err != nil {
		return Status{}, fmt.Errorf("parse remote status: %w", err)
	}
	if status.Schema != 1 || status.Role != expectedRole || (status.Role != "entry" && status.Role != "exit") {
		return Status{}, errors.New("remote status identity is invalid")
	}
	return status, nil
}

func (status Status) Problems() []string {
	var problems []string
	if !status.PanelReady {
		problems = append(problems, "panel API is not ready")
	}
	if !status.XrayRunning {
		problems = append(problems, "Xray process is not running")
	}
	if status.InboundCount < 1 {
		problems = append(problems, "no managed inbound is present")
	}
	if status.Role == "entry" {
		if !status.Listeners.Client {
			problems = append(problems, "client listener is absent")
		}
		if !status.Listeners.Subscription {
			problems = append(problems, "subscription listener is absent")
		}
		for _, alternative := range status.ExpectedAlternatives {
			switch alternative {
			case "xhttp":
				if !status.Listeners.XHTTP {
					problems = append(problems, "XHTTP client listener is absent")
				}
			case "xhttp-pq":
				if !status.Listeners.XHTTPPQ {
					problems = append(problems, "PQ XHTTP client listener is absent")
				}
			case "grpc":
				if !status.Listeners.GRPC {
					problems = append(problems, "gRPC client listener is absent")
				}
			case "hysteria2":
				if !status.Listeners.Hysteria2 {
					problems = append(problems, "Hysteria 2 UDP client listener is absent")
				}
			default:
				problems = append(problems, "unknown expected client transport "+alternative)
			}
		}
		if !status.Node.Present || status.Node.Status != "online" {
			problems = append(problems, "exit node is not online")
		}
		if status.Node.TLSVerifyMode != "mtls" {
			problems = append(problems, "exit node is not using mTLS")
		}
		if status.Node.APITokenPresent {
			problems = append(problems, "exit node still has an API token")
		}
		if !status.Subscription.Enabled || !status.Subscription.Routing || !status.Subscription.HappDetect {
			problems = append(problems, "HAPP routed subscription is not fully enabled")
		}
	} else if !status.Listeners.Interserver {
		problems = append(problems, "interserver listener is absent")
	}
	return problems
}
