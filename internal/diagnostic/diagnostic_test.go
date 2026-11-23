// SPDX-License-Identifier: GPL-3.0-only

package diagnostic

import (
	"encoding/base64"
	"os/exec"
	"strings"
	"testing"

	"github.com/b1ts23/xray-easy-cascade/internal/inventory"
)

func TestScriptSyntaxAndRedaction(t *testing.T) {
	inv := inventory.Default()
	inv.Transport.ClientAlternatives = []inventory.ClientAlternative{{Kind: "reality-xhttp", Port: 8443}, {Kind: "reality-xhttp-pq", Port: 10443}, {Kind: "reality-grpc", Port: 9443}}
	inv.Certificates.SubscriptionTLS = "acme-ip"
	inv.Transport.Hysteria2 = inventory.Hysteria2{Enabled: true, Port: 443}
	script, err := Script("entry", inv)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", "-n")
	cmd.Stdin = strings.NewReader(script)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("syntax: %v: %s", err, output)
	}
	for _, forbidden := range []string{"client_id", "privateKey", "subId", "cat $token", "echo $token"} {
		if strings.Contains(script, forbidden) {
			t.Fatalf("diagnostic script exposes %q", forbidden)
		}
	}
	expectedBase64 := base64.StdEncoding.EncodeToString([]byte(`["xhttp","xhttp-pq","grpc","hysteria2"]`))
	for _, required := range []string{"xhttp=$(listener 8443)", "xhttp_pq=$(listener 10443)", "grpc=$(listener 9443)", "hysteria2=$(udp_listener 443)", "expected_b64=" + expectedBase64, `--argjson expected "$expected"`} {
		if !strings.Contains(script, required) {
			t.Fatalf("diagnostic script missing %q", required)
		}
	}
}

func TestProblemsRequireHysteria2UDPListener(t *testing.T) {
	status := Status{Schema: 1, Role: "entry", PanelReady: true, XrayRunning: true, InboundCount: 2,
		ExpectedAlternatives: []string{"hysteria2"}, Listeners: Listeners{Client: true, Subscription: true},
		Node:         Node{Present: true, Status: "online", TLSVerifyMode: "mtls"},
		Subscription: Subscription{Enabled: true, Routing: true, HappDetect: true}}
	problems := status.Problems()
	if len(problems) != 1 || !strings.Contains(problems[0], "Hysteria 2") {
		t.Fatalf("unexpected problems: %v", problems)
	}
}

func TestProblemsRequireConfiguredAlternativeListeners(t *testing.T) {
	status := Status{
		Schema: 1, Role: "entry", PanelReady: true, XrayRunning: true, InboundCount: 3,
		ExpectedAlternatives: []string{"xhttp", "grpc"},
		Listeners:            Listeners{Client: true, XHTTP: true, Subscription: true},
		Node:                 Node{Present: true, Status: "online", TLSVerifyMode: "mtls"},
		Subscription:         Subscription{Enabled: true, Routing: true, HappDetect: true},
	}
	problems := status.Problems()
	if len(problems) != 1 || !strings.Contains(problems[0], "gRPC") {
		t.Fatalf("unexpected alternative listener problems: %v", problems)
	}
}

func TestProblemsRequirePQXHTTPListener(t *testing.T) {
	status := Status{
		Schema: 1, Role: "entry", PanelReady: true, XrayRunning: true, InboundCount: 2,
		ExpectedAlternatives: []string{"xhttp-pq"},
		Listeners:            Listeners{Client: true, Subscription: true},
		Node:                 Node{Present: true, Status: "online", TLSVerifyMode: "mtls"},
		Subscription:         Subscription{Enabled: true, Routing: true, HappDetect: true},
	}
	problems := status.Problems()
	if len(problems) != 1 || !strings.Contains(problems[0], "PQ XHTTP") {
		t.Fatalf("unexpected PQ listener problems: %v", problems)
	}
}

func TestParseAndProblems(t *testing.T) {
	raw := `{"schema":1,"role":"entry","panelReady":true,"xrayRunning":true,"inboundCount":1,"listeners":{"client":true,"subscription":true,"interserver":false},"node":{"present":true,"status":"online","tlsVerifyMode":"mtls","apiTokenPresent":false},"subscription":{"enabled":true,"routing":true,"happDetect":true}}`
	status, err := Parse(marker+base64.StdEncoding.EncodeToString([]byte(raw)), "entry")
	if err != nil {
		t.Fatal(err)
	}
	if problems := status.Problems(); len(problems) != 0 {
		t.Fatalf("healthy status has problems: %v", problems)
	}
	status.Node.APITokenPresent = true
	if problems := status.Problems(); len(problems) != 1 || !strings.Contains(problems[0], "API token") {
		t.Fatalf("unexpected problems: %v", problems)
	}
}
