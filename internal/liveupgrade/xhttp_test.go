// SPDX-License-Identifier: GPL-3.0-only

package liveupgrade

import (
	"os/exec"
	"strings"
	"testing"
)

func testXHTTPOptions() XHTTPOptions {
	return XHTTPOptions{
		PrimaryInboundTag: "in-443-tcp", PrimaryPort: 443,
		InboundTag: "in-client-xhttp", Remark: "entry-xhttp", Port: 8443,
		EntryAddress: "203.0.113.10", BalancerTag: "Balancer",
	}
}

func TestXHTTPApplyScriptIsScopedAndSyntacticallyValid(t *testing.T) {
	script, err := XHTTPApplyScript(testOptions(), testXHTTPOptions())
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", "-n")
	cmd.Stdin = strings.NewReader(script)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("shell syntax: %v: %s", err, output)
	}
	for _, required := range []string{
		"/inbounds/add", `network:"xhttp"`, `flow=""`, "/server/getNewX25519Cert",
		`shareAddrStrategy:"custom"`, `+[$added])|unique`, "/xray/update",
		"/server/restartXrayService", "3XUI_LIVE_XHTTP_UPDATED",
	} {
		if !strings.Contains(script, required) {
			t.Fatalf("script missing %q", required)
		}
	}
	for _, forbidden := range []string{"ufw ", "iptables ", "systemctl restart", "importDB", "inbounds/del"} {
		if strings.Contains(script, forbidden) {
			t.Fatalf("script contains forbidden mutation %q", forbidden)
		}
	}
}

func TestXHTTPVerifyScriptChecksCascadeAndSubscription(t *testing.T) {
	script, err := XHTTPVerifyScript(testOptions(), XHTTPVerifyOptions{
		Transport: testXHTTPOptions(), SubscriptionPort: 2096,
		ExpectedExitIPv4: "198.51.100.20", ExpectedExitIPv6: "2001:db8:2::20",
	})
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", "-n")
	cmd.Stdin = strings.NewReader(script)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("shell syntax: %v: %s", err, output)
	}
	for _, required := range []string{
		"3XUI_REFERENCE_XHTTP_E2E_READY", "3XUI_REFERENCE_XHTTP_SUBSCRIPTION_READY",
		"type=xhttp", "type=tcp", "routing-enable", `network:"xhttp"`,
		`index($tag)!=null`, "198.51.100.20", "2001:db8:2::20",
	} {
		if !strings.Contains(script, required) {
			t.Fatalf("script missing %q", required)
		}
	}
}

func TestXHTTPOptionsRejectUnsafeValues(t *testing.T) {
	cases := []XHTTPOptions{testXHTTPOptions(), testXHTTPOptions(), testXHTTPOptions(), testXHTTPOptions()}
	cases[0].InboundTag = "bad\ntag"
	cases[1].Port = 0
	cases[2].EntryAddress = "127.0.0.1"
	cases[3].PrimaryPort = 0
	for index, options := range cases {
		if _, err := XHTTPApplyScript(testOptions(), options); err == nil {
			t.Fatalf("case %d accepted unsafe input", index)
		}
	}
}

func TestLauncherWithXHTTPApplyKeepsDatabaseRollback(t *testing.T) {
	apply, err := XHTTPApplyScript(testOptions(), testXHTTPOptions())
	if err != nil {
		t.Fatal(err)
	}
	script, err := LauncherWithApplyScript(testOptions(), strings.Repeat("d", 32), apply, "set -eu\ntrue\n", true)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(decodeEmbeddedScripts(t, script), "\n")
	for _, required := range []string{"/inbounds/add", "keepHostSettings=false", "/server/importDB", "exit 97"} {
		if !strings.Contains(joined, required) {
			t.Fatalf("guarded XHTTP transaction missing %q", required)
		}
	}
}
