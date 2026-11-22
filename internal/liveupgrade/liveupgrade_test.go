// SPDX-License-Identifier: GPL-3.0-only

package liveupgrade

import (
	"encoding/base64"
	"os/exec"
	"strings"
	"testing"
)

func testOptions() Options {
	return Options{
		Scheme: "https", Port: 28443, BasePath: "/example/", CurlTLS: "-k",
		IPv4OutboundTag: "exit-ipv4", IPv6OutboundTag: "exit-ipv6",
		BalancerTag: "Balancer", ClientInboundTag: "in-443-tcp", ObservatoryInterval: "1m",
	}
}

func TestApplyScriptIsNarrowAndSyntacticallyValid(t *testing.T) {
	script, err := ApplyScript(testOptions())
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", "-n")
	cmd.Stdin = strings.NewReader(script)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("shell syntax: %v: %s", err, output)
	}
	for _, required := range []string{
		`selector=[$v4]`, `.fallbackTag=$v6`, `probeInterval:$interval`,
		`$base[0:$catch]+$bt+$base[$catch:]`, `/server/getConfigJson`,
		`/server/restartXrayService`, `delete_token`, "3XUI_LIVE_RUNTIME_UPDATED",
	} {
		if !strings.Contains(script, required) {
			t.Fatalf("script missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"/inbounds/add", "importDB", "systemctl restart", "ufw ", "iptables ",
		"rm -rf /etc",
	} {
		if strings.Contains(script, forbidden) {
			t.Fatalf("script contains forbidden mutation %q", forbidden)
		}
	}
}

func TestApplyScriptRejectsUnsafeInput(t *testing.T) {
	cases := []Options{testOptions(), testOptions(), testOptions(), testOptions()}
	cases[0].IPv4OutboundTag = "bad\ntag"
	cases[1].BasePath = "missing-slashes"
	cases[2].Port = 0
	cases[3].ObservatoryInterval = "0s"
	for index, options := range cases {
		if _, err := ApplyScript(options); err == nil {
			t.Fatalf("case %d accepted unsafe input", index)
		}
	}
}

func TestLauncherArmsIndependentWorkerAndRollback(t *testing.T) {
	script, err := LauncherScript(testOptions(), strings.Repeat("a", 32), "set -eu\necho VERIFIED\n", false)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", "-n")
	cmd.Stdin = strings.NewReader(script)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("launcher shell syntax: %v: %s", err, output)
	}
	for _, required := range []string{
		"/server/getDb", "databaseSHA256", "snapshotTokenName",
		`--on-active=5m`, "xray-cascade-live-rollback-", "xray-cascade-live-worker-",
		"systemd-run --quiet", "watchdog_armed=true", "3XUI_LIVE_UPGRADE_ARMED",
		"snapshot_name=xray-cascade-live-snapshot-$tx", "cleanup_snapshot_token",
		"3XUI_LIVE_UPGRADE_CLEANUP_REQUIRED",
	} {
		if !strings.Contains(script, required) {
			t.Fatalf("launcher missing %q", required)
		}
	}
	if strings.Contains(script, "keepHostSettings=false") {
		t.Fatal("launcher must not import a database before rollback")
	}
}

func TestLauncherEmbedsFailClosedRollback(t *testing.T) {
	script, err := LauncherScript(testOptions(), strings.Repeat("b", 32), "set -eu\ntrue\n", true)
	if err != nil {
		t.Fatal(err)
	}
	decoded := decodeEmbeddedScripts(t, script)
	joined := strings.Join(decoded, "\n")
	for _, required := range []string{
		"keepHostSettings=false", "/server/importDB", "3XUI_LIVE_ROLLBACK_READY",
		"exit 97", "rollback_now", `flock 8`,
		`test "$(jq -r '.status' "$txdir/metadata.json")" = pending`,
		"3XUI_LIVE_UPGRADE_COMMITTED",
	} {
		if !strings.Contains(joined, required) {
			t.Fatalf("embedded scripts missing %q", required)
		}
	}
	for index, embedded := range decoded {
		cmd := exec.Command("sh", "-n")
		cmd.Stdin = strings.NewReader(embedded)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("embedded script %d syntax: %v: %s", index, err, output)
		}
	}
}

func TestManualConfirmationLeavesWatchdogArmedUntilCommit(t *testing.T) {
	options := testOptions()
	options.RequireOperatorCommit = true
	script, err := LauncherScript(options, strings.Repeat("c", 32), "set -eu\ntrue\n", false)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(decodeEmbeddedScripts(t, script), "\n")
	for _, required := range []string{
		`verified_waiting_confirmation`, "3XUI_LIVE_UPGRADE_WAITING_CONFIRMATION",
		`pending|verified_waiting_confirmation`,
	} {
		if !strings.Contains(joined, required) {
			t.Fatalf("manual-confirmation scripts missing %q", required)
		}
	}
	commit, err := CommitScript(strings.Repeat("c", 32))
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", "-n")
	cmd.Stdin = strings.NewReader(commit)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("commit shell syntax: %v: %s", err, output)
	}
	for _, required := range []string{
		`flock 8`, `= verified_waiting_confirmation`, `systemctl stop "$rollback_unit.timer"`,
		"3XUI_LIVE_UPGRADE_COMMITTED",
	} {
		if !strings.Contains(commit, required) {
			t.Fatalf("commit script missing %q", required)
		}
	}
}

func decodeEmbeddedScripts(t *testing.T, script string) []string {
	t.Helper()
	var decoded []string
	for _, line := range strings.Split(script, "\n") {
		marker := "printf '%s' '"
		if !strings.HasPrefix(line, marker) || !strings.Contains(line, "' | base64 -d") {
			continue
		}
		encoded := strings.TrimPrefix(line, marker)
		encoded = strings.SplitN(encoded, "' | base64 -d", 2)[0]
		raw, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			t.Fatalf("decode embedded script: %v", err)
		}
		decoded = append(decoded, string(raw))
	}
	if len(decoded) != 2 {
		t.Fatalf("expected rollback and worker scripts, got %d", len(decoded))
	}
	// Worker embeds apply and verify as two additional base64 payloads.
	for _, line := range strings.Split(decoded[1], "\n") {
		marker := "printf '%s' '"
		if !strings.HasPrefix(line, marker) || !strings.Contains(line, "' | base64 -d") {
			continue
		}
		encoded := strings.TrimPrefix(line, marker)
		encoded = strings.SplitN(encoded, "' | base64 -d", 2)[0]
		raw, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			t.Fatalf("decode worker payload: %v", err)
		}
		decoded = append(decoded, string(raw))
	}
	return decoded
}
