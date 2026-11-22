// SPDX-License-Identifier: GPL-3.0-only

package deployprod

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"testing"

	"github.com/b1ts23/xray-easy-cascade/internal/deploylab"
	"github.com/b1ts23/xray-easy-cascade/internal/inventory"
	"github.com/b1ts23/xray-easy-cascade/internal/production"
	"github.com/b1ts23/xray-easy-cascade/internal/remote"
)

type runtimeFakeRunner struct {
	calls  []string
	failAt string
}

func (f *runtimeFakeRunner) Run(_ context.Context, target remote.Target, script string) (string, error) {
	role := "entry"
	if target.Host == "198.51.100.20" {
		role = "exit"
	}
	kind, output := "unknown", ""
	switch {
	case strings.Contains(script, "3XUI_PUBLIC_IPV6\\t"):
		kind = "discover-ipv6"
		if role == "entry" {
			output = publicIPv6Prefix + "2001:db8::10"
		} else {
			output = publicIPv6Prefix + "2001:db8::20"
		}
	case strings.Contains(script, "3XUI_PRODUCTION_CANDIDATE_READY"):
		kind, output = "candidate", "3XUI_PRODUCTION_CANDIDATE_READY role="+role
	case strings.Contains(script, "3XUI_PRODUCTION_STAGED"):
		kind, output = "stage", "3XUI_PRODUCTION_STAGED role="+role
	case strings.Contains(script, "3XUI_PRODUCTION_FIREWALL_READY"):
		kind, output = "firewall", "3XUI_PRODUCTION_FIREWALL_READY role="+role
	case strings.Contains(script, "3XUI_PRODUCTION_SSH_PROTECTION_READY"):
		kind, output = "ssh-protect", "3XUI_PRODUCTION_SSH_PROTECTION_READY role="+role
	case strings.Contains(script, "3XUI_PRODUCTION_ACTIVATED"):
		kind, output = "activate", "3XUI_PRODUCTION_ACTIVATED role="+role
	case strings.Contains(script, "3XUI_PRODUCTION_ACME_READY"):
		kind, output = "acme", "3XUI_PRODUCTION_ACME_READY role="+role
	case strings.Contains(script, "3XUI_PRODUCTION_SUBSCRIPTION_TLS_READY"):
		kind, output = "subscription-tls", "3XUI_PRODUCTION_SUBSCRIPTION_TLS_READY"
	case strings.Contains(script, "3XUI_PRODUCTION_INSTALL_ROLLED_BACK"):
		kind, output = "install-rollback", "3XUI_PRODUCTION_INSTALL_ROLLED_BACK role="+role
	case strings.Contains(script, "3XUI_TRANSACTION_SNAPSHOT_READY"):
		kind, output = "snapshot", "3XUI_TRANSACTION_SNAPSHOT_READY role="+role
	case strings.Contains(script, "3XUI_NODE_TOKEN\\t"):
		kind = "token"
		output = "3XUI_NODE_TOKEN\ttest-node-token\n3XUI_NODE_PIN\t" + strings.Repeat("a", 64)
	case strings.Contains(script, "3XUI_ENTRY_CONFIG_READY"):
		kind, output = "entry-runtime", "3XUI_ENTRY_CONFIG_READY"
	case strings.Contains(script, "3XUI_PRODUCTION_EXIT_CONFIG_READY"):
		kind, output = "exit-verify", "3XUI_PRODUCTION_EXIT_CONFIG_READY"
	case strings.Contains(script, "3XUI_TRANSACTION_COMMITTED"):
		kind, output = "commit", "3XUI_TRANSACTION_COMMITTED role="+role
	case strings.Contains(script, "3XUI_TRANSACTION_ROLLED_BACK"):
		kind, output = "rollback", "3XUI_TRANSACTION_ROLLED_BACK role="+role
	}
	call := role + ":" + kind
	f.calls = append(f.calls, call)
	if call == f.failAt {
		return "", errors.New("simulated runtime failure")
	}
	return output + "\n", nil
}

func productionRuntimeInventory() inventory.Inventory {
	inv := validInventory()
	inv.Entry.CascadeAddress = "203.0.113.10"
	inv.Exit.CascadeAddress = "198.51.100.20"
	inv.Certificates.NodeTransport = "pin"
	return inv
}

func testHappProfile() (string, string) {
	profile := "happ://routing/onadd/test"
	return profile, fmt.Sprintf("%x", sha256.Sum256([]byte(profile)))
}

func TestProductionRuntimeScriptsUseHTTPSAndPublicNodePolicy(t *testing.T) {
	inv := productionRuntimeInventory()
	script, err := deploylab.EntryScriptWithOptions(inv, deploylab.NodeAccess{Token: "secret", Pin: strings.Repeat("b", 64)}, "happ://routing/onadd/test", deploylab.ProductionRuntimeOptions())
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"panel_scheme", "allowPrivateAddress", `tlsVerifyMode:"pin"`} {
		if !strings.Contains(script, required) {
			t.Fatalf("production runtime script missing %q", required)
		}
	}
	if strings.Contains(script, "isolated container lab") {
		t.Fatal("production runtime leaked lab resource policy")
	}
	cmd := exec.Command("sh", "-n")
	cmd.Stdin = strings.NewReader(script)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("production entry shell syntax: %v: %s", err, output)
	}
	if !strings.Contains(script, "/nodes/mtls/ca") {
		t.Fatal("production entry script does not mint mTLS material before panel restart")
	}
	if !strings.Contains(productionExitTokenScript(), "/root/cert/ip/fullchain.pem") {
		t.Fatal("production enrollment pin is not derived from the active ACME certificate")
	}
}

func TestParsePublicIPv6(t *testing.T) {
	got, err := parsePublicIPv6("noise\n" + publicIPv6Prefix + "2001:db8::20\n")
	if err != nil || got != "2001:db8::20" {
		t.Fatalf("got=%q err=%v", got, err)
	}
	if got, err := parsePublicIPv6(publicIPv6Prefix + "disabled\n"); err != nil || got != "disabled" {
		t.Fatalf("disabled got=%q err=%v", got, err)
	}
	for _, bad := range []string{"", publicIPv6Prefix + "fd00::1\n", publicIPv6Prefix + "203.0.113.10\n"} {
		if _, err := parsePublicIPv6(bad); err == nil {
			t.Fatalf("accepted invalid marker %q", bad)
		}
	}
}

func TestResolveProductionNetworkFeedsIPv6FirewallPlan(t *testing.T) {
	inv := productionRuntimeInventory()
	inv.Entry.PublicIPv6 = "auto"
	inv.Exit.PublicIPv6 = "auto"
	runner := &runtimeFakeRunner{}
	resolved, err := ResolveProductionNetwork(context.Background(), runner, inv)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := production.BuildPlan(resolved)
	if err != nil {
		t.Fatal(err)
	}
	var reality, nodeAPI bool
	for _, rule := range plan.Firewall {
		if rule.Source == "2001:db8::10" && rule.Purpose == "entry-to-exit-reality-ipv6" {
			reality = true
		}
		if rule.Source == "2001:db8::10" && rule.Purpose == "entry-to-node-api-ipv6" {
			nodeAPI = true
		}
	}
	if !reality || !nodeAPI {
		t.Fatalf("resolved IPv6 was not included in firewall plan: %#v", plan.Firewall)
	}
}

func TestConfigureRuntimeCommitsBothNodes(t *testing.T) {
	runner := &runtimeFakeRunner{}
	var out bytes.Buffer
	profile, checksum := testHappProfile()
	if err := ConfigureRuntime(context.Background(), runner, productionRuntimeInventory(), profile, checksum, &out); err != nil {
		t.Fatal(err)
	}
	want := []string{"exit:snapshot", "entry:snapshot", "exit:token", "entry:entry-runtime", "exit:exit-verify", "exit:commit", "entry:commit"}
	if strings.Join(runner.calls, "\n") != strings.Join(want, "\n") {
		t.Fatalf("unexpected production runtime order:\n%s", strings.Join(runner.calls, "\n"))
	}
	if !strings.Contains(out.String(), "3XUI_PRODUCTION_RUNTIME_READY") {
		t.Fatalf("missing production completion marker: %s", out.String())
	}
}

func TestConfigureRuntimeRollsBackBothNodes(t *testing.T) {
	runner := &runtimeFakeRunner{failAt: "entry:entry-runtime"}
	profile, checksum := testHappProfile()
	err := ConfigureRuntime(context.Background(), runner, productionRuntimeInventory(), profile, checksum, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "configure production entry") {
		t.Fatalf("unexpected error: %v", err)
	}
	got := strings.Join(runner.calls, "\n")
	if !strings.HasSuffix(got, "entry:rollback\nexit:rollback") {
		t.Fatalf("runtime rollback order is not entry then exit:\n%s", got)
	}
}

func TestDeployFreshHostsRemovesBothInstallsAfterRuntimeFailure(t *testing.T) {
	runner := &runtimeFakeRunner{failAt: "entry:entry-runtime"}
	profile, checksum := testHappProfile()
	err := DeployFreshHosts(context.Background(), runner, productionRuntimeInventory(), profile, checksum, &bytes.Buffer{})
	if err == nil {
		t.Fatal("expected runtime failure")
	}
	got := strings.Join(runner.calls, "\n")
	if !strings.HasSuffix(got, "entry:rollback\nexit:rollback\nentry:install-rollback\nexit:install-rollback") {
		t.Fatalf("fresh-host cleanup order is unsafe:\n%s", got)
	}
}
