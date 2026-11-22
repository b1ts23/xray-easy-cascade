// SPDX-License-Identifier: GPL-3.0-only

package production

import (
	"os/exec"
	"strings"
	"testing"

	"github.com/b1ts23/xray-cascade/internal/inventory"
)

func TestBuildPlanRestrictsExitToEntry(t *testing.T) {
	inv := inventory.Default()
	inv.Entry.Host = "203.0.113.10"
	inv.Exit.Host = "198.51.100.20"
	inv.Entry.PublicIPv6 = "2001:db8::10"
	plan, err := BuildPlan(inv)
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range plan.Firewall {
		if rule.Node == "exit" && rule.Purpose != "preserve-ssh" && rule.Purpose != "acme-http-01" && rule.Source == "any" {
			t.Fatalf("exit service exposed publicly: %#v", rule)
		}
	}
	joined := strings.Join(plan.Lines(), "\n")
	for _, required := range []string{"entry tcp/443 from any", "entry tcp/2096 from any", "exit tcp/2053 from 203.0.113.10", "never reset"} {
		if !strings.Contains(joined, required) {
			t.Fatalf("plan missing %q:\n%s", required, joined)
		}
	}
}

func TestBuildPlanAddsACMEHTTPValidationForBothNodes(t *testing.T) {
	inv := inventory.Default()
	inv.Entry.Host = "203.0.113.10"
	inv.Exit.Host = "198.51.100.20"
	inv.Entry.PublicIPv6 = "disabled"
	inv.Certificates.SubscriptionTLS = "acme-ip"
	plan, err := BuildPlan(inv)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"entry": false, "exit": false}
	for _, rule := range plan.Firewall {
		if rule.Port == 80 && rule.Source == "any" && rule.Purpose == "acme-http-01" {
			want[rule.Node] = true
		}
	}
	for node, found := range want {
		if !found {
			t.Fatalf("missing ACME HTTP-01 rule for %s", node)
		}
	}
}

func TestBuildPlanRejectsHostnameForOwnedFirewall(t *testing.T) {
	inv := inventory.Default()
	inv.Entry.Host = "entry.example.com"
	if _, err := BuildPlan(inv); err == nil {
		t.Fatal("hostname accepted for deterministic firewall source")
	}
}

func TestBuildPlanIncludesAlternativeClientTransportPorts(t *testing.T) {
	inv := inventory.Default()
	inv.Entry.Host = "203.0.113.10"
	inv.Exit.Host = "198.51.100.20"
	inv.Transport.ClientAlternatives = []inventory.ClientAlternative{{Kind: "reality-xhttp", Port: 8443}, {Kind: "reality-xhttp-pq", Port: 10443}, {Kind: "reality-grpc", Port: 9443}}
	plan, err := BuildPlan(inv)
	if err != nil {
		t.Fatal(err)
	}
	want := map[int]string{8443: "client-xhttp-reality", 10443: "client-xhttp-pq-reality", 9443: "client-grpc-reality"}
	for _, rule := range plan.Firewall {
		if rule.Node == "entry" && rule.Source == "any" && want[rule.Port] == rule.Purpose {
			delete(want, rule.Port)
		}
	}
	if len(want) != 0 {
		t.Fatalf("alternative firewall rules missing: %#v", want)
	}
}

func TestBuildPlanIncludesHysteria2UDP(t *testing.T) {
	inv := inventory.Default()
	inv.Entry.Host = "203.0.113.10"
	inv.Exit.Host = "198.51.100.20"
	inv.Certificates.SubscriptionTLS = "acme-ip"
	inv.Transport.Hysteria2 = inventory.Hysteria2{Enabled: true, Port: 443}
	plan, err := BuildPlan(inv)
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range plan.Firewall {
		if rule.Node == "entry" && rule.Port == 443 && rule.Protocol == "udp" && rule.Purpose == "client-hysteria2-tls" {
			return
		}
	}
	t.Fatal("missing Hysteria2 UDP firewall rule")
}

func TestBuildInstallStepsEnforcesSafeOrder(t *testing.T) {
	inv := inventory.Default()
	inv.Entry.Host = "203.0.113.10"
	inv.Exit.Host = "198.51.100.20"
	inv.Entry.PublicIPv6 = "disabled"
	inv.Exit.PublicIPv6 = "disabled"
	inv.Certificates.SubscriptionTLS = "acme-ip"
	entry, err := BuildInstallSteps("entry", inv)
	if err != nil {
		t.Fatal(err)
	}
	exit, err := BuildInstallSteps("exit", inv)
	if err != nil {
		t.Fatal(err)
	}
	names := func(steps []InstallStep) string {
		values := make([]string, 0, len(steps))
		for _, step := range steps {
			if strings.TrimSpace(step.Script) == "" {
				t.Fatalf("empty script for step %s", step.Name)
			}
			values = append(values, step.Name)
		}
		return strings.Join(values, ",")
	}
	if got, want := names(entry), "candidate,stage,firewall,activate,acme-ip,subscription-tls"; got != want {
		t.Fatalf("entry order = %s, want %s", got, want)
	}
	if got, want := names(exit), "candidate,stage,firewall,activate,acme-ip"; got != want {
		t.Fatalf("exit order = %s, want %s", got, want)
	}
}

func TestCandidateScriptIsPinnedAndDoesNotActivate(t *testing.T) {
	script, err := CandidateScript("entry")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{XUIURL, XUISHA256, "sha256sum -c", "x-ui.service.debian", "unsafe path"} {
		if !strings.Contains(script, required) {
			t.Fatalf("candidate script missing %q", required)
		}
	}
	for _, forbidden := range []string{"systemctl enable", "systemctl start", "ufw reset", "/usr/local/x-ui"} {
		if strings.Contains(script, forbidden) {
			t.Fatalf("candidate script activates production resource %q", forbidden)
		}
	}
	cmd := exec.Command("sh", "-n")
	cmd.Stdin = strings.NewReader(script)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("candidate script syntax: %v: %s", err, output)
	}
}

func TestACMEIPScriptPinsSupplyChainAndMatchesReferenceLayout(t *testing.T) {
	inv := inventory.Default()
	inv.Entry.Host = "203.0.113.10"
	inv.Exit.Host = "198.51.100.20"
	inv.Certificates.SubscriptionTLS = "acme-ip"
	script, err := ACMEIPScript("entry", inv)
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		ACMEURL,
		ACMESHA256,
		"sha256sum -c",
		"--certificate-profile shortlived",
		"--days 6",
		"--keylength ec-256",
		"/root/cert/ip/fullchain.pem",
		"/root/cert/ip/privkey.pem",
		"xray-cascade:acme-renew",
		"systemctl restart x-ui",
		"unmanaged /root/cert/ip is not empty",
		"cron_backup",
		"web_changed",
		"--uninstall",
		"3XUI_PRODUCTION_ACME_READY",
	} {
		if !strings.Contains(script, required) {
			t.Fatalf("ACME script missing %q", required)
		}
	}
	for _, forbidden := range []string{"curl -s https://get.acme.sh | sh", "StrictHostKeyChecking=no", "chmod 777"} {
		if strings.Contains(script, forbidden) {
			t.Fatalf("ACME script contains unsafe operation %q", forbidden)
		}
	}
	cmd := exec.Command("sh", "-n")
	cmd.Stdin = strings.NewReader(script)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("ACME script syntax: %v: %s", err, output)
	}
}

func TestACMEIPScriptRejectsHostname(t *testing.T) {
	inv := inventory.Default()
	inv.Entry.Host = "entry.example.com"
	inv.Exit.Host = "198.51.100.20"
	inv.Certificates.SubscriptionTLS = "acme-ip"
	if _, err := ACMEIPScript("entry", inv); err == nil {
		t.Fatal("ACME IP script accepted a hostname")
	}
}

func TestSubscriptionTLSScriptUsesSupportedAPIAndVerifiesChain(t *testing.T) {
	inv := inventory.Default()
	inv.Entry.Host = "203.0.113.10"
	inv.Exit.Host = "198.51.100.20"
	inv.Certificates.SubscriptionTLS = "acme-ip"
	script, err := SubscriptionTLSScript(inv)
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"/setting/all",
		"-X POST \"$api/setting/all\"",
		"/setting/update",
		"/setting/restartPanel",
		"subCertFile",
		"subKeyFile",
		"-verify_ip",
		"--noproxy",
		"Verify return code: 0 (ok)",
		"3XUI_PRODUCTION_SUBSCRIPTION_TLS_READY",
	} {
		if !strings.Contains(script, required) {
			t.Fatalf("subscription TLS script missing %q", required)
		}
	}
	for _, forbidden := range []string{"sqlite3", "UPDATE settings", "-k", "--insecure"} {
		if strings.Contains(script, forbidden) {
			t.Fatalf("subscription TLS script bypasses trust or API with %q", forbidden)
		}
	}
	cmd := exec.Command("sh", "-n")
	cmd.Stdin = strings.NewReader(script)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("subscription TLS script syntax: %v: %s", err, output)
	}
}

func TestStageInstallScriptDoesNotActivateNetworkOrService(t *testing.T) {
	inv := inventory.Default()
	inv.Entry.Host = "203.0.113.10"
	inv.Exit.Host = "198.51.100.20"
	script, err := StageInstallScript("exit", inv)
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"x-ui.service.debian", "systemd-analyze verify", "SystemCallFilter=@system-service", "subjectAltName=IP:$server_address", "3XUI_PRODUCTION_STAGED"} {
		if !strings.Contains(script, required) {
			t.Fatalf("stage script missing %q", required)
		}
	}
	for _, forbidden := range []string{"systemctl start", "systemctl enable", "ufw ", "iptables", "firewall-cmd"} {
		if strings.Contains(script, forbidden) {
			t.Fatalf("stage script activates %q", forbidden)
		}
	}
	cmd := exec.Command("sh", "-n")
	cmd.Stdin = strings.NewReader(script)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("stage script syntax: %v: %s", err, output)
	}
}

func TestActivationScriptRollsBackFailedFirstStart(t *testing.T) {
	inv := inventory.Default()
	inv.Entry.Host = "203.0.113.10"
	inv.Exit.Host = "198.51.100.20"
	script, err := ActivationScript("exit", inv)
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"systemctl enable --now x-ui",
		"systemctl disable --now x-ui",
		"x-ui must be inactive",
		".status=\"active\"",
		"3XUI_PRODUCTION_ACTIVATED",
	} {
		if !strings.Contains(script, required) {
			t.Fatalf("activation script missing %q", required)
		}
	}
	for _, forbidden := range []string{"ufw ", "iptables", "firewall-cmd"} {
		if strings.Contains(script, forbidden) {
			t.Fatalf("activation script changes firewall with %q", forbidden)
		}
	}
	cmd := exec.Command("sh", "-n")
	cmd.Stdin = strings.NewReader(script)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("activation script syntax: %v: %s", err, output)
	}
}

func TestInstallRollbackRequiresOwnershipAndRestoresFirewall(t *testing.T) {
	script, err := InstallRollbackScript("entry")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		".clusterRole==$role",
		"firewallSnapshot",
		"initial.state",
		"xray-cascade:acme-renew",
		"acmeInstalledByProject",
		"systemctl disable --now x-ui",
		"3XUI_PRODUCTION_INSTALL_ROLLED_BACK",
	} {
		if !strings.Contains(script, required) {
			t.Fatalf("install rollback script missing %q", required)
		}
	}
	for _, forbidden := range []string{"ufw reset", "iptables -F", "rm -rf / ", "rm -rf $root"} {
		if strings.Contains(script, forbidden) {
			t.Fatalf("install rollback script contains unsafe operation %q", forbidden)
		}
	}
	cmd := exec.Command("sh", "-n")
	cmd.Stdin = strings.NewReader(script)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("install rollback script syntax: %v: %s", err, output)
	}
}

func TestFirewallScriptOwnsOnlyCommentedRules(t *testing.T) {
	inv := inventory.Default()
	inv.Entry.Host = "203.0.113.10"
	inv.Exit.Host = "198.51.100.20"
	inv.Entry.PublicIPv6 = "disabled"
	script, err := FirewallScript("exit", inv)
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"xray-cascade:", "user.rules", "ufw --force enable", "3XUI_PRODUCTION_FIREWALL_READY"} {
		if !strings.Contains(script, required) {
			t.Fatalf("firewall script missing %q", required)
		}
	}
	for _, forbidden := range []string{"ufw reset", "iptables -F", "ufw delete"} {
		if strings.Contains(script, forbidden) {
			t.Fatalf("firewall script contains destructive operation %q", forbidden)
		}
	}
	cmd := exec.Command("sh", "-n")
	cmd.Stdin = strings.NewReader(script)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("firewall script syntax: %v: %s", err, output)
	}
}
