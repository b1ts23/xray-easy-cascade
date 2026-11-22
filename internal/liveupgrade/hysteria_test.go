// SPDX-License-Identifier: GPL-3.0-only

package liveupgrade

import (
	"os/exec"
	"strings"
	"testing"
)

func testHysteriaOptions() HysteriaOptions {
	return HysteriaOptions{
		PrimaryInboundTag: "in-443-tcp", InboundTag: "in-client-hysteria2", Remark: "entry-hysteria2",
		Port: 443, EntryAddress: "203.0.113.10", BalancerTag: "Balancer",
		CertificateFile: "/root/cert/ip/fullchain.pem", KeyFile: "/root/cert/ip/privkey.pem",
	}
}

func TestHysteriaApplyIsAdditiveAndScoped(t *testing.T) {
	script, err := HysteriaApplyScript(testOptions(), testHysteriaOptions())
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"protocol:\"hysteria\"", "network:\"hysteria\"", "security:\"tls\"", "hysteriaSettings:{version:2}",
		"subSortIndex:3", "ss -H -lun", "openssl x509", "restartXrayService", "3XUI_LIVE_HYSTERIA_UPDATED",
	} {
		if !strings.Contains(script, required) {
			t.Fatalf("Hysteria apply missing %q", required)
		}
	}
	for _, forbidden := range []string{"ufw ", "iptables", "systemctl restart ssh", "inbounds/del", "PermitRootLogin"} {
		if strings.Contains(script, forbidden) {
			t.Fatalf("Hysteria apply contains out-of-scope operation %q", forbidden)
		}
	}
	cmd := exec.Command("bash", "-n")
	cmd.Stdin = strings.NewReader(script)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("Hysteria apply syntax: %v: %s", err, output)
	}
}

func TestHysteriaVerifyRequiresEgressAndSubscription(t *testing.T) {
	script, err := HysteriaVerifyScript(testOptions(), HysteriaVerifyOptions{
		Transport: testHysteriaOptions(), SubscriptionPort: 2096,
		ExpectedExitIPv4: "198.51.100.20", ExpectedExitIPv6: "2001:db8::20",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"run -test", "protocol:\"hysteria\"", "cdn-cgi/trace", "198.51.100.20", "2001:db8::20",
		"Happ/4.6.1", "^hysteria2://", "type=xhttp", "3XUI_REFERENCE_HYSTERIA_E2E_READY",
		"3XUI_REFERENCE_HYSTERIA_SUBSCRIPTION_READY",
	} {
		if !strings.Contains(script, required) {
			t.Fatalf("Hysteria verify missing %q", required)
		}
	}
	cmd := exec.Command("bash", "-n")
	cmd.Stdin = strings.NewReader(script)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("Hysteria verify syntax: %v: %s", err, output)
	}
}

func TestHysteriaRejectsUnsafeInputs(t *testing.T) {
	options := testHysteriaOptions()
	options.KeyFile = "relative.key"
	if _, err := HysteriaApplyScript(testOptions(), options); err == nil {
		t.Fatal("relative key path accepted")
	}
	options = testHysteriaOptions()
	options.EntryAddress = "127.0.0.1"
	if _, err := HysteriaApplyScript(testOptions(), options); err == nil {
		t.Fatal("loopback entry accepted")
	}
}
