// SPDX-License-Identifier: GPL-3.0-only

package liveupgrade

import (
	"os/exec"
	"strings"
	"testing"
)

func TestReferenceVerifyScriptIsSyntacticallyValidAndScoped(t *testing.T) {
	script, err := ReferenceVerifyScript(testOptions(), ReferenceVerifyOptions{
		InboundTag: "in-443-tcp", ClientPort: 443, SubscriptionPort: 2096,
		EntryAddress:     "203.0.113.10",
		ExpectedExitIPv4: "198.51.100.20",
		ExpectedExitIPv6: "2001:db8:2::20",
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
		"3XUI_REFERENCE_CASCADE_E2E_READY", "3XUI_REFERENCE_HAPP_READY",
		"198.51.100.20", "3XUI_REFERENCE_CASCADE_EGRESS_MISMATCH", "subEnableRouting==true", "delete_token",
		"3XUI_REFERENCE_RU_SITES_READY", "3XUI_REFERENCE_RU_SITES_FAILED", "ru_passed", "-lt 3",
		"https://www.yandex.ru/", "https://www.nalog.gov.ru/", "https://www.mos.ru/", "https://vk.com/",
	} {
		if !strings.Contains(script, required) {
			t.Fatalf("reference verifier missing %q", required)
		}
	}
	if strings.Contains(script, "gosuslugi") {
		t.Fatal("site-specific Gosuslugi filtering must not gate the cascade transaction")
	}
	for _, forbidden := range []string{"iptables ", "ip6tables ", "restartXrayService", "importDB"} {
		if strings.Contains(script, forbidden) {
			t.Fatalf("reference verifier contains mutation %q", forbidden)
		}
	}
}

func TestReferenceVerifyRejectsUnsafeValues(t *testing.T) {
	_, err := ReferenceVerifyScript(testOptions(), ReferenceVerifyOptions{
		InboundTag: "bad\ntag", ClientPort: 443, SubscriptionPort: 2096,
		EntryAddress:     "203.0.113.10",
		ExpectedExitIPv4: "198.51.100.20",
		ExpectedExitIPv6: "2001:db8:2::20",
	})
	if err == nil {
		t.Fatal("unsafe reference verifier options accepted")
	}
}
