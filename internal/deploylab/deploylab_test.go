// SPDX-License-Identifier: GPL-3.0-only

package deploylab

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/b1ts23/xray-easy-cascade/internal/inventory"
)

func testCertificatePEM(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	raw, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw}))
}

func TestParseExitAccess(t *testing.T) {
	pin := strings.Repeat("a", 64)
	access, err := ParseExitAccess("noise\n" + tokenPrefix + "abc123\n" + pinPrefix + pin + "\n")
	if err != nil || access.Token != "abc123" || access.Pin != pin {
		t.Fatalf("access=%#v err=%v", access, err)
	}
	for _, bad := range []string{"", tokenPrefix + "bad token\n" + pinPrefix + pin, tokenPrefix + "one\n" + tokenPrefix + "two\n" + pinPrefix + pin, tokenPrefix + "one\n" + pinPrefix + "bad"} {
		if _, err := ParseExitAccess(bad); err == nil {
			t.Fatalf("accepted invalid output %q", bad)
		}
	}
}

func TestEntryScriptCarriesSecretsEncodedAndUses3XUIAPI(t *testing.T) {
	inv := inventory.Default()
	inv.Entry.CascadeAddress = "172.29.10.10"
	inv.Exit.CascadeAddress = "172.29.10.11"
	inv.Transport.ClientAlternatives = []inventory.ClientAlternative{{Kind: "reality-xhttp", Port: 10444}, {Kind: "reality-xhttp-pq", Port: 10446}, {Kind: "reality-grpc", Port: 10445}}
	inv.Transport.InterserverAlternatives = []inventory.InterserverAlternative{{Kind: "reality-xhttp", Port: 11444}}
	inv.Certificates.SubscriptionTLS = "existing"
	inv.Certificates.SubscriptionCertFile = "/etc/x-ui/subscription.crt"
	inv.Certificates.SubscriptionKeyFile = "/etc/x-ui/subscription.key"
	inv.Transport.Hysteria2 = inventory.Hysteria2{Enabled: true, Port: 10443}
	script, err := EntryScript(inv, NodeAccess{Token: "secret-node-token", Pin: strings.Repeat("b", 64)}, "happ://routing/onadd/test")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(script, "secret-node-token") {
		t.Fatal("plaintext node token appears in generated shell")
	}
	for _, required := range []string{"/nodes/test", "/inbounds/add", "/inbounds/del/", "/server/getNewVlessEnc", "/xray/update", "3XUI_ENTRY_CONFIG_READY", "cascade-exit-ipv4", "cascade-exit-ipv6", "cascade-exit-xhttp-ipv4", "cascade-exit-xhttp-ipv6", "in-cascade-exit-xhttp", "balancer_fallback=blocked", "balancer_strategy=leastPing", "observatory", `in-client-entry-xhttp`, `in-client-entry-xhttp-pq`, `in-client-entry-grpc`, `in-client-entry-hysteria2`, `protocol:["bittorrent"]`, `ip:["geoip:private"]`, `network:"xhttp"`, `network:"grpc"`, `protocol:"hysteria"`, `flow:""`, `mlkem768x25519plus.native.`, `subSortIndex:2`, `subSortIndex:3`, `subSortIndex:4`, `subSortIndex:5`} {
		if !strings.Contains(script, required) {
			t.Fatalf("generated script missing %q", required)
		}
	}
	if !strings.Contains(script, `tlsVerifyMode:"pin"`) {
		t.Fatal("node connection is not certificate-pinned HTTPS")
	}
	if !strings.Contains(script, "subHappAutoDetect=true") || !strings.Contains(script, "3XUI_ROSCOMVPN_READY") {
		t.Fatal("RoscomVPN subscription settings are missing")
	}
	if !strings.Contains(script, "subEncrypt=false") || !strings.Contains(script, "subHappNoLimit=false") {
		t.Fatal("reference HAPP security settings are missing")
	}
	for _, required := range []string{"roscom-geoip.dat", "roscom-geosite.dat", "3XUI_ROSCOMVPN_SERVER_READY"} {
		if !strings.Contains(script, required) {
			t.Fatalf("RoscomVPN server routing is missing %q", required)
		}
	}
	if strings.Contains(script, "config.json") {
		t.Fatal("generated script must not edit standalone Xray config.json")
	}
}

func TestE2EScriptChecksBothClientTransportsAndSubscription(t *testing.T) {
	inv := inventory.Default()
	inv.Entry.CascadeAddress = "172.29.10.10"
	inv.Transport.ClientAlternatives = []inventory.ClientAlternative{{Kind: "reality-xhttp", Port: 10444}, {Kind: "reality-xhttp-pq", Port: 10446}, {Kind: "reality-grpc", Port: 10445}}
	inv.Certificates.SubscriptionTLS = "existing"
	inv.Transport.Hysteria2 = inventory.Hysteria2{Enabled: true, Port: 10443}
	script, err := E2EScript(inv, strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", "-n")
	cmd.Stdin = strings.NewReader(script)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("E2E shell syntax: %v: %s", err, output)
	}
	for _, required := range []string{
		"3XUI_CASCADE_TCP_E2E_READY", "3XUI_CASCADE_XHTTP_E2E_READY", "3XUI_CASCADE_XHTTP_PQ_E2E_READY", "3XUI_CASCADE_GRPC_E2E_READY", "3XUI_CASCADE_HYSTERIA2_E2E_READY",
		"3XUI_CLIENT_TRANSPORT_FALLBACK_READY",
		"3XUI_MULTI_TRANSPORT_SUBSCRIPTION_READY", "3XUI_XHTTP_PQ_SUBSCRIPTION_READY", "3XUI_GRPC_SUBSCRIPTION_READY", "3XUI_HYSTERIA2_SUBSCRIPTION_READY", `network:"xhttp"`, `network:"grpc"`, `protocol:"hysteria"`,
		`test "$xclient_id" = "$client_id"`, `test "$gclient_id" = "$client_id"`, `grep -c 'type=xhttp'`, `grep -c 'type=grpc'`,
	} {
		if !strings.Contains(script, required) {
			t.Fatalf("E2E script missing %q", required)
		}
	}
}

func TestValidateBoundaryRejectsPublicTargets(t *testing.T) {
	inv := inventory.Default()
	inv.Entry.Host = "203.0.113.10"
	inv.Exit.Host = "127.0.0.1"
	inv.Entry.CascadeAddress = "172.29.10.10"
	inv.Exit.CascadeAddress = "172.29.10.11"
	inv.Entry.SSHPort, inv.Exit.SSHPort = 2201, 2202
	inv.Entry.PublicIPv6, inv.Exit.PublicIPv6 = "disabled", "disabled"
	inv.Transport.ClientPort, inv.Transport.InterserverPort = 10443, 11443
	if err := ValidateBoundary(inv, "root@host:22"); err == nil {
		t.Fatal("public SSH target accepted by lab deploy")
	}
	inv.Entry.Host = "127.0.0.1"
	if err := ValidateBoundary(inv, "root@host:22"); err != nil {
		t.Fatalf("valid lab boundary rejected: %v", err)
	}
	inv.Entry.PublicIPv6, inv.Exit.PublicIPv6 = "fd29:10::10", "fd29:10::11"
	if err := ValidateBoundary(inv, "root@host:22"); err != nil {
		t.Fatalf("private dual-stack lab boundary rejected: %v", err)
	}
	inv.Exit.PublicIPv6 = "2001:db8::11"
	if err := ValidateBoundary(inv, "root@host:22"); err == nil {
		t.Fatal("non-private IPv6 address accepted by lab deploy")
	}
}

func TestFailoverE2EScriptIsScopedAndFailsClosed(t *testing.T) {
	inv := inventory.Default()
	inv.Entry.CascadeAddress = "172.29.10.10"
	inv.Exit.CascadeAddress = "172.29.10.11"
	inv.Entry.PublicIPv6 = "fd29:10::10"
	inv.Exit.PublicIPv6 = "fd29:10::11"
	inv.Transport.ClientPort = 10443
	inv.Transport.InterserverPort = 11443
	inv.Transport.InterserverAlternatives = []inventory.InterserverAlternative{{Kind: "reality-xhttp", Port: 12443}}
	inv.Transport.IPv6Fallback = "required"

	script, err := FailoverE2EScript(inv)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", "-n")
	cmd.Stdin = strings.NewReader(script)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("failover shell syntax: %v: %s", err, output)
	}
	for _, required := range []string{
		`iptables -I OUTPUT 1 -d "$exit_v4" -p tcp --dport "$hop_port" -j REJECT`,
		`ip6tables -I OUTPUT 1 -d "$exit_v6" -p tcp --dport "$hop_port" -j REJECT`,
		`iptables -D OUTPUT -d "$exit_v4" -p tcp --dport "$hop_port" -j REJECT`,
		`ip6tables -D OUTPUT -d "$exit_v6" -p tcp --dport "$hop_port" -j REJECT`,
		`cascade-exit-xhttp-ipv4`, `.strategy.type=="leastPing"`, `.fallbackTag=="blocked"`,
		`.obj.observatory.probeInterval=="2s"`,
		"delete_test_token", `jq -e '.success==true' /run/xray-cascade-failover-delete.json`,
		"3XUI_FAILOVER_XHTTP_TRANSPORT_READY", "3XUI_FAILOVER_TCP_TRANSPORT_READY", "3XUI_FAILOVER_IPV6_FALLBACK_READY",
		"3XUI_FAILOVER_FAIL_CLOSED_READY", "3XUI_FAILOVER_RECOVERY_READY",
	} {
		if !strings.Contains(script, required) {
			t.Fatalf("failover script missing %q", required)
		}
	}
	if strings.Contains(script, "iptables -P") || strings.Contains(script, "ip6tables -P") {
		t.Fatal("failover script must not change chain policies")
	}
}

func TestMtlsScriptsCarryOnlyValidatedPublicCertificates(t *testing.T) {
	certificate := testCertificatePEM(t)
	marker := exitCertPrefix + base64.StdEncoding.EncodeToString([]byte(certificate)) + "\n"
	parsed, err := ParseExitCertificate(marker)
	if err != nil || parsed != certificate {
		t.Fatalf("parsed certificate mismatch err=%v", err)
	}
	entryScript, err := EntryTrustExitCertificateScript(certificate, "172.29.10.11")
	if err != nil {
		t.Fatal(err)
	}
	exitScript, err := ExitTrustMtlsScript(certificate)
	if err != nil {
		t.Fatal(err)
	}
	inv := inventory.Default()
	inv.Exit.CascadeAddress = "172.29.10.11"
	switchScript, err := EntrySwitchNodeMtlsScript(inv)
	if err != nil {
		t.Fatal(err)
	}
	for name, script := range map[string]string{"entry-trust": entryScript, "exit-trust": exitScript, "entry-switch": switchScript} {
		cmd := exec.Command("sh", "-n")
		cmd.Stdin = strings.NewReader(script)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%s syntax: %v: %s", name, err, output)
		}
	}
	if !strings.Contains(switchScript, `tlsVerifyMode:"mtls"`) || !strings.Contains(switchScript, "clearApiToken:true") {
		t.Fatal("node switch does not fail closed to mTLS-only authentication")
	}
}
