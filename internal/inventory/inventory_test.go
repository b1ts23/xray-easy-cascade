// SPDX-License-Identifier: GPL-3.0-only

package inventory

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultRequiresHosts(t *testing.T) {
	err := Default().Validate()
	if err == nil || !strings.Contains(err.Error(), "entry.host is required") || !strings.Contains(err.Error(), "exit.host is required") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	inv := Default()
	inv.Entry.Host = "203.0.113.10"
	inv.Exit.Host = "198.51.100.20"
	path := filepath.Join(t.TempDir(), "inventory.yml")
	if err := Save(path, inv); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o, want 600", info.Mode().Perm())
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Entry.Host != inv.Entry.Host || got.Exit.Host != inv.Exit.Host {
		t.Fatalf("round trip mismatch: %#v", got)
	}
}

func TestSaveReplacesPermissiveFileWithMode0600(t *testing.T) {
	inv := Default()
	inv.Entry.Host = "203.0.113.10"
	inv.Exit.Host = "198.51.100.20"
	path := filepath.Join(t.TempDir(), "inventory.yml")
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Save(path, inv); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o, want 600", info.Mode().Perm())
	}
}

func TestSaveRejectsSymbolicLink(t *testing.T) {
	inv := Default()
	inv.Entry.Host = "203.0.113.10"
	inv.Exit.Host = "198.51.100.20"
	dir := t.TempDir()
	target := filepath.Join(dir, "target.yml")
	if err := os.WriteFile(target, []byte("do not replace"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "inventory.yml")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := Save(link, inv); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("unexpected error: %v", err)
	}
	raw, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "do not replace" {
		t.Fatalf("symlink target was changed: %q", raw)
	}
}

func TestLoadRejectsUnknownFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "inventory.yml")
	raw := `schema: 1
cluster:
  name: test
  routing_profile: roscomvpn-default
  typo: true
`
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "field typo not found") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSameHostRejected(t *testing.T) {
	inv := Default()
	inv.Entry.Host = "203.0.113.10"
	inv.Exit.Host = inv.Entry.Host
	if err := inv.Validate(); err == nil || !strings.Contains(err.Error(), "endpoints must be different") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSameHostDifferentSSHPortsAcceptedForLab(t *testing.T) {
	inv := Default()
	inv.Entry.Host = "127.0.0.1"
	inv.Entry.SSHPort = 2201
	inv.Exit.Host = "127.0.0.1"
	inv.Exit.SSHPort = 2202
	if err := inv.Validate(); err != nil {
		t.Fatalf("distinct SSH endpoints should be valid: %v", err)
	}
}

func TestCascadeAllRoutingProfileAccepted(t *testing.T) {
	inv := Default()
	inv.Cluster.RoutingProfile = "cascade-all"
	inv.Entry.Host = "203.0.113.10"
	inv.Exit.Host = "198.51.100.20"
	if err := inv.Validate(); err != nil {
		t.Fatalf("cascade-all should be valid: %v", err)
	}
}

func TestACMEIPRequiresPublicIPv4Hosts(t *testing.T) {
	inv := Default()
	inv.Entry.Host = "entry.example.com"
	inv.Exit.Host = "198.51.100.20"
	inv.Certificates.SubscriptionTLS = "acme-ip"
	err := inv.Validate()
	if err == nil || !strings.Contains(err.Error(), "entry.host must be an explicit public IPv4 address for acme-ip") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestClientAlternativesAreValidated(t *testing.T) {
	inv := Default()
	inv.Entry.Host = "203.0.113.10"
	inv.Exit.Host = "198.51.100.20"
	inv.Transport.ClientAlternatives = []ClientAlternative{{Kind: "reality-xhttp", Port: 8443}}
	if err := inv.Validate(); err != nil {
		t.Fatalf("valid XHTTP alternative rejected: %v", err)
	}
	if got := inv.ClientAlternativePort("reality-xhttp"); got != 8443 {
		t.Fatalf("XHTTP port = %d, want 8443", got)
	}
	inv.Transport.ClientAlternatives = append(inv.Transport.ClientAlternatives, ClientAlternative{Kind: "reality-xhttp", Port: 8446})
	if err := inv.Validate(); err == nil || !strings.Contains(err.Error(), "kind must be unique") {
		t.Fatalf("duplicate alternative accepted: %v", err)
	}

	inv.Transport.ClientAlternatives = []ClientAlternative{{Kind: "reality-xhttp", Port: inv.Transport.ClientPort}}
	if err := inv.Validate(); err == nil || !strings.Contains(err.Error(), "conflicts with primary client transport") {
		t.Fatalf("conflicting alternative port accepted: %v", err)
	}

	for _, kind := range []string{"reality-xhttp-pq", "reality-grpc"} {
		inv.Transport.ClientAlternatives = []ClientAlternative{{Kind: kind, Port: 8444}}
		if err := inv.Validate(); err == nil || !strings.Contains(err.Error(), "experimental") {
			t.Fatalf("experimental alternative %s accepted: %v", kind, err)
		}
	}
}

func TestInterserverAlternativesAreValidated(t *testing.T) {
	inv := Default()
	inv.Entry.Host = "203.0.113.10"
	inv.Exit.Host = "198.51.100.20"
	inv.Transport.InterserverAlternatives = []InterserverAlternative{{Kind: "reality-xhttp", Port: 8443}}
	if err := inv.Validate(); err == nil || !strings.Contains(err.Error(), "experimental") {
		t.Fatalf("experimental interserver XHTTP alternative accepted: %v", err)
	}
	if got := inv.InterserverAlternativePort("reality-xhttp"); got != 8443 {
		t.Fatalf("interserver XHTTP port = %d, want 8443", got)
	}
	inv.Transport.InterserverAlternatives = append(inv.Transport.InterserverAlternatives, InterserverAlternative{Kind: "reality-xhttp", Port: 8444})
	if err := inv.Validate(); err == nil || !strings.Contains(err.Error(), "kind must be unique") {
		t.Fatalf("duplicate interserver alternative accepted: %v", err)
	}
	inv.Transport.InterserverAlternatives = []InterserverAlternative{{Kind: "reality-xhttp", Port: inv.Transport.InterserverPort}}
	if err := inv.Validate(); err == nil || !strings.Contains(err.Error(), "exit port") {
		t.Fatalf("conflicting interserver port accepted: %v", err)
	}
}

func TestNodeLocalPortConflictsAreRejected(t *testing.T) {
	inv := Default()
	inv.Entry.Host = "203.0.113.10"
	inv.Exit.Host = "198.51.100.20"
	inv.Transport.ClientAlternatives = []ClientAlternative{{Kind: "reality-xhttp", Port: inv.Subscription.Port}}
	err := inv.Validate()
	if err == nil || !strings.Contains(err.Error(), "entry port") || !strings.Contains(err.Error(), "subscription") {
		t.Fatalf("node-local collision accepted: %v", err)
	}
}

func TestHysteria2IsRejectedByReleasedProfile(t *testing.T) {
	inv := Default()
	inv.Entry.Host = "203.0.113.10"
	inv.Exit.Host = "198.51.100.20"
	inv.Certificates.SubscriptionTLS = "acme-ip"
	inv.Transport.Hysteria2 = Hysteria2{Enabled: true, Port: inv.Transport.ClientPort}
	if err := inv.Validate(); err == nil || !strings.Contains(err.Error(), "experimental") {
		t.Fatalf("experimental HY2 accepted: %v", err)
	}
	inv.Certificates.SubscriptionTLS = "pending"
	if err := inv.Validate(); err == nil || !strings.Contains(err.Error(), "requires subscription_tls existing or acme-ip") {
		t.Fatalf("HY2 without TLS accepted: %v", err)
	}
}
