// SPDX-License-Identifier: GPL-3.0-only

package command

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/b1ts23/xray-easy-cascade/internal/inventory"
)

func TestDeployIsDisabled(t *testing.T) {
	err := Run([]string{"deploy"}, strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
	if !errors.Is(err, ErrNotImplemented) || ExitCode(err) != 2 {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestWriteReadyMarkersHidesInternalMaterial(t *testing.T) {
	var output bytes.Buffer
	writeReadyMarkers(&output, "3XUI_ENTRY_CONFIG_READY\n3XUI_NODE_TOKEN\tsecret\n3XUI_NODE_PIN\tabcd\n3XUI_EXIT_CERT\tcert\n3XUI_MTLS_CA\tca\n")
	if output.String() != "3XUI_ENTRY_CONFIG_READY\n" {
		t.Fatalf("unexpected markers: %q", output.String())
	}
}

func TestInitSelectsReferenceACMEIPLayout(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "inventory.yml")
	input := strings.Join([]string{
		"test-cascade",
		"203.0.113.10",
		"198.51.100.20",
		"",
		"",
		"",
		"",
		"",
	}, "\n")
	if err := Run([]string{"init", "--output", path}, strings.NewReader(input), &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	inv, err := inventory.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if inv.Certificates.SubscriptionTLS != "acme-ip" {
		t.Fatalf("unexpected certificate defaults: %#v", inv.Certificates)
	}
}

func TestProductionRollbackIsDisabled(t *testing.T) {
	err := Run([]string{"rollback"}, strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
	if !errors.Is(err, ErrNotImplemented) || ExitCode(err) != 2 {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestProductionBackupIsDisabled(t *testing.T) {
	err := Run([]string{"backup"}, strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
	if !errors.Is(err, ErrNotImplemented) || ExitCode(err) != 2 {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestProductionRestoreIsDisabled(t *testing.T) {
	err := Run([]string{"restore"}, strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
	if !errors.Is(err, ErrNotImplemented) || ExitCode(err) != 2 {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestProductionDiagnosticsAreDisabled(t *testing.T) {
	for _, name := range []string{"status", "verify"} {
		err := Run([]string{name}, strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
		if !errors.Is(err, ErrNotImplemented) || ExitCode(err) != 2 {
			t.Fatalf("%s: unexpected error: %v", name, err)
		}
	}
	if ExitCode(ErrVerificationFailed) != 4 {
		t.Fatalf("verification exit code = %d", ExitCode(ErrVerificationFailed))
	}
}

func TestBackupKeygenAndVerify(t *testing.T) {
	dir := t.TempDir()
	identity := filepath.Join(dir, "backup-identity.txt")
	var out bytes.Buffer
	if err := Run([]string{"backup-keygen", "--output", identity}, strings.NewReader(""), &out, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "recipient=age1") {
		t.Fatalf("public recipient missing: %s", out.String())
	}
	if info, err := os.Stat(identity); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("identity is not protected: info=%v err=%v", info, err)
	}
}

func TestPanelPrintURLDoesNotConnect(t *testing.T) {
	dir := t.TempDir()
	identity := filepath.Join(dir, "id_ed25519")
	knownHosts := filepath.Join(dir, "known_hosts")
	for _, path := range []string{identity, knownHosts} {
		if err := os.WriteFile(path, []byte("fixture"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	inventoryPath := filepath.Join(dir, "inventory.yml")
	inv := inventory.Default()
	inv.Entry.Host = "203.0.113.10"
	inv.Exit.Host = "198.51.100.20"
	inv.Entry.SSHIdentityFile = identity
	inv.Exit.SSHIdentityFile = identity
	if err := inventory.Save(inventoryPath, inv); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := Run([]string{"panel", "--print-url", "--local-port", "12053", "--inventory", inventoryPath, "--known-hosts", knownHosts}, strings.NewReader(""), &out, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(out.String()) != "http://127.0.0.1:12053/entry/panel/" {
		t.Fatalf("unexpected panel URL: %q", out.String())
	}
	out.Reset()
	if err := Run([]string{"panel", "exit", "--print-url", "--inventory", inventoryPath, "--known-hosts", knownHosts}, strings.NewReader(""), &out, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(out.String()) != "https://127.0.0.1:12054/exit/panel/" {
		t.Fatalf("unexpected exit panel URL: %q", out.String())
	}
}

func TestAccessPrintsObviousProtectedHandoff(t *testing.T) {
	dir := t.TempDir()
	inventoryPath := filepath.Join(dir, "inventory.yml")
	handoff := filepath.Join(dir, "xray-cascade-access.txt")
	if err := os.WriteFile(handoff, []byte("both panel credentials\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := Run([]string{"access", "--inventory", inventoryPath}, strings.NewReader(""), &out, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "both panel credentials") || !strings.Contains(out.String(), handoff) {
		t.Fatalf("unexpected access output: %s", out.String())
	}
}

func TestLabDeployRejectsPublicTargetsBeforeSSH(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "inventory.yml")
	inv := `schema: 1
cluster:
  name: unsafe-lab
  routing_profile: cascade-all
entry:
  host: 203.0.113.10
  cascade_address: 172.29.10.10
  ssh_user: root
  ssh_port: 2201
  ssh_identity_file: /missing/key
  public_ipv6: disabled
exit:
  host: 127.0.0.1
  cascade_address: 172.29.10.11
  ssh_user: root
  ssh_port: 2202
  ssh_identity_file: /missing/key
  public_ipv6: disabled
panel:
  access: ssh-tunnel
subscription: {}
transport:
  client: reality-vision-tcp
  client_port: 10443
  interserver: reality-vision-tcp
  interserver_port: 11443
  prefer_interserver: ipv4
  ipv6_fallback: disabled
  client_reality:
    target: example.com:443
    server_name: example.com
  interserver_reality:
    target: example.net:443
    server_name: example.net
`
	if err := os.WriteFile(path, []byte(inv), 0o600); err != nil {
		t.Fatal(err)
	}
	err := Run([]string{"deploy", "--lab", "--yes", "--inventory", path, "--proxy-jump", "root@example.test:22"}, strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("public target was not rejected by lab boundary: %v", err)
	}
}

func TestInitAndPlan(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "inventory.yml")
	input := strings.Join([]string{
		"demo",
		"203.0.113.10",
		"198.51.100.20",
		"",
		"",
		"",
		"",
	}, "\n") + "\n"

	var initOut bytes.Buffer
	if err := Run([]string{"init", "--output", path}, strings.NewReader(input), &initOut, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}

	var planOut bytes.Buffer
	if err := Run([]string{"plan", "--inventory", path}, strings.NewReader(""), &planOut, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(planOut.String(), "no SSH connections, no server changes") {
		t.Fatalf("unsafe or incomplete plan output: %s", planOut.String())
	}
	if !strings.Contains(planOut.String(), "run vpnctl preflight") {
		t.Fatalf("plan does not point to preflight: %s", planOut.String())
	}
}

func TestPreflightUsesNonInteractiveSSHForBothNodes(t *testing.T) {
	dir := t.TempDir()
	sshBin := filepath.Join(dir, "ssh")
	sshFixture := `#!/bin/sh
cat >/dev/null
cat <<'EOF'
schema	1
uid	0
os_id	ubuntu
os_version	24.04
arch	x86_64
kernel	6.8.0
pid1	lab-entrypoint
systemd	no
apt_get	yes
curl	yes
ss	yes
ipv4_default	yes
ipv6_global	no
port_443	free
memory_kib	2097152
memory_limit_bytes	402653184
disk_available_kib	10485760
ufw	absent
EOF
`
	if err := os.WriteFile(sshBin, []byte(sshFixture), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	identity := filepath.Join(dir, "id_ed25519")
	knownHosts := filepath.Join(dir, "known hosts")
	for _, path := range []string{identity, knownHosts} {
		if err := os.WriteFile(path, []byte("fixture"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	inventoryPath := filepath.Join(dir, "inventory.yml")
	inventoryYAML := `schema: 1
cluster:
  name: test
  routing_profile: cascade-all
entry:
  host: 127.0.0.1
  ssh_user: root
  ssh_port: 2201
  ssh_identity_file: ` + identity + `
  public_ipv6: disabled
exit:
  host: 127.0.0.1
  ssh_user: root
  ssh_port: 2202
  ssh_identity_file: ` + identity + `
  public_ipv6: disabled
panel:
  access: ssh-tunnel
  public_domain: ""
subscription:
  public_domain: ""
transport:
  client: reality-vision-tcp
  interserver: reality-vision-tcp
  prefer_interserver: ipv4
  ipv6_fallback: disabled
`
	if err := os.WriteFile(inventoryPath, []byte(inventoryYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	err := Run([]string{"preflight", "--inventory", inventoryPath, "--known-hosts", knownHosts, "--lab"}, strings.NewReader(""), &out, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	text := out.String()
	if strings.Count(text, "LAB_READY") != 2 || !strings.Contains(text, "read-only SSH") {
		t.Fatalf("unexpected output: %s", text)
	}
}

func TestPreflightBlockedExitCode(t *testing.T) {
	if ExitCode(ErrPreflightBlocked) != 3 {
		t.Fatalf("exit code = %d, want 3", ExitCode(ErrPreflightBlocked))
	}
}
