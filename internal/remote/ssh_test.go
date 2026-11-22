// SPDX-License-Identifier: GPL-3.0-only

package remote

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestArgsEnforceStrictReadOnlyTransport(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "path with spaces")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	knownHosts := filepath.Join(dir, "known_hosts")
	identity := filepath.Join(dir, "id_ed25519")
	for _, path := range []string{knownHosts, identity} {
		if err := os.WriteFile(path, []byte("fixture"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	runner, err := NewOpenSSH(knownHosts, "jump@example.test:2222")
	if err != nil {
		t.Fatal(err)
	}
	args, err := runner.Args(Target{Host: "node.example.test", User: "root", Port: 22, IdentityFile: identity})
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"BatchMode=yes", "PasswordAuthentication=no", "StrictHostKeyChecking=yes", "IdentitiesOnly=yes", "-J", "jump@example.test:2222", "sh", "-s"} {
		if !slices.Contains(args, required) {
			t.Fatalf("missing %q in %#v", required, args)
		}
	}
	wantKnownHosts := `UserKnownHostsFile="` + knownHosts + `"`
	if !slices.Contains(args, wantKnownHosts) {
		t.Fatalf("known_hosts path was not config-quoted: %#v", args)
	}
}

func TestArgsRejectUnsafeTarget(t *testing.T) {
	dir := t.TempDir()
	knownHosts := filepath.Join(dir, "known_hosts")
	identity := filepath.Join(dir, "id")
	for _, path := range []string{knownHosts, identity} {
		if err := os.WriteFile(path, []byte("fixture"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	runner, err := NewOpenSSH(knownHosts, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Args(Target{Host: "-oProxyCommand=bad", User: "root", Port: 22, IdentityFile: identity}); err == nil {
		t.Fatal("unsafe host was accepted")
	}
}

func TestTunnelArgsAreLoopbackOnly(t *testing.T) {
	dir := t.TempDir()
	knownHosts := filepath.Join(dir, "known_hosts")
	identity := filepath.Join(dir, "id")
	for _, path := range []string{knownHosts, identity} {
		if err := os.WriteFile(path, []byte("fixture"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	runner, err := NewOpenSSH(knownHosts, "jump@example.test:22")
	if err != nil {
		t.Fatal(err)
	}
	args, err := runner.TunnelArgs(Target{Host: "entry.example.test", User: "root", Port: 22, IdentityFile: identity}, 12053, 2053)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, " ")
	for _, required := range []string{"-N", "ExitOnForwardFailure=yes", "127.0.0.1:12053:127.0.0.1:2053", "root@entry.example.test"} {
		if !strings.Contains(joined, required) {
			t.Fatalf("tunnel args missing %q: %s", required, joined)
		}
	}
	if strings.Contains(joined, "0.0.0.0") || slices.Contains(args, "sh") {
		t.Fatalf("unsafe tunnel args: %s", joined)
	}
}
