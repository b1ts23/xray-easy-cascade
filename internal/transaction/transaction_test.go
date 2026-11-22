// SPDX-License-Identifier: GPL-3.0-only

package transaction

import (
	"os/exec"
	"strings"
	"testing"
)

func TestNewID(t *testing.T) {
	id, err := NewID()
	if err != nil {
		t.Fatal(err)
	}
	if len(id) != 32 || strings.Trim(id, "0123456789abcdef") != "" {
		t.Fatalf("unsafe transaction ID %q", id)
	}
}

func TestGeneratedScriptsPassShellSyntax(t *testing.T) {
	endpoint := Endpoint{Scheme: "https", BasePath: "/exit/panel/", CurlTLS: "-k"}
	id := strings.Repeat("c", 32)
	scripts := []struct {
		name string
		fn   func(string, string, string, Endpoint) (string, error)
	}{{"begin", BeginScript}, {"commit", CommitScript}, {"rollback", RollbackScript}}
	for _, item := range scripts {
		script, err := item.fn("container-lab", "exit", id, endpoint)
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("sh", "-n")
		cmd.Stdin = strings.NewReader(script)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%s script syntax: %v: %s", item.name, err, output)
		}
	}
}

func TestScriptsUseAPIBackupAndScopedOwnership(t *testing.T) {
	endpoint := Endpoint{Scheme: "https", BasePath: "/exit/panel/", CurlTLS: "-k"}
	begin, err := BeginScript("container-lab", "exit", strings.Repeat("a", 32), endpoint)
	if err != nil {
		t.Fatal(err)
	}
	rollback, err := RollbackScript("container-lab", "exit", strings.Repeat("a", 32), endpoint)
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"/server/getDb", "ownership.json", "databaseSHA256", "roscom-geoip.dat"} {
		if !strings.Contains(begin, required) {
			t.Fatalf("begin script missing %q", required)
		}
	}
	for _, required := range []string{"/server/importDB", "keepHostSettings=false", "databaseSHA256", "ROLLED_BACK"} {
		if !strings.Contains(rollback, required) {
			t.Fatalf("rollback script missing %q", required)
		}
	}
	if strings.Contains(begin, "rm -rf /etc") || strings.Contains(rollback, "rm -rf /etc") {
		t.Fatal("transaction script contains broad destructive removal")
	}
}

func TestScriptsRejectUnsafeMetadata(t *testing.T) {
	endpoint := Endpoint{Scheme: "http", BasePath: "/entry/panel/"}
	for _, cluster := range []string{"", "bad cluster", "../bad"} {
		if _, err := BeginScript(cluster, "entry", strings.Repeat("a", 32), endpoint); err == nil {
			t.Fatalf("accepted unsafe cluster %q", cluster)
		}
	}
	if _, err := BeginScript("safe", "entry", "not-an-id", endpoint); err == nil {
		t.Fatal("accepted unsafe transaction ID")
	}
}

func TestParseCurrentID(t *testing.T) {
	id := strings.Repeat("b", 32)
	got, err := ParseCurrentID("noise\n" + currentIDPrefix + id + "\n")
	if err != nil || got != id {
		t.Fatalf("got=%q err=%v", got, err)
	}
	if _, err := ParseCurrentID(currentIDPrefix + "unsafe"); err == nil {
		t.Fatal("accepted unsafe current transaction ID")
	}
	got, err = ParseCurrentID("3XUI_TRANSACTION_NONE\n")
	if err != nil || got != "" {
		t.Fatalf("empty transaction got=%q err=%v", got, err)
	}
	if _, err := ParseCurrentID("3XUI_TRANSACTION_NONE\n" + currentIDPrefix + id); err == nil {
		t.Fatal("accepted conflicting transaction markers")
	}
}
