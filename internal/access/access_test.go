// SPDX-License-Identifier: GPL-3.0-only

package access

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testSummary() Summary {
	return Summary{
		Cluster:          "my-cascade",
		Entry:            Panel{Role: "entry", Username: "entry-user", Password: "entry-secret", Port: 2053, WebBasePath: "/entry/panel/", AccessURL: "https://127.0.0.1:12053/entry/panel/", OpenCommand: "vpnctl panel entry"},
		Exit:             Panel{Role: "exit", Username: "exit-user", Password: "exit-secret", Port: 2053, WebBasePath: "/exit/panel/", AccessURL: "https://127.0.0.1:12054/exit/panel/", OpenCommand: "vpnctl panel exit"},
		HappSubscription: "https://203.0.113.10:2096/sub/id",
	}
}

func TestPrintShowsBothPanelsAndHAPPInTerminal(t *testing.T) {
	var out bytes.Buffer
	if err := Print(&out, testSummary()); err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"3x-ui panel:  entry", "entry-user", "entry-secret", "3x-ui panel:  exit", "exit-user", "exit-secret", "HAPP subscription", "https://203.0.113.10:2096/sub/id"} {
		if !strings.Contains(out.String(), expected) {
			t.Fatalf("terminal handoff missing %q:\n%s", expected, out.String())
		}
	}
	if strings.Contains(strings.ToLower(out.String()), "api token") {
		t.Fatal("terminal handoff must not expose an API token")
	}
}

func TestSaveCreatesObviousRootOnlyRecoveryFile(t *testing.T) {
	dir := t.TempDir()
	path := DefaultPath(filepath.Join(dir, "inventory.yml"))
	if filepath.Base(path) != "xray-cascade-access.txt" {
		t.Fatalf("unexpected recovery path: %s", path)
	}
	if err := Save(path, testSummary()); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("recovery file mode=%o", info.Mode().Perm())
	}
}
