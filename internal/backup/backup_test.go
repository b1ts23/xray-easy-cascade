// SPDX-License-Identifier: GPL-3.0-only

package backup

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
)

func TestCreateEncryptedBundle(t *testing.T) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "backup.age")
	if err := Create(path, identity.Recipient().String(), "test", []byte("entry-secret"), []byte("exit-secret"), time.Unix(1700000000, 0)); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("entry-secret")) || bytes.Contains(raw, []byte("exit-secret")) {
		t.Fatal("encrypted backup contains plaintext")
	}
	reader, err := age.Decrypt(bytes.NewReader(raw), identity)
	if err != nil {
		t.Fatal(err)
	}
	tarReader := tar.NewReader(reader)
	found := map[string]string{}
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(tarReader)
		if err != nil {
			t.Fatal(err)
		}
		found[header.Name] = string(data)
	}
	if found["entry.tar.gz"] != "entry-secret" || found["exit.tar.gz"] != "exit-secret" || !strings.Contains(found["manifest.json"], `"schema": 1`) {
		t.Fatalf("unexpected decrypted members: %#v", found)
	}
}

func TestGenerateIdentityProtectsFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.txt")
	recipient, err := GenerateIdentity(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(recipient, "age1") {
		t.Fatalf("unexpected recipient %q", recipient)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("identity mode=%o", info.Mode().Perm())
	}
	if _, err := GenerateIdentity(path); err == nil {
		t.Fatal("existing identity was overwritten")
	}
	derived, err := Recipient(path)
	if err != nil || derived != recipient {
		t.Fatalf("derived recipient=%q err=%v", derived, err)
	}
}

func TestVerifyEncryptedBundle(t *testing.T) {
	dir := t.TempDir()
	identityPath := filepath.Join(dir, "identity.txt")
	recipient, err := GenerateIdentity(identityPath)
	if err != nil {
		t.Fatal(err)
	}
	backupPath := filepath.Join(dir, "backup.age")
	if err := Create(backupPath, recipient, "verified-cluster", testNodeArchive(t, "entry", false), testNodeArchive(t, "exit", false), time.Unix(1700000000, 0)); err != nil {
		t.Fatal(err)
	}
	manifest, err := Verify(backupPath, identityPath)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Cluster != "verified-cluster" || len(manifest.Members) != 2 {
		t.Fatalf("unexpected manifest: %#v", manifest)
	}
}

func testNodeArchive(t *testing.T, role string, symlink bool) []byte {
	t.Helper()
	members := map[string][]byte{
		"./x-ui.db":            []byte("database"),
		"./node-manifest.json": nil,
	}
	manifest, err := json.Marshal(map[string]any{"schema": 1, "role": role})
	if err != nil {
		t.Fatal(err)
	}
	members["./node-manifest.json"] = manifest
	var checksums strings.Builder
	for _, name := range []string{"./node-manifest.json", "./x-ui.db"} {
		sum := sha256.Sum256(members[name])
		checksums.WriteString(hex.EncodeToString(sum[:]) + "  " + name + "\n")
	}
	members["./checksums.sha256"] = []byte(checksums.String())
	var buffer bytes.Buffer
	gzipWriter := gzip.NewWriter(&buffer)
	tarWriter := tar.NewWriter(gzipWriter)
	if err := tarWriter.WriteHeader(&tar.Header{Name: "./", Typeflag: tar.TypeDir, Mode: 0o700}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"./checksums.sha256", "./node-manifest.json", "./x-ui.db"} {
		data := members[name]
		if err := tarWriter.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o600, Size: int64(len(data))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tarWriter.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if symlink {
		if err := tarWriter.WriteHeader(&tar.Header{Name: "./panel.key", Typeflag: tar.TypeSymlink, Linkname: "/etc/shadow"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func TestNodeArchiveValidation(t *testing.T) {
	dir := t.TempDir()
	identityPath := filepath.Join(dir, "identity.txt")
	recipient, err := GenerateIdentity(identityPath)
	if err != nil {
		t.Fatal(err)
	}
	valid := testNodeArchive(t, "entry", false)
	backupPath := filepath.Join(dir, "valid.age")
	if err := Create(backupPath, recipient, "test", valid, testNodeArchive(t, "exit", false), time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := NodeArchive(backupPath, identityPath, "entry"); err != nil {
		t.Fatal(err)
	}
	maliciousPath := filepath.Join(dir, "symlink.age")
	if err := Create(maliciousPath, recipient, "test", testNodeArchive(t, "entry", true), testNodeArchive(t, "exit", false), time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := NodeArchive(maliciousPath, identityPath, "entry"); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("symlink member was accepted: %v", err)
	}
}

func TestExportScriptSyntax(t *testing.T) {
	script, err := ExportScript("exit", "https", "/exit/panel/", "-k")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", "-n")
	cmd.Stdin = strings.NewReader(script)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("syntax: %v: %s", err, output)
	}
	if !strings.Contains(script, "/server/getDb") || !strings.Contains(script, "node_token_key.json") {
		t.Fatal("export omits required state")
	}
}

func TestRestoreScriptSyntax(t *testing.T) {
	script, err := RestoreScript("entry", "http", "/entry/panel/", "")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", "-n")
	cmd.Stdin = strings.NewReader(script)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("syntax: %v: %s", err, output)
	}
	for _, required := range []string{"importDB", "sha256sum -c", "--no-same-owner", "3XUI_BACKUP_RESTORED"} {
		if !strings.Contains(script, required) {
			t.Fatalf("restore omits %q", required)
		}
	}
}
