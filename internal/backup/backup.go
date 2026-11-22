// SPDX-License-Identifier: GPL-3.0-only

package backup

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"filippo.io/age"
)

const MaxNodeExportBytes int64 = 128 * 1024 * 1024

type Member struct {
	Name   string `json:"name"`
	Size   int    `json:"size"`
	SHA256 string `json:"sha256"`
}

type Manifest struct {
	Schema    int      `json:"schema"`
	Cluster   string   `json:"cluster"`
	CreatedAt string   `json:"createdAt"`
	Members   []Member `json:"members"`
}

func recipientFromIdentity(path string) (*age.X25519Identity, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect backup identity: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("backup identity must be a regular file, not a symbolic link")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("backup identity permissions must not allow group or other access")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read backup identity: %w", err)
	}
	identity, err := age.ParseX25519Identity(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, fmt.Errorf("parse backup identity: %w", err)
	}
	return identity, nil
}

// Recipient returns the public recipient for an existing protected identity.
func Recipient(identityPath string) (string, error) {
	identity, err := recipientFromIdentity(identityPath)
	if err != nil {
		return "", err
	}
	return identity.Recipient().String(), nil
}

func GenerateIdentity(path string) (string, error) {
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return "", errors.New("refusing to replace backup identity through a symbolic link")
		}
		return "", errors.New("backup identity already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		return "", fmt.Errorf("generate age identity: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", fmt.Errorf("create identity directory: %w", err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", fmt.Errorf("create backup identity: %w", err)
	}
	ok := false
	defer func() {
		_ = file.Close()
		if !ok {
			_ = os.Remove(path)
		}
	}()
	if _, err := io.WriteString(file, identity.String()+"\n"); err != nil {
		return "", err
	}
	if err := file.Sync(); err != nil {
		return "", err
	}
	if err := file.Close(); err != nil {
		return "", err
	}
	ok = true
	return identity.Recipient().String(), nil
}

func Create(path, recipientText, cluster string, entryExport, exitExport []byte, now time.Time) error {
	recipient, err := age.ParseX25519Recipient(strings.TrimSpace(recipientText))
	if err != nil {
		return fmt.Errorf("parse age recipient: %w", err)
	}
	if strings.TrimSpace(cluster) == "" {
		return errors.New("backup cluster is required")
	}
	if len(entryExport) == 0 || len(exitExport) == 0 {
		return errors.New("both node exports are required")
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("refusing to replace backup through a symbolic link")
		}
		return errors.New("backup output already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".xray-cascade-backup-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	ok := false
	defer func() {
		_ = tmp.Close()
		if !ok {
			_ = os.Remove(tmpPath)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		return err
	}
	encrypted, err := age.Encrypt(tmp, recipient)
	if err != nil {
		return fmt.Errorf("initialize backup encryption: %w", err)
	}
	members := []struct {
		name string
		data []byte
	}{{"entry.tar.gz", entryExport}, {"exit.tar.gz", exitExport}}
	manifest := Manifest{Schema: 1, Cluster: cluster, CreatedAt: now.UTC().Format(time.RFC3339)}
	for _, item := range members {
		sum := sha256.Sum256(item.data)
		manifest.Members = append(manifest.Members, Member{Name: item.name, Size: len(item.data), SHA256: hex.EncodeToString(sum[:])})
	}
	manifestRaw, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	tarWriter := tar.NewWriter(encrypted)
	writeMember := func(name string, data []byte) error {
		header := &tar.Header{Name: name, Mode: 0o600, Size: int64(len(data)), ModTime: now.UTC(), Typeflag: tar.TypeReg}
		if err := tarWriter.WriteHeader(header); err != nil {
			return err
		}
		_, err := tarWriter.Write(data)
		return err
	}
	if err := writeMember("manifest.json", manifestRaw); err != nil {
		return err
	}
	for _, item := range members {
		if err := writeMember(item.name, item.data); err != nil {
			return err
		}
	}
	if err := tarWriter.Close(); err != nil {
		return err
	}
	if err := encrypted.Close(); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	ok = true
	return nil
}

// Verify decrypts a backup in memory and validates its manifest without
// extracting any member to disk. It returns metadata only, never secret data.
func Verify(path, identityPath string) (Manifest, error) {
	identity, err := recipientFromIdentity(identityPath)
	if err != nil {
		return Manifest{}, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return Manifest{}, fmt.Errorf("inspect backup: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return Manifest{}, errors.New("backup must be a regular file, not a symbolic link")
	}
	file, err := os.Open(path)
	if err != nil {
		return Manifest{}, fmt.Errorf("open backup: %w", err)
	}
	decrypted, err := age.Decrypt(file, identity)
	if err != nil {
		_ = file.Close()
		return Manifest{}, fmt.Errorf("decrypt backup: %w", err)
	}
	tarReader := tar.NewReader(decrypted)
	members := make(map[string][]byte, 3)
	for {
		header, nextErr := tarReader.Next()
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil {
			_ = file.Close()
			return Manifest{}, fmt.Errorf("read backup archive: %w", nextErr)
		}
		if header.Typeflag != tar.TypeReg || (header.Name != "manifest.json" && header.Name != "entry.tar.gz" && header.Name != "exit.tar.gz") {
			_ = file.Close()
			return Manifest{}, fmt.Errorf("backup contains unexpected member %q", header.Name)
		}
		if _, exists := members[header.Name]; exists {
			_ = file.Close()
			return Manifest{}, fmt.Errorf("backup contains duplicate member %q", header.Name)
		}
		if header.Size < 0 || header.Size > MaxNodeExportBytes {
			_ = file.Close()
			return Manifest{}, fmt.Errorf("backup member %q exceeds safety limit", header.Name)
		}
		data, readErr := io.ReadAll(io.LimitReader(tarReader, header.Size+1))
		if readErr != nil || int64(len(data)) != header.Size {
			_ = file.Close()
			return Manifest{}, fmt.Errorf("read backup member %q", header.Name)
		}
		members[header.Name] = data
	}
	if err := file.Close(); err != nil {
		return Manifest{}, err
	}
	if len(members) != 3 {
		return Manifest{}, errors.New("backup must contain manifest, entry, and exit members")
	}
	var manifest Manifest
	decoder := json.NewDecoder(bytes.NewReader(members["manifest.json"]))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return Manifest{}, fmt.Errorf("parse backup manifest: %w", err)
	}
	if manifest.Schema != 1 || strings.TrimSpace(manifest.Cluster) == "" || len(manifest.Members) != 2 {
		return Manifest{}, errors.New("backup manifest is invalid")
	}
	seen := make(map[string]bool, 2)
	for _, member := range manifest.Members {
		if member.Name != "entry.tar.gz" && member.Name != "exit.tar.gz" {
			return Manifest{}, fmt.Errorf("manifest contains unexpected member %q", member.Name)
		}
		if seen[member.Name] {
			return Manifest{}, fmt.Errorf("manifest contains duplicate member %q", member.Name)
		}
		seen[member.Name] = true
		data := members[member.Name]
		sum := sha256.Sum256(data)
		if member.Size != len(data) || member.SHA256 != hex.EncodeToString(sum[:]) {
			return Manifest{}, fmt.Errorf("backup member %q failed checksum validation", member.Name)
		}
	}
	for _, role := range []string{"entry", "exit"} {
		if err := validateNodeArchive(members[role+".tar.gz"], role); err != nil {
			return Manifest{}, err
		}
	}
	return manifest, nil
}

// NodeArchive returns one authenticated inner node archive after validating the
// complete outer backup. The caller must keep the returned plaintext in memory.
func NodeArchive(path, identityPath, role string) ([]byte, error) {
	if role != "entry" && role != "exit" {
		return nil, errors.New("backup role must be entry or exit")
	}
	if _, err := Verify(path, identityPath); err != nil {
		return nil, err
	}
	identity, err := recipientFromIdentity(identityPath)
	if err != nil {
		return nil, err
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	decrypted, err := age.Decrypt(file, identity)
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	wanted := role + ".tar.gz"
	tarReader := tar.NewReader(decrypted)
	for {
		header, nextErr := tarReader.Next()
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil {
			_ = file.Close()
			return nil, nextErr
		}
		if header.Name != wanted {
			continue
		}
		data, readErr := io.ReadAll(io.LimitReader(tarReader, MaxNodeExportBytes+1))
		_ = file.Close()
		if readErr != nil || int64(len(data)) != header.Size || int64(len(data)) > MaxNodeExportBytes {
			return nil, fmt.Errorf("read %s node archive", role)
		}
		if err := validateNodeArchive(data, role); err != nil {
			return nil, err
		}
		return data, nil
	}
	_ = file.Close()
	return nil, fmt.Errorf("backup is missing %s node archive", role)
}

func validateNodeArchive(raw []byte, role string) error {
	gzipReader, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("open %s node archive: %w", role, err)
	}
	tarReader := tar.NewReader(gzipReader)
	allowed := map[string]bool{
		"./": true, "./checksums.sha256": true, "./node-manifest.json": true, "./x-ui.db": true,
		"./ownership.json": true, "./node_token_key.json": true, "./subscription.crt": true,
		"./subscription.key": true, "./panel.crt": true, "./panel.key": true,
		"./panel-ca.crt": true, "./panel-ca.key": true, "./exit-node-ca.crt": true,
		"./exit-trust.crt": true, "./roscom-geoip.dat": true, "./roscom-geosite.dat": true,
		"./x-ui.service": true, "./x-ui-sandbox.conf": true, "./ufw-user.rules": true,
		"./ufw-user6.rules": true, "./bootstrap-credentials": true,
	}
	members := make(map[string][]byte, len(allowed))
	var total int64
	for {
		header, nextErr := tarReader.Next()
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil {
			return fmt.Errorf("read %s node archive: %w", role, nextErr)
		}
		if !allowed[header.Name] {
			return fmt.Errorf("%s node archive contains unexpected member %q", role, header.Name)
		}
		if _, duplicate := members[header.Name]; duplicate {
			return fmt.Errorf("%s node archive contains duplicate member %q", role, header.Name)
		}
		if header.Name == "./" {
			if header.Typeflag != tar.TypeDir {
				return fmt.Errorf("%s node archive root is not a directory", role)
			}
			members[header.Name] = nil
			continue
		}
		if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA {
			return fmt.Errorf("%s node archive member %q is not a regular file", role, header.Name)
		}
		if header.Size < 0 || total+header.Size > MaxNodeExportBytes {
			return fmt.Errorf("%s node archive exceeds safety limit", role)
		}
		data, readErr := io.ReadAll(io.LimitReader(tarReader, header.Size+1))
		if readErr != nil || int64(len(data)) != header.Size {
			return fmt.Errorf("read %s node member %q", role, header.Name)
		}
		total += header.Size
		members[header.Name] = data
	}
	if err := gzipReader.Close(); err != nil {
		return fmt.Errorf("close %s node archive: %w", role, err)
	}
	for _, required := range []string{"./checksums.sha256", "./node-manifest.json", "./x-ui.db"} {
		if len(members[required]) == 0 {
			return fmt.Errorf("%s node archive is missing %q", role, required)
		}
	}
	var nodeManifest struct {
		Schema int    `json:"schema"`
		Role   string `json:"role"`
	}
	if err := json.Unmarshal(members["./node-manifest.json"], &nodeManifest); err != nil || nodeManifest.Schema != 1 || nodeManifest.Role != role {
		return fmt.Errorf("%s node manifest is invalid", role)
	}
	checked := make(map[string]bool, len(members))
	for _, line := range strings.Split(strings.TrimSpace(string(members["./checksums.sha256"])), "\n") {
		parts := strings.SplitN(line, "  ", 2)
		if len(parts) != 2 || len(parts[0]) != 64 || !strings.HasPrefix(parts[1], "./") {
			return fmt.Errorf("%s node checksum manifest is invalid", role)
		}
		if _, err := hex.DecodeString(parts[0]); err != nil {
			return fmt.Errorf("%s node checksum manifest is invalid", role)
		}
		data, exists := members[parts[1]]
		if !exists || parts[1] == "./checksums.sha256" || checked[parts[1]] {
			return fmt.Errorf("%s node checksum member %q is invalid", role, parts[1])
		}
		sum := sha256.Sum256(data)
		if parts[0] != hex.EncodeToString(sum[:]) {
			return fmt.Errorf("%s node member %q failed checksum validation", role, parts[1])
		}
		checked[parts[1]] = true
	}
	for name := range members {
		if name != "./" && name != "./checksums.sha256" && !checked[name] {
			return fmt.Errorf("%s node member %q has no checksum", role, name)
		}
	}
	return nil
}

// RestoreScript validates a controller-created node archive, restores managed
// files, imports the database through 3x-ui's API, and removes plaintext state.
func RestoreScript(role, scheme, basePath, curlTLS string) (string, error) {
	if role != "entry" && role != "exit" {
		return "", errors.New("backup role must be entry or exit")
	}
	if scheme != "http" && scheme != "https" {
		return "", errors.New("restore scheme must be http or https")
	}
	if !strings.HasPrefix(basePath, "/") || !strings.HasSuffix(basePath, "/") {
		return "", errors.New("restore base path must start and end with slash")
	}
	if curlTLS != "" && curlTLS != "-k" {
		return "", errors.New("unsupported restore TLS option")
	}
	return fmt.Sprintf(`set -eu
umask 077
role=%s
archive=/run/xray-cascade-restore-%s.tar.gz
work=$(mktemp -d /run/xray-cascade-restore-XXXXXX)
cleanup() { rm -rf "$work" "$archive"; }
trap cleanup EXIT INT TERM
test -f "$archive"
tar -tzf "$archive" | while IFS= read -r member; do
  case "$member" in
    ./|./checksums.sha256|./node-manifest.json|./x-ui.db|./ownership.json|./node_token_key.json|./subscription.crt|./subscription.key|./panel.crt|./panel.key|./panel-ca.crt|./panel-ca.key|./exit-node-ca.crt|./exit-trust.crt|./roscom-geoip.dat|./roscom-geosite.dat|./x-ui.service|./x-ui-sandbox.conf|./ufw-user.rules|./ufw-user6.rules) ;;
    *) echo "unexpected restore member" >&2; exit 1 ;;
  esac
done
tar -xzf "$archive" -C "$work" --no-same-owner
test -s "$work/x-ui.db"
test -s "$work/checksums.sha256"
(cd "$work" && sha256sum -c checksums.sha256 >/dev/null)
jq -e --arg role "$role" '.schema==1 and .role==$role' "$work/node-manifest.json" >/dev/null
restore_file() {
  destination=$1 name=$2
  if [ -f "$work/$name" ]; then
    install -d -m 0755 "$(dirname "$destination")"
    cp -p "$work/$name" "$destination"
  else
    rm -f "$destination"
  fi
}
while IFS='|' read -r destination name; do
  restore_file "$destination" "$name"
done <<'XCASCADE_FILES'
/var/lib/xray-cascade/ownership.json|ownership.json
/etc/x-ui/node_token_key.json|node_token_key.json
/etc/x-ui/subscription.crt|subscription.crt
/etc/x-ui/subscription.key|subscription.key
/etc/x-ui/panel.crt|panel.crt
/etc/x-ui/panel.key|panel.key
/etc/x-ui/panel-ca.crt|panel-ca.crt
/etc/x-ui/panel-ca.key|panel-ca.key
/etc/x-ui/exit-node-ca.crt|exit-node-ca.crt
/usr/local/share/ca-certificates/xray-cascade-exit.crt|exit-trust.crt
/usr/local/x-ui/bin/roscom-geoip.dat|roscom-geoip.dat
/usr/local/x-ui/bin/roscom-geosite.dat|roscom-geosite.dat
/etc/systemd/system/x-ui.service|x-ui.service
/etc/systemd/system/x-ui.service.d/10-xui-sandbox.conf|x-ui-sandbox.conf
/etc/ufw/user.rules|ufw-user.rules
/etc/ufw/user6.rules|ufw-user6.rules
XCASCADE_FILES
restore_file "/var/lib/xray-cascade/operator/bootstrap-credentials-$role" bootstrap-credentials
if command -v update-ca-certificates >/dev/null 2>&1; then update-ca-certificates >/dev/null; fi
cd /usr/local/x-ui
token=$(./x-ui setting -tokenName xray-cascade-restore -tokenScope admin -getApiToken | sed -n 's/^apiToken: //p' | tail -n 1)
test -n "$token"
printf 'Authorization: Bearer %%s\n' "$token" > "$work/api-header"
unset token
api=%s://127.0.0.1:2053%sapi
curl --fail-with-body -sS %s -H @"$work/api-header" -F keepHostSettings=false -F "db=@$work/x-ui.db" "$api/server/importDB" > "$work/import.json"
jq -e '.success==true' "$work/import.json" >/dev/null
stopped=false
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
  sleep 1
  if ! curl --fail -sS %s "%s://127.0.0.1:2053%s" -o /dev/null 2>/dev/null; then stopped=true; break; fi
done
test "$stopped" = true
ready=false
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30; do
  sleep 1
  if curl --fail -sS %s "%s://127.0.0.1:2053%s" -o /dev/null 2>/dev/null; then ready=true; break; fi
done
test "$ready" = true
echo "3XUI_BACKUP_RESTORED role=$role"
`, role, role, scheme, basePath, curlTLS, curlTLS, scheme, basePath, curlTLS, scheme, basePath), nil
}

func ExportScript(role, scheme, basePath, curlTLS string) (string, error) {
	if role != "entry" && role != "exit" {
		return "", errors.New("backup role must be entry or exit")
	}
	if scheme != "http" && scheme != "https" {
		return "", errors.New("backup scheme must be http or https")
	}
	if !strings.HasPrefix(basePath, "/") || !strings.HasSuffix(basePath, "/") {
		return "", errors.New("backup base path must start and end with slash")
	}
	if curlTLS != "" && curlTLS != "-k" {
		return "", errors.New("unsupported backup TLS option")
	}
	return fmt.Sprintf(`set -eu
umask 077
role=%s
work=$(mktemp -d /run/xray-cascade-export-XXXXXX)
cleanup() { rm -rf "$work"; }
trap cleanup EXIT INT TERM
cd /usr/local/x-ui
token=$(./x-ui setting -tokenName xray-cascade-backup -tokenScope admin -getApiToken | sed -n 's/^apiToken: //p' | tail -n 1)
test -n "$token"
printf 'Authorization: Bearer %%s\n' "$token" > "$work/api-header"
unset token
api=%s://127.0.0.1:2053%sapi
curl --fail-with-body -sS %s -H @"$work/api-header" "$api/server/getDb" -o "$work/x-ui.db"
test -s "$work/x-ui.db"
rm -f "$work/api-header"
copy_file() { source=$1 name=$2; if [ -f "$source" ] && [ ! -L "$source" ]; then cp -p "$source" "$work/$name"; fi; }
copy_file /var/lib/xray-cascade/ownership.json ownership.json
copy_file /etc/x-ui/node_token_key.json node_token_key.json
copy_file /etc/x-ui/subscription.crt subscription.crt
copy_file /etc/x-ui/subscription.key subscription.key
copy_file /etc/x-ui/panel.crt panel.crt
copy_file /etc/x-ui/panel.key panel.key
copy_file /etc/x-ui/panel-ca.crt panel-ca.crt
copy_file /etc/x-ui/panel-ca.key panel-ca.key
copy_file /etc/x-ui/exit-node-ca.crt exit-node-ca.crt
copy_file /usr/local/share/ca-certificates/xray-cascade-exit.crt exit-trust.crt
copy_file /usr/local/x-ui/bin/roscom-geoip.dat roscom-geoip.dat
copy_file /usr/local/x-ui/bin/roscom-geosite.dat roscom-geosite.dat
copy_file /etc/systemd/system/x-ui.service x-ui.service
copy_file /etc/systemd/system/x-ui.service.d/10-xui-sandbox.conf x-ui-sandbox.conf
copy_file /etc/ufw/user.rules ufw-user.rules
copy_file /etc/ufw/user6.rules ufw-user6.rules
copy_file "/var/lib/xray-cascade/operator/bootstrap-credentials-$role" bootstrap-credentials
jq -n --arg role "$role" --arg created "$(date -u +%%Y-%%m-%%dT%%H:%%M:%%SZ)" '{schema:1,role:$role,createdAt:$created}' > "$work/node-manifest.json"
(cd "$work" && sha256sum ./* > checksums.sha256)
tar -C "$work" -czf - .
`, role, scheme, basePath, curlTLS), nil
}
