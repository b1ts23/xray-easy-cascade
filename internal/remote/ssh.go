// SPDX-License-Identifier: GPL-3.0-only

package remote

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

type Target struct {
	Host         string
	User         string
	Port         int
	IdentityFile string
}

type OpenSSH struct {
	knownHosts string
	proxyJump  string
	bin        string
}

var safeUser = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

func NewOpenSSH(knownHosts, proxyJump string) (*OpenSSH, error) {
	knownHosts, err := expandHome(knownHosts)
	if err != nil {
		return nil, err
	}
	if info, err := os.Lstat(knownHosts); err != nil {
		return nil, fmt.Errorf("inspect known_hosts: %w", err)
	} else if !info.Mode().IsRegular() {
		return nil, errors.New("known_hosts must be a regular file")
	}
	if strings.HasPrefix(proxyJump, "-") || strings.ContainsAny(proxyJump, " \t\r\n") {
		return nil, errors.New("proxy-jump must be one OpenSSH target without whitespace")
	}
	return &OpenSSH{knownHosts: knownHosts, proxyJump: proxyJump, bin: "ssh"}, nil
}

func (s *OpenSSH) Args(target Target) ([]string, error) {
	if !safeUser.MatchString(target.User) {
		return nil, errors.New("SSH user contains unsupported characters")
	}
	if target.Host == "" || strings.HasPrefix(target.Host, "-") || strings.ContainsAny(target.Host, "@ \t\r\n") {
		return nil, errors.New("SSH host contains unsupported characters")
	}
	if target.Port < 1 || target.Port > 65535 {
		return nil, errors.New("SSH port must be between 1 and 65535")
	}
	identity, err := expandHome(target.IdentityFile)
	if err != nil {
		return nil, err
	}
	if info, err := os.Lstat(identity); err != nil {
		return nil, fmt.Errorf("inspect SSH identity: %w", err)
	} else if !info.Mode().IsRegular() {
		return nil, errors.New("SSH identity must be a regular file")
	}

	args := []string{
		"-T",
		"-o", "BatchMode=yes",
		"-o", "PasswordAuthentication=no",
		"-o", "KbdInteractiveAuthentication=no",
		"-o", "PreferredAuthentications=publickey",
		"-o", "IdentitiesOnly=yes",
		"-o", "StrictHostKeyChecking=yes",
		"-o", "UserKnownHostsFile=" + quoteConfigValue(s.knownHosts),
		"-o", "ConnectTimeout=10",
		"-o", "LogLevel=ERROR",
		"-i", identity,
		"-p", strconv.Itoa(target.Port),
	}
	if s.proxyJump != "" {
		args = append(args, "-J", s.proxyJump)
	}
	args = append(args, target.User+"@"+target.Host, "sh", "-s")
	return args, nil
}

func (s *OpenSSH) TunnelArgs(target Target, localPort, remotePort int) ([]string, error) {
	if localPort < 1024 || localPort > 65535 {
		return nil, errors.New("local tunnel port must be between 1024 and 65535")
	}
	if remotePort < 1 || remotePort > 65535 {
		return nil, errors.New("remote tunnel port must be between 1 and 65535")
	}
	base, err := s.Args(target)
	if err != nil {
		return nil, err
	}
	// Args ends in target, sh, -s. Tunnel options must precede the target.
	targetArg := base[len(base)-3]
	args := append([]string{}, base[:len(base)-3]...)
	forward := fmt.Sprintf("127.0.0.1:%d:127.0.0.1:%d", localPort, remotePort)
	args = append(args,
		"-N",
		"-o", "ExitOnForwardFailure=yes",
		"-o", "ServerAliveInterval=30",
		"-o", "ServerAliveCountMax=3",
		"-L", forward,
		targetArg,
	)
	return args, nil
}

// Tunnel opens one loopback-only local forward and blocks until the context is
// cancelled or SSH exits. No remote command is executed.
func (s *OpenSSH) Tunnel(ctx context.Context, target Target, localPort, remotePort int, stderr io.Writer) error {
	args, err := s.TunnelArgs(target, localPort, remotePort)
	if err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, s.bin, args...)
	cmd.Stdin = nil
	cmd.Stdout = io.Discard
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("OpenSSH tunnel failed: %w", err)
	}
	return nil
}

func quoteConfigValue(value string) string {
	replacer := strings.NewReplacer(`\`, `\\`, `"`, `\"`)
	return `"` + replacer.Replace(value) + `"`
}

func (s *OpenSSH) Run(ctx context.Context, target Target, script string) (string, error) {
	raw, err := s.RunBytes(ctx, target, script, 16*1024*1024)
	return string(raw), err
}

type limitedBuffer struct {
	buffer bytes.Buffer
	limit  int64
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if int64(b.buffer.Len()+len(p)) > b.limit {
		return 0, errors.New("remote output exceeded safety limit")
	}
	return b.buffer.Write(p)
}

// RunBytes executes the same pinned OpenSSH transport as Run while preserving
// binary stdout and enforcing a caller-supplied memory bound.
func (s *OpenSSH) RunBytes(ctx context.Context, target Target, script string, maxBytes int64) ([]byte, error) {
	if maxBytes < 1 {
		return nil, errors.New("remote output limit must be positive")
	}
	args, err := s.Args(target)
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, s.bin, args...)
	cmd.Stdin = strings.NewReader(script)
	stdout := &limitedBuffer{limit: maxBytes}
	var stderr bytes.Buffer
	cmd.Stdout = stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		message := strings.TrimSpace(stderr.String())
		if message != "" {
			return nil, fmt.Errorf("OpenSSH failed: %w: %s", err, message)
		}
		return nil, fmt.Errorf("OpenSSH failed: %w", err)
	}
	return stdout.buffer.Bytes(), nil
}

// UploadRestoreArchive streams an authenticated plaintext node archive over
// SSH to a fixed root-only runtime path. It never creates a local plaintext file.
func (s *OpenSSH) UploadRestoreArchive(ctx context.Context, target Target, role string, data []byte, maxBytes int64) error {
	if role != "entry" && role != "exit" {
		return errors.New("restore role must be entry or exit")
	}
	if len(data) == 0 || int64(len(data)) > maxBytes {
		return errors.New("restore archive size is outside the safety limit")
	}
	args, err := s.Args(target)
	if err != nil {
		return err
	}
	args = args[:len(args)-2]
	remotePath := "/run/xray-cascade-restore-" + role + ".tar.gz"
	args = append(args, "umask 077; cat > "+remotePath)
	cmd := exec.CommandContext(ctx, s.bin, args...)
	cmd.Stdin = bytes.NewReader(data)
	var stderr bytes.Buffer
	cmd.Stdout = io.Discard
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		message := strings.TrimSpace(stderr.String())
		if message != "" {
			return fmt.Errorf("OpenSSH restore upload failed: %w: %s", err, message)
		}
		return fmt.Errorf("OpenSSH restore upload failed: %w", err)
	}
	return nil
}

func expandHome(path string) (string, error) {
	if path == "~" || strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("resolve home directory: %w", err)
		}
		path = filepath.Join(home, strings.TrimPrefix(path, "~/"))
	}
	if strings.TrimSpace(path) == "" {
		return "", errors.New("path must not be empty")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve path: %w", err)
	}
	return absolute, nil
}
