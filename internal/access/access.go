// SPDX-License-Identifier: GPL-3.0-only

// Package access defines the human-facing handoff produced after a successful
// deployment. Secrets are printed deliberately at the operator's terminal;
// API and node tokens are never part of this handoff.
package access

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type Panel struct {
	Role        string
	Username    string
	Password    string
	Port        int
	WebBasePath string
	AccessURL   string
	OpenCommand string
}

type Summary struct {
	Cluster          string
	Entry            Panel
	Exit             Panel
	HappSubscription string
}

func (summary Summary) Validate() error {
	if strings.TrimSpace(summary.Cluster) == "" {
		return errors.New("cluster name is required")
	}
	for _, panel := range []Panel{summary.Entry, summary.Exit} {
		if (panel.Role != "entry" && panel.Role != "exit") || strings.TrimSpace(panel.Username) == "" || strings.TrimSpace(panel.Password) == "" {
			return errors.New("both panel credentials are required")
		}
		if panel.Port < 1 || panel.Port > 65535 || !strings.HasPrefix(panel.WebBasePath, "/") || !strings.HasSuffix(panel.WebBasePath, "/") {
			return fmt.Errorf("invalid %s panel endpoint", panel.Role)
		}
		if strings.ContainsAny(panel.Username+panel.Password, "\r\n\t") {
			return fmt.Errorf("invalid %s panel credentials", panel.Role)
		}
	}
	if !strings.HasPrefix(summary.HappSubscription, "https://") || strings.ContainsAny(summary.HappSubscription, "\r\n\t ") {
		return errors.New("valid HTTPS HAPP subscription is required")
	}
	return nil
}

func printPanel(out io.Writer, panel Panel) {
	fmt.Fprintln(out, "═══════════════════════════════════════════")
	fmt.Fprintf(out, "3x-ui panel:  %s\n", panel.Role)
	fmt.Fprintf(out, "Username:     %s\n", panel.Username)
	fmt.Fprintf(out, "Password:     %s\n", panel.Password)
	fmt.Fprintf(out, "Port:         %d\n", panel.Port)
	fmt.Fprintf(out, "WebBasePath:  %s\n", panel.WebBasePath)
	fmt.Fprintf(out, "Access URL:   %s\n", panel.AccessURL)
	fmt.Fprintf(out, "Open command: %s\n", panel.OpenCommand)
	fmt.Fprintln(out, "═══════════════════════════════════════════")
}

// Print writes secrets to the explicitly supplied operator stream. Callers
// must not route this output into ordinary deployment logs.
func Print(out io.Writer, summary Summary) error {
	if err := summary.Validate(); err != nil {
		return err
	}
	fmt.Fprintf(out, "\nXray Cascade installed: %s\n\n", summary.Cluster)
	printPanel(out, summary.Entry)
	fmt.Fprintln(out)
	printPanel(out, summary.Exit)
	fmt.Fprintln(out)
	fmt.Fprintln(out, "═══════════════════════════════════════════")
	fmt.Fprintln(out, "HAPP subscription")
	fmt.Fprintf(out, "URL: %s\n", summary.HappSubscription)
	fmt.Fprintln(out, "Add this single URL as a subscription in HAPP.")
	fmt.Fprintln(out, "═══════════════════════════════════════════")
	return nil
}

// DefaultPath is intentionally adjacent to inventory.yml and not hidden in a
// platform-specific config directory, so the operator always knows where the
// optional recovery copy is located.
func DefaultPath(inventoryPath string) string {
	return filepath.Join(filepath.Dir(inventoryPath), "xray-cascade-access.txt")
}

func Save(path string, summary Summary) error {
	if err := summary.Validate(); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return errors.New("refusing to write access handoff through a symbolic link")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".xray-cascade-access-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := Print(tmp, summary); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}
