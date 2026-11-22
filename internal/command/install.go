// SPDX-License-Identifier: GPL-3.0-only

package command

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/b1ts23/xray-easy-cascade/internal/access"
	"github.com/b1ts23/xray-easy-cascade/internal/deployprod"
	"github.com/b1ts23/xray-easy-cascade/internal/inventory"
	"github.com/b1ts23/xray-easy-cascade/internal/remote"
)

func runProductionDeploy(inventoryPath, knownHosts, proxyJump string, yes bool, in io.Reader, out, errOut io.Writer) error {
	if err := runPlan([]string{"--inventory", inventoryPath}, out, errOut); err != nil {
		return err
	}
	preflightArgs := []string{"--inventory", inventoryPath, "--known-hosts", knownHosts}
	if proxyJump != "" {
		preflightArgs = append(preflightArgs, "--proxy-jump", proxyJump)
	}
	if err := runPreflight(preflightArgs, out, errOut); err != nil {
		return err
	}
	if !yes {
		reader := bufio.NewReader(in)
		fmt.Fprint(out, "\nInstall the cascade on both clean VPS now? [y/N]: ")
		answer, err := reader.ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		if strings.ToLower(strings.TrimSpace(answer)) != "y" {
			return errors.New("installation cancelled before mutation")
		}
	}
	inv, err := inventory.Load(inventoryPath)
	if err != nil {
		return err
	}
	runner, err := remote.NewOpenSSH(knownHosts, proxyJump)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	happDeeplink, happSHA, err := fetchRoscomVPN(ctx)
	cancel()
	if err != nil {
		return fmt.Errorf("fetch pinned RoscomVPN routing: %w", err)
	}
	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	fmt.Fprintln(out, "\nINSTALLING (automatic rollback is armed until final E2E succeeds)")
	summary, err := deployprod.DeployFreshHosts(ctx, runner, inv, happDeeplink, happSHA, out)
	if err != nil {
		return err
	}
	handoffPath := access.DefaultPath(inventoryPath)
	if err := access.Save(handoffPath, summary); err != nil {
		return fmt.Errorf("save protected access handoff: %w", err)
	}
	if err := access.Print(out, summary); err != nil {
		return err
	}
	fmt.Fprintf(out, "\nProtected recovery copy: %s\n", handoffPath)
	return nil
}

func configureProfile(inv *inventory.Inventory, profile string) error {
	switch strings.ToLower(strings.TrimSpace(profile)) {
	case "base":
		inv.Transport.ClientAlternatives = []inventory.ClientAlternative{{Kind: "reality-xhttp", Port: 8443}}
	case "extended":
		inv.Transport.ClientAlternatives = []inventory.ClientAlternative{
			{Kind: "reality-xhttp", Port: 8443},
			{Kind: "reality-xhttp-pq", Port: 10443},
			{Kind: "reality-grpc", Port: 9443},
		}
		inv.Transport.Hysteria2 = inventory.Hysteria2{Enabled: true, Port: 443}
		inv.Transport.InterserverAlternatives = []inventory.InterserverAlternative{{Kind: "reality-xhttp", Port: 8443}}
	default:
		return errors.New("profile must be base or extended")
	}
	return nil
}

func scanHostKeys(ctx context.Context, inv inventory.Inventory) ([]byte, string, error) {
	var keys bytes.Buffer
	for role, server := range map[string]inventory.Server{"entry": inv.Entry, "exit": inv.Exit} {
		cmd := exec.CommandContext(ctx, "ssh-keyscan", "-T", "10", "-p", fmt.Sprint(server.SSHPort), server.Host)
		var stderr bytes.Buffer
		cmd.Stdout = &keys
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			return nil, "", fmt.Errorf("scan %s SSH host key: %w: %s", role, err, strings.TrimSpace(stderr.String()))
		}
	}
	if keys.Len() == 0 || keys.Len() > 1024*1024 {
		return nil, "", errors.New("SSH host-key scan returned no usable keys")
	}
	tmp, err := os.CreateTemp("", "xray-cascade-known-hosts-*")
	if err != nil {
		return nil, "", err
	}
	path := tmp.Name()
	defer os.Remove(path)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return nil, "", err
	}
	if _, err := tmp.Write(keys.Bytes()); err != nil {
		_ = tmp.Close()
		return nil, "", err
	}
	if err := tmp.Close(); err != nil {
		return nil, "", err
	}
	cmd := exec.CommandContext(ctx, "ssh-keygen", "-lf", path)
	fingerprints, err := cmd.CombinedOutput()
	if err != nil {
		return nil, "", fmt.Errorf("calculate SSH fingerprints: %w", err)
	}
	return keys.Bytes(), strings.TrimSpace(string(fingerprints)), nil
}

func runInstall(args []string, in io.Reader, out, errOut io.Writer) error {
	flags := flag.NewFlagSet("install", flag.ContinueOnError)
	flags.SetOutput(errOut)
	workDir := flags.String("work-dir", "xray-easy-cascade-install", "directory for protected inventory and access handoff")
	profile := flags.String("profile", "extended", "transport profile: base or extended")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("install accepts no positional arguments")
	}
	if err := os.MkdirAll(*workDir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(*workDir, 0o700); err != nil {
		return err
	}
	inventoryPath := filepath.Join(*workDir, "inventory.yml")
	knownHostsPath := filepath.Join(*workDir, "known_hosts")
	for _, path := range []string{inventoryPath, knownHostsPath, access.DefaultPath(inventoryPath)} {
		if _, err := os.Lstat(path); err == nil {
			return fmt.Errorf("%s already exists; move or remove the previous install directory first", path)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	reader := bufio.NewReader(in)
	inv := inventory.Default()
	if err := configureProfile(&inv, *profile); err != nil {
		return err
	}
	fmt.Fprintln(out, "Xray Easy Cascade — guided two-server installation")
	fmt.Fprintln(out, "Nothing changes until SSH checks pass and you confirm the final plan.")
	fmt.Fprintln(out)
	var err error
	if inv.Cluster.Name, err = prompt(reader, out, "Cascade name", inv.Cluster.Name); err != nil {
		return err
	}
	if inv.Entry.Host, err = promptRequired(reader, out, "Entry server public IPv4"); err != nil {
		return err
	}
	if inv.Exit.Host, err = promptRequired(reader, out, "Exit server public IPv4"); err != nil {
		return err
	}
	entryIP, entryErr := netip.ParseAddr(inv.Entry.Host)
	exitIP, exitErr := netip.ParseAddr(inv.Exit.Host)
	if entryErr != nil || exitErr != nil || !entryIP.Is4() || !exitIP.Is4() || !entryIP.IsGlobalUnicast() || !exitIP.IsGlobalUnicast() || entryIP == exitIP {
		return errors.New("entry and exit must be two different public IPv4 addresses")
	}
	if inv.Entry.SSHIdentityFile, err = prompt(reader, out, "SSH private key", inv.Entry.SSHIdentityFile); err != nil {
		return err
	}
	inv.Exit.SSHIdentityFile = inv.Entry.SSHIdentityFile
	inv.Certificates.SubscriptionTLS = "acme-ip"
	fmt.Fprintln(out, "\nIPv6 fallback: auto. If both VPS have global IPv6, it becomes an independent")
	fmt.Fprintln(out, "backup path between entry and exit. If both IPv4 and IPv6 fail, traffic is blocked.")
	if err := inventory.Save(inventoryPath, inv); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	keys, fingerprints, err := scanHostKeys(ctx, inv)
	cancel()
	if err != nil {
		return err
	}
	fmt.Fprintln(out, "\nSSH host-key fingerprints (compare them with your VPS provider console):")
	fmt.Fprintln(out, fingerprints)
	fmt.Fprint(out, "Trust and pin these SSH host keys? [y/N]: ")
	answer, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	if strings.ToLower(strings.TrimSpace(answer)) != "y" {
		return errors.New("installation cancelled before mutation; SSH host keys were not trusted")
	}
	if err := os.WriteFile(knownHostsPath, keys, 0o600); err != nil {
		return err
	}
	if err := os.Chmod(knownHostsPath, 0o600); err != nil {
		return err
	}
	if err := runPlan([]string{"--inventory", inventoryPath}, out, errOut); err != nil {
		return err
	}
	if err := runPreflight([]string{"--inventory", inventoryPath, "--known-hosts", knownHostsPath}, out, errOut); err != nil {
		return err
	}
	fmt.Fprint(out, "\nThe read-only checks passed. Install on BOTH clean VPS? [y/N]: ")
	answer, err = reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	if strings.ToLower(strings.TrimSpace(answer)) != "y" {
		return errors.New("installation cancelled before mutation")
	}
	return runProductionDeploy(inventoryPath, knownHostsPath, "", true, reader, out, errOut)
}
