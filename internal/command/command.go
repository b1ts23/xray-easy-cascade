// SPDX-License-Identifier: GPL-3.0-only

package command

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/b1ts23/xray-easy-cascade/internal/access"
	"github.com/b1ts23/xray-easy-cascade/internal/backup"
	"github.com/b1ts23/xray-easy-cascade/internal/certificate"
	"github.com/b1ts23/xray-easy-cascade/internal/deploylab"
	"github.com/b1ts23/xray-easy-cascade/internal/diagnostic"
	"github.com/b1ts23/xray-easy-cascade/internal/inventory"
	"github.com/b1ts23/xray-easy-cascade/internal/preflight"
	"github.com/b1ts23/xray-easy-cascade/internal/production"
	"github.com/b1ts23/xray-easy-cascade/internal/remote"
	"github.com/b1ts23/xray-easy-cascade/internal/routing"
	"github.com/b1ts23/xray-easy-cascade/internal/transaction"
)

var Version = "0.0.0-design"

var ErrNotImplemented = errors.New("command is intentionally disabled in the design preview")
var ErrPreflightBlocked = errors.New("one or more nodes failed preflight")
var ErrVerificationFailed = errors.New("one or more runtime checks failed")

func ExitCode(err error) int {
	if errors.Is(err, ErrNotImplemented) {
		return 2
	}
	if errors.Is(err, ErrPreflightBlocked) {
		return 3
	}
	if errors.Is(err, ErrVerificationFailed) {
		return 4
	}
	return 1
}

func Run(args []string, in io.Reader, out, errOut io.Writer) error {
	if len(args) == 0 {
		printHelp(out)
		return nil
	}

	switch args[0] {
	case "help", "--help", "-h":
		printHelp(out)
		return nil
	case "version", "--version":
		fmt.Fprintln(out, Version)
		return nil
	case "init":
		return runInit(args[1:], in, out, errOut)
	case "plan":
		return runPlan(args[1:], out, errOut)
	case "preflight":
		return runPreflight(args[1:], out, errOut)
	case "deploy":
		return runDeploy(args[1:], in, out, errOut)
	case "rollback":
		return runRollback(args[1:], in, out, errOut)
	case "backup-keygen":
		return runBackupKeygen(args[1:], out, errOut)
	case "backup":
		return runBackup(args[1:], out, errOut)
	case "backup-verify":
		return runBackupVerify(args[1:], out, errOut)
	case "restore":
		return runRestore(args[1:], in, out, errOut)
	case "status":
		return runStatus(args[1:], out, errOut)
	case "verify":
		return runVerify(args[1:], out, errOut)
	case "panel":
		return runPanel(args[1:], out, errOut)
	case "access":
		return runAccess(args[1:], out, errOut)
	case "update", "uninstall":
		return fmt.Errorf("%s: %w", args[0], ErrNotImplemented)
	default:
		return fmt.Errorf("unknown command %q; run vpnctl help", args[0])
	}
}

func printHelp(out io.Writer) {
	fmt.Fprintln(out, `vpnctl — two-node Xray cascade controller (design preview)

Usage:
  vpnctl init [--output inventory.yml] [--force]
  vpnctl plan [--inventory inventory.yml]
  vpnctl preflight [--inventory inventory.yml] [--known-hosts PATH] [--proxy-jump TARGET] [--lab] [--json]
  vpnctl deploy --lab --inventory lab/inventory.example.yml --known-hosts PATH --proxy-jump TARGET [--yes]
  vpnctl rollback --lab --inventory lab/inventory.example.yml --known-hosts PATH --proxy-jump TARGET [--yes]
  vpnctl backup-keygen --output PATH
  vpnctl backup --lab --recipient age1... --output BACKUP.age --inventory lab/inventory.example.yml --known-hosts PATH --proxy-jump TARGET
  vpnctl backup-verify --input BACKUP.age --identity PATH
  vpnctl restore --lab --yes --input BACKUP.age --identity PATH --inventory lab/inventory.example.yml --known-hosts PATH --proxy-jump TARGET
  vpnctl status --lab --inventory lab/inventory.example.yml --known-hosts PATH --proxy-jump TARGET [--json]
  vpnctl verify --lab --inventory lab/inventory.example.yml --known-hosts PATH --proxy-jump TARGET
  vpnctl panel [entry|exit] --inventory inventory.yml --known-hosts PATH [--proxy-jump TARGET] [--local-port PORT] [--print-url]
  vpnctl access [--inventory inventory.yml] [--file PATH]
  vpnctl version

Production deploy, backup, restore, rollback, update and uninstall remain fail-closed.
Status and verify currently require --lab. Panel is a loopback-only SSH tunnel.`)
}

func runAccess(args []string, out, errOut io.Writer) error {
	flags := flag.NewFlagSet("access", flag.ContinueOnError)
	flags.SetOutput(errOut)
	inventoryPath := flags.String("inventory", "inventory.yml", "inventory path used to locate the handoff")
	filePath := flags.String("file", "", "explicit access handoff path")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("access accepts no positional arguments")
	}
	path := *filePath
	if path == "" {
		path = access.DefaultPath(*inventoryPath)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("read access handoff %s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("access handoff must be a regular non-symlink file")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return errors.New("access handoff permissions must not allow group or other access")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if _, err := out.Write(raw); err != nil {
		return err
	}
	fmt.Fprintf(out, "\nSaved copy: %s\n", path)
	return nil
}

func runPanel(args []string, out, errOut io.Writer) error {
	leadingRole := ""
	if len(args) > 0 && (args[0] == "entry" || args[0] == "exit") {
		leadingRole = args[0]
		args = args[1:]
	}
	flags := flag.NewFlagSet("panel", flag.ContinueOnError)
	flags.SetOutput(errOut)
	inventoryPath := flags.String("inventory", "inventory.yml", "inventory path")
	knownHosts := flags.String("known-hosts", "~/.ssh/known_hosts", "pinned SSH known_hosts file")
	proxyJump := flags.String("proxy-jump", "", "optional OpenSSH jump target")
	localPort := flags.Int("local-port", 0, "local loopback port (default 12053 for entry, 12054 for exit)")
	printURL := flags.Bool("print-url", false, "validate and print the local panel URL without opening a tunnel")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() > 1 {
		return errors.New("panel accepts at most one role: entry or exit")
	}
	role := "entry"
	if leadingRole != "" {
		role = leadingRole
	}
	if flags.NArg() == 1 {
		if leadingRole != "" {
			return errors.New("panel role was provided more than once")
		}
		role = flags.Arg(0)
	}
	if role != "entry" && role != "exit" {
		return errors.New("panel role must be entry or exit")
	}
	inv, err := inventory.Load(*inventoryPath)
	if err != nil {
		return err
	}
	if inv.Panel.Access != "ssh-tunnel" {
		return errors.New("panel command requires panel.access=ssh-tunnel")
	}
	runner, err := remote.NewOpenSSH(*knownHosts, *proxyJump)
	if err != nil {
		return err
	}
	server := inv.Entry
	basePath := "/entry/panel/"
	chosenLocalPort := *localPort
	if chosenLocalPort == 0 {
		chosenLocalPort = 12053
	}
	if role == "exit" {
		server = inv.Exit
		basePath = "/exit/panel/"
		if *localPort == 0 {
			chosenLocalPort = 12054
		}
	}
	target := remote.Target{Host: server.Host, User: server.SSHUser, Port: server.SSHPort, IdentityFile: server.SSHIdentityFile}
	if _, err := runner.TunnelArgs(target, chosenLocalPort, inv.Panel.Port); err != nil {
		return err
	}
	scheme := "http"
	if inv.Certificates.SubscriptionTLS == "acme-ip" || role == "exit" {
		scheme = "https"
	}
	url := fmt.Sprintf("%s://127.0.0.1:%d%s", scheme, chosenLocalPort, basePath)
	if *printURL {
		fmt.Fprintln(out, url)
		return nil
	}
	fmt.Fprintln(out, "Panel tunnel ready when SSH connects:", url)
	fmt.Fprintln(out, "Press Ctrl-C to close the loopback-only tunnel.")
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	err = runner.Tunnel(ctx, target, chosenLocalPort, inv.Panel.Port, errOut)
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}

func collectLabStatus(inv inventory.Inventory, runner *remote.OpenSSH) ([]diagnostic.Status, error) {
	targets := []struct {
		role   string
		server inventory.Server
	}{
		{role: "entry", server: inv.Entry},
		{role: "exit", server: inv.Exit},
	}
	statuses := make([]diagnostic.Status, 0, len(targets))
	for _, item := range targets {
		script, err := diagnostic.Script(item.role, inv)
		if err != nil {
			return nil, err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		raw, runErr := runner.Run(ctx, remote.Target{Host: item.server.Host, User: item.server.SSHUser, Port: item.server.SSHPort, IdentityFile: item.server.SSHIdentityFile}, script)
		cancel()
		if runErr != nil {
			return nil, fmt.Errorf("collect %s status: %w", item.role, runErr)
		}
		status, parseErr := diagnostic.Parse(raw, item.role)
		if parseErr != nil {
			return nil, fmt.Errorf("parse %s status: %w", item.role, parseErr)
		}
		statuses = append(statuses, status)
	}
	return statuses, nil
}

func labDiagnosticSetup(args []string, commandName string, errOut io.Writer) (inventory.Inventory, *remote.OpenSSH, bool, error) {
	flags := flag.NewFlagSet(commandName, flag.ContinueOnError)
	flags.SetOutput(errOut)
	inventoryPath := flags.String("inventory", "inventory.yml", "inventory path")
	knownHosts := flags.String("known-hosts", "~/.ssh/known_hosts", "pinned SSH known_hosts file")
	proxyJump := flags.String("proxy-jump", "", "required OpenSSH jump target for the isolated lab")
	labMode := flags.Bool("lab", false, "operate only on loopback-forwarded isolated containers")
	jsonOutput := flags.Bool("json", false, "print machine-readable JSON (status only)")
	if err := flags.Parse(args); err != nil {
		return inventory.Inventory{}, nil, false, err
	}
	if flags.NArg() != 0 {
		return inventory.Inventory{}, nil, false, fmt.Errorf("%s accepts no positional arguments", commandName)
	}
	if !*labMode {
		return inventory.Inventory{}, nil, false, fmt.Errorf("production %s: %w", commandName, ErrNotImplemented)
	}
	if commandName == "verify" && *jsonOutput {
		return inventory.Inventory{}, nil, false, errors.New("verify does not accept --json")
	}
	inv, err := inventory.Load(*inventoryPath)
	if err != nil {
		return inventory.Inventory{}, nil, false, err
	}
	if err := deploylab.ValidateBoundary(inv, *proxyJump); err != nil {
		return inventory.Inventory{}, nil, false, fmt.Errorf("lab safety boundary: %w", err)
	}
	runner, err := remote.NewOpenSSH(*knownHosts, *proxyJump)
	if err != nil {
		return inventory.Inventory{}, nil, false, err
	}
	return inv, runner, *jsonOutput, nil
}

func runStatus(args []string, out, errOut io.Writer) error {
	inv, runner, jsonOutput, err := labDiagnosticSetup(args, "status", errOut)
	if err != nil {
		return err
	}
	statuses, err := collectLabStatus(inv, runner)
	if err != nil {
		return err
	}
	var problems []string
	if jsonOutput {
		raw, encodeErr := json.MarshalIndent(statuses, "", "  ")
		if encodeErr != nil {
			return encodeErr
		}
		fmt.Fprintln(out, string(raw))
	} else {
		fmt.Fprintln(out, "STATUS LAB (redacted; no credentials or subscription URLs)")
	}
	for _, status := range statuses {
		roleProblems := status.Problems()
		if !jsonOutput {
			state := "READY"
			if len(roleProblems) > 0 {
				state = "DEGRADED"
			}
			fmt.Fprintf(out, "%s: %s; panel=%t xray=%t inbounds=%d\n", strings.ToUpper(status.Role), state, status.PanelReady, status.XrayRunning, status.InboundCount)
			if status.Role == "entry" {
				fmt.Fprintf(out, "  node=%s tls=%s api_token_present=%t subscription=%t routing=%t\n", status.Node.Status, status.Node.TLSVerifyMode, status.Node.APITokenPresent, status.Subscription.Enabled, status.Subscription.Routing)
				fmt.Fprintf(out, "  client_listeners: tcp=%t xhttp=%t xhttp_pq=%t grpc=%t hysteria2=%t\n", status.Listeners.Client, status.Listeners.XHTTP, status.Listeners.XHTTPPQ, status.Listeners.GRPC, status.Listeners.Hysteria2)
			}
			for _, problem := range roleProblems {
				fmt.Fprintln(out, "  PROBLEM:", problem)
			}
		}
		for _, problem := range roleProblems {
			problems = append(problems, status.Role+": "+problem)
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("%w: %s", ErrVerificationFailed, strings.Join(problems, "; "))
	}
	return nil
}

func runVerify(args []string, out, errOut io.Writer) error {
	inv, runner, _, err := labDiagnosticSetup(args, "verify", errOut)
	if err != nil {
		return err
	}
	statuses, err := collectLabStatus(inv, runner)
	if err != nil {
		return err
	}
	for _, status := range statuses {
		if problems := status.Problems(); len(problems) > 0 {
			return fmt.Errorf("%w: %s: %s", ErrVerificationFailed, status.Role, strings.Join(problems, "; "))
		}
	}
	happSHA := ""
	if inv.Subscription.HappRouting == "roscomvpn-default" {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		_, happSHA, err = fetchRoscomVPN(ctx)
		cancel()
		if err != nil {
			return err
		}
	}
	script, err := deploylab.E2EScript(inv, happSHA)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	raw, runErr := runner.Run(ctx, remote.Target{Host: inv.Entry.Host, User: inv.Entry.SSHUser, Port: inv.Entry.SSHPort, IdentityFile: inv.Entry.SSHIdentityFile}, script)
	cancel()
	if runErr != nil {
		return fmt.Errorf("%w: cascade end-to-end: %v", ErrVerificationFailed, runErr)
	}
	writeReadyMarkers(out, raw)
	if inv.Transport.IPv6Fallback != "disabled" && inv.Exit.PublicIPv6 != "disabled" && inv.Exit.PublicIPv6 != "auto" && strings.TrimSpace(inv.Exit.PublicIPv6) != "" {
		failoverScript, buildErr := deploylab.FailoverE2EScript(inv)
		if buildErr != nil {
			return buildErr
		}
		ctx, cancel = context.WithTimeout(context.Background(), 120*time.Second)
		failoverRaw, failoverErr := runner.Run(ctx, remote.Target{Host: inv.Entry.Host, User: inv.Entry.SSHUser, Port: inv.Entry.SSHPort, IdentityFile: inv.Entry.SSHIdentityFile}, failoverScript)
		cancel()
		if failoverErr != nil {
			return fmt.Errorf("%w: IPv4/IPv6 failover: %v", ErrVerificationFailed, failoverErr)
		}
		writeReadyMarkers(out, failoverRaw)
	}
	fmt.Fprintln(out, "3XUI_LAB_VERIFY_READY")
	return nil
}

func runRestore(args []string, in io.Reader, out, errOut io.Writer) (retErr error) {
	flags := flag.NewFlagSet("restore", flag.ContinueOnError)
	flags.SetOutput(errOut)
	inventoryPath := flags.String("inventory", "inventory.yml", "inventory path")
	knownHosts := flags.String("known-hosts", "~/.ssh/known_hosts", "pinned SSH known_hosts file")
	proxyJump := flags.String("proxy-jump", "", "required OpenSSH jump target for the isolated lab")
	labMode := flags.Bool("lab", false, "restore only loopback-forwarded isolated containers")
	yes := flags.Bool("yes", false, "confirm the lab restore non-interactively")
	input := flags.String("input", "", "encrypted backup path")
	identity := flags.String("identity", "", "age identity path")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("restore accepts no positional arguments")
	}
	if !*labMode {
		return fmt.Errorf("production restore: %w", ErrNotImplemented)
	}
	if strings.TrimSpace(*input) == "" || strings.TrimSpace(*identity) == "" {
		return errors.New("restore requires --input and --identity")
	}
	inv, err := inventory.Load(*inventoryPath)
	if err != nil {
		return err
	}
	if err := deploylab.ValidateBoundary(inv, *proxyJump); err != nil {
		return fmt.Errorf("lab safety boundary: %w", err)
	}
	manifest, err := backup.Verify(*input, *identity)
	if err != nil {
		return err
	}
	if manifest.Cluster != inv.Cluster.Name {
		return fmt.Errorf("backup cluster %q does not match inventory cluster %q", manifest.Cluster, inv.Cluster.Name)
	}
	archives := make(map[string][]byte, 2)
	for _, role := range []string{"entry", "exit"} {
		archives[role], err = backup.NodeArchive(*input, *identity, role)
		if err != nil {
			return err
		}
	}
	if !*yes {
		reader := bufio.NewReader(in)
		fmt.Fprintf(out, "Restore encrypted backup for lab cluster %s? [y/N]: ", inv.Cluster.Name)
		answer, readErr := reader.ReadString('\n')
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return readErr
		}
		if strings.ToLower(strings.TrimSpace(answer)) != "y" {
			return errors.New("lab restore cancelled")
		}
	}
	runner, err := remote.NewOpenSSH(*knownHosts, *proxyJump)
	if err != nil {
		return err
	}
	entryTarget := remote.Target{Host: inv.Entry.Host, User: inv.Entry.SSHUser, Port: inv.Entry.SSHPort, IdentityFile: inv.Entry.SSHIdentityFile}
	exitTarget := remote.Target{Host: inv.Exit.Host, User: inv.Exit.SSHUser, Port: inv.Exit.SSHPort, IdentityFile: inv.Exit.SSHIdentityFile}
	entryEndpoint := transaction.Endpoint{Scheme: "http", BasePath: "/entry/panel/"}
	exitEndpoint := transaction.Endpoint{Scheme: "https", BasePath: "/exit/panel/", CurlTLS: "-k"}
	type restoreNode struct {
		role     string
		target   remote.Target
		endpoint transaction.Endpoint
		started  bool
	}
	nodes := []*restoreNode{
		{role: "exit", target: exitTarget, endpoint: exitEndpoint},
		{role: "entry", target: entryTarget, endpoint: entryEndpoint},
	}
	txID, err := transaction.NewID()
	if err != nil {
		return err
	}
	transactionActive := true
	defer func() {
		if retErr == nil || !transactionActive {
			return
		}
		for index := len(nodes) - 1; index >= 0; index-- {
			node := nodes[index]
			if !node.started {
				continue
			}
			script, buildErr := transaction.RollbackScript(inv.Cluster.Name, node.role, txID, node.endpoint)
			if buildErr != nil {
				retErr = errors.Join(retErr, buildErr)
				continue
			}
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			raw, rollbackErr := runner.Run(ctx, node.target, script)
			cancel()
			if rollbackErr != nil {
				retErr = errors.Join(retErr, fmt.Errorf("%s automatic restore rollback: %w", node.role, rollbackErr))
				continue
			}
			writeReadyMarkers(out, raw)
		}
	}()
	for _, node := range nodes {
		script, buildErr := transaction.BeginScript(inv.Cluster.Name, node.role, txID, node.endpoint)
		if buildErr != nil {
			return buildErr
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		raw, beginErr := runner.Run(ctx, node.target, script)
		cancel()
		if beginErr != nil {
			return fmt.Errorf("begin %s restore transaction: %w", node.role, beginErr)
		}
		node.started = true
		writeReadyMarkers(out, raw)
	}
	for _, node := range nodes {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		uploadErr := runner.UploadRestoreArchive(ctx, node.target, node.role, archives[node.role], backup.MaxNodeExportBytes)
		cancel()
		if uploadErr != nil {
			return fmt.Errorf("upload %s restore archive: %w", node.role, uploadErr)
		}
		script, buildErr := backup.RestoreScript(node.role, node.endpoint.Scheme, node.endpoint.BasePath, node.endpoint.CurlTLS)
		if buildErr != nil {
			return buildErr
		}
		ctx, cancel = context.WithTimeout(context.Background(), 90*time.Second)
		raw, restoreErr := runner.Run(ctx, node.target, script)
		cancel()
		if restoreErr != nil {
			return fmt.Errorf("restore %s: %w", node.role, restoreErr)
		}
		writeReadyMarkers(out, raw)
	}
	happSHA := ""
	if inv.Subscription.HappRouting == "roscomvpn-default" {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		_, happSHA, err = fetchRoscomVPN(ctx)
		cancel()
		if err != nil {
			return err
		}
	}
	e2eScript, err := deploylab.E2EScript(inv, happSHA)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	e2eRaw, err := runner.Run(ctx, entryTarget, e2eScript)
	cancel()
	if err != nil {
		return fmt.Errorf("restored cascade end-to-end: %w", err)
	}
	writeReadyMarkers(out, e2eRaw)
	for _, node := range nodes {
		script, buildErr := transaction.CommitScript(inv.Cluster.Name, node.role, txID, node.endpoint)
		if buildErr != nil {
			return buildErr
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		raw, commitErr := runner.Run(ctx, node.target, script)
		cancel()
		if commitErr != nil {
			return fmt.Errorf("commit %s restore: %w", node.role, commitErr)
		}
		writeReadyMarkers(out, raw)
	}
	transactionActive = false
	fmt.Fprintln(out, "3XUI_LAB_RESTORE_READY")
	return nil
}

func runBackupKeygen(args []string, out, errOut io.Writer) error {
	flags := flag.NewFlagSet("backup-keygen", flag.ContinueOnError)
	flags.SetOutput(errOut)
	output := flags.String("output", "", "new age identity path")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || strings.TrimSpace(*output) == "" {
		return errors.New("backup-keygen requires --output and accepts no positional arguments")
	}
	recipient, err := backup.GenerateIdentity(*output)
	if err != nil {
		return err
	}
	abs, err := filepath.Abs(*output)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "3XUI_BACKUP_IDENTITY_READY path=%s\n", abs)
	fmt.Fprintf(out, "recipient=%s\n", recipient)
	fmt.Fprintln(out, "Store the identity offline; only the public recipient belongs in automation.")
	return nil
}

func runBackup(args []string, out, errOut io.Writer) error {
	flags := flag.NewFlagSet("backup", flag.ContinueOnError)
	flags.SetOutput(errOut)
	inventoryPath := flags.String("inventory", "inventory.yml", "inventory path")
	knownHosts := flags.String("known-hosts", "~/.ssh/known_hosts", "pinned SSH known_hosts file")
	proxyJump := flags.String("proxy-jump", "", "required OpenSSH jump target for the isolated lab")
	labMode := flags.Bool("lab", false, "back up only loopback-forwarded isolated containers")
	recipient := flags.String("recipient", "", "public age X25519 recipient")
	outputPath := flags.String("output", "", "new encrypted backup path")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("backup accepts no positional arguments")
	}
	if !*labMode {
		return fmt.Errorf("production backup: %w", ErrNotImplemented)
	}
	if strings.TrimSpace(*recipient) == "" || strings.TrimSpace(*outputPath) == "" {
		return errors.New("backup requires --recipient and --output")
	}
	inv, err := inventory.Load(*inventoryPath)
	if err != nil {
		return err
	}
	if err := deploylab.ValidateBoundary(inv, *proxyJump); err != nil {
		return fmt.Errorf("lab safety boundary: %w", err)
	}
	runner, err := remote.NewOpenSSH(*knownHosts, *proxyJump)
	if err != nil {
		return err
	}
	type backupNode struct {
		role     string
		target   remote.Target
		scheme   string
		basePath string
		curlTLS  string
	}
	nodes := []backupNode{
		{role: "entry", target: remote.Target{Host: inv.Entry.Host, User: inv.Entry.SSHUser, Port: inv.Entry.SSHPort, IdentityFile: inv.Entry.SSHIdentityFile}, scheme: "http", basePath: "/entry/panel/"},
		{role: "exit", target: remote.Target{Host: inv.Exit.Host, User: inv.Exit.SSHUser, Port: inv.Exit.SSHPort, IdentityFile: inv.Exit.SSHIdentityFile}, scheme: "https", basePath: "/exit/panel/", curlTLS: "-k"},
	}
	exports := make(map[string][]byte, 2)
	for _, node := range nodes {
		script, buildErr := backup.ExportScript(node.role, node.scheme, node.basePath, node.curlTLS)
		if buildErr != nil {
			return buildErr
		}
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		raw, runErr := runner.RunBytes(ctx, node.target, script, backup.MaxNodeExportBytes)
		cancel()
		if runErr != nil {
			return fmt.Errorf("export %s backup: %w", node.role, runErr)
		}
		exports[node.role] = raw
		fmt.Fprintf(out, "3XUI_BACKUP_EXPORT_READY role=%s\n", node.role)
	}
	if err := backup.Create(*outputPath, *recipient, inv.Cluster.Name, exports["entry"], exports["exit"], time.Now()); err != nil {
		return err
	}
	abs, err := filepath.Abs(*outputPath)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "3XUI_LAB_BACKUP_READY output=%s encryption=age\n", abs)
	return nil
}

func runBackupVerify(args []string, out, errOut io.Writer) error {
	flags := flag.NewFlagSet("backup-verify", flag.ContinueOnError)
	flags.SetOutput(errOut)
	input := flags.String("input", "", "encrypted backup path")
	identity := flags.String("identity", "", "age identity path")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || strings.TrimSpace(*input) == "" || strings.TrimSpace(*identity) == "" {
		return errors.New("backup-verify requires --input and --identity and accepts no positional arguments")
	}
	manifest, err := backup.Verify(*input, *identity)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "3XUI_BACKUP_VERIFIED cluster=%s created=%s members=%d\n", manifest.Cluster, manifest.CreatedAt, len(manifest.Members))
	return nil
}

func runRollback(args []string, in io.Reader, out, errOut io.Writer) error {
	flags := flag.NewFlagSet("rollback", flag.ContinueOnError)
	flags.SetOutput(errOut)
	inventoryPath := flags.String("inventory", "inventory.yml", "inventory path")
	knownHosts := flags.String("known-hosts", "~/.ssh/known_hosts", "pinned SSH known_hosts file")
	proxyJump := flags.String("proxy-jump", "", "required OpenSSH jump target for the isolated lab")
	labMode := flags.Bool("lab", false, "rollback only a pending isolated-container transaction")
	yes := flags.Bool("yes", false, "confirm rollback non-interactively")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("rollback accepts no positional arguments")
	}
	if !*labMode {
		return fmt.Errorf("production rollback: %w", ErrNotImplemented)
	}
	inv, err := inventory.Load(*inventoryPath)
	if err != nil {
		return err
	}
	if err := deploylab.ValidateBoundary(inv, *proxyJump); err != nil {
		return fmt.Errorf("lab safety boundary: %w", err)
	}
	if !*yes {
		reader := bufio.NewReader(in)
		fmt.Fprint(out, "Restore the pending transaction on both isolated lab nodes? [y/N]: ")
		answer, readErr := reader.ReadString('\n')
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return readErr
		}
		if strings.ToLower(strings.TrimSpace(answer)) != "y" {
			return errors.New("lab rollback cancelled")
		}
	}
	runner, err := remote.NewOpenSSH(*knownHosts, *proxyJump)
	if err != nil {
		return err
	}
	type rollbackNode struct {
		role     string
		target   remote.Target
		endpoint transaction.Endpoint
		id       string
	}
	nodes := []rollbackNode{
		{role: "entry", target: remote.Target{Host: inv.Entry.Host, User: inv.Entry.SSHUser, Port: inv.Entry.SSHPort, IdentityFile: inv.Entry.SSHIdentityFile}, endpoint: transaction.Endpoint{Scheme: "http", BasePath: "/entry/panel/"}},
		{role: "exit", target: remote.Target{Host: inv.Exit.Host, User: inv.Exit.SSHUser, Port: inv.Exit.SSHPort, IdentityFile: inv.Exit.SSHIdentityFile}, endpoint: transaction.Endpoint{Scheme: "https", BasePath: "/exit/panel/", CurlTLS: "-k"}},
	}
	for index := range nodes {
		script, buildErr := transaction.CurrentIDScript(inv.Cluster.Name, nodes[index].role, nodes[index].endpoint)
		if buildErr != nil {
			return buildErr
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		raw, runErr := runner.Run(ctx, nodes[index].target, script)
		cancel()
		if runErr != nil {
			return fmt.Errorf("inspect %s pending transaction: %w", nodes[index].role, runErr)
		}
		nodes[index].id, err = transaction.ParseCurrentID(raw)
		if err != nil {
			return fmt.Errorf("inspect %s pending transaction: %w", nodes[index].role, err)
		}
	}
	pendingID := ""
	for _, node := range nodes {
		if node.id == "" {
			continue
		}
		if pendingID != "" && node.id != pendingID {
			return errors.New("entry and exit pending transaction IDs do not match")
		}
		pendingID = node.id
	}
	if pendingID == "" {
		return errors.New("no pending lab transaction")
	}
	var rollbackErr error
	for _, node := range nodes {
		if node.id == "" {
			continue
		}
		script, buildErr := transaction.RollbackScript(inv.Cluster.Name, node.role, node.id, node.endpoint)
		if buildErr != nil {
			rollbackErr = errors.Join(rollbackErr, buildErr)
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		raw, runErr := runner.Run(ctx, node.target, script)
		cancel()
		if runErr != nil {
			rollbackErr = errors.Join(rollbackErr, fmt.Errorf("%s rollback: %w", node.role, runErr))
			continue
		}
		writeReadyMarkers(out, raw)
	}
	if rollbackErr != nil {
		return rollbackErr
	}
	fmt.Fprintln(out, "3XUI_LAB_ROLLBACK_READY")
	return nil
}

func runDeploy(args []string, in io.Reader, out, errOut io.Writer) (retErr error) {
	flags := flag.NewFlagSet("deploy", flag.ContinueOnError)
	flags.SetOutput(errOut)
	inventoryPath := flags.String("inventory", "inventory.yml", "inventory path")
	knownHosts := flags.String("known-hosts", "~/.ssh/known_hosts", "pinned SSH known_hosts file")
	proxyJump := flags.String("proxy-jump", "", "required OpenSSH jump target for the isolated lab")
	labMode := flags.Bool("lab", false, "deploy only to loopback-forwarded isolated containers")
	yes := flags.Bool("yes", false, "confirm the lab mutation non-interactively")
	simulateFailure := flags.Bool("simulate-failure", false, "lab-only: fail after mutation to exercise automatic rollback")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("deploy accepts no positional arguments")
	}
	if !*labMode {
		return fmt.Errorf("production deploy: %w", ErrNotImplemented)
	}

	inv, err := inventory.Load(*inventoryPath)
	if err != nil {
		return err
	}
	if err := deploylab.ValidateBoundary(inv, *proxyJump); err != nil {
		return fmt.Errorf("lab safety boundary: %w", err)
	}
	if !*yes {
		reader := bufio.NewReader(in)
		fmt.Fprint(out, "Mutate only the isolated 3x-ui container lab? [y/N]: ")
		answer, readErr := reader.ReadString('\n')
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return readErr
		}
		if strings.ToLower(strings.TrimSpace(answer)) != "y" {
			return errors.New("lab deploy cancelled")
		}
	}

	runner, err := remote.NewOpenSSH(*knownHosts, *proxyJump)
	if err != nil {
		return err
	}
	entryTarget := remote.Target{Host: inv.Entry.Host, User: inv.Entry.SSHUser, Port: inv.Entry.SSHPort, IdentityFile: inv.Entry.SSHIdentityFile}
	exitTarget := remote.Target{Host: inv.Exit.Host, User: inv.Exit.SSHUser, Port: inv.Exit.SSHPort, IdentityFile: inv.Exit.SSHIdentityFile}

	fmt.Fprintln(out, "DEPLOY LAB (3x-ui API only; production targets are rejected)")
	checks := []struct {
		role   string
		server inventory.Server
		target remote.Target
	}{{"entry", inv.Entry, entryTarget}, {"exit", inv.Exit, exitTarget}}
	for _, item := range checks {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		raw, runErr := runner.Run(ctx, item.target, preflight.Script)
		cancel()
		if runErr != nil {
			return fmt.Errorf("%s lab preflight: %w", item.role, runErr)
		}
		facts, parseErr := preflight.Parse(strings.NewReader(raw))
		if parseErr != nil {
			return fmt.Errorf("%s lab preflight response: %w", item.role, parseErr)
		}
		report := preflight.Assess(item.role, item.server.Host, facts, true)
		if report.Status != preflight.StatusLabReady {
			return fmt.Errorf("%s lab preflight: %w", item.role, ErrPreflightBlocked)
		}
	}
	fmt.Fprintln(out, "3XUI_LAB_PREFLIGHT_READY")
	for _, item := range checks {
		script, buildErr := production.CandidateScript(item.role)
		if buildErr != nil {
			return buildErr
		}
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		raw, stageErr := runner.Run(ctx, item.target, script)
		cancel()
		if stageErr != nil {
			return fmt.Errorf("stage %s production candidate: %w", item.role, stageErr)
		}
		writeReadyMarkers(out, raw)
	}

	txID, err := transaction.NewID()
	if err != nil {
		return err
	}
	entryEndpoint := transaction.Endpoint{Scheme: "http", BasePath: "/entry/panel/"}
	exitEndpoint := transaction.Endpoint{Scheme: "https", BasePath: "/exit/panel/", CurlTLS: "-k"}
	type transactionNode struct {
		role     string
		target   remote.Target
		endpoint transaction.Endpoint
		started  bool
	}
	txNodes := []*transactionNode{
		{role: "exit", target: exitTarget, endpoint: exitEndpoint},
		{role: "entry", target: entryTarget, endpoint: entryEndpoint},
	}
	transactionActive := true
	defer func() {
		if retErr == nil || !transactionActive {
			return
		}
		for index := len(txNodes) - 1; index >= 0; index-- {
			node := txNodes[index]
			if !node.started {
				continue
			}
			script, buildErr := transaction.RollbackScript(inv.Cluster.Name, node.role, txID, node.endpoint)
			if buildErr != nil {
				retErr = errors.Join(retErr, fmt.Errorf("build %s rollback: %w", node.role, buildErr))
				continue
			}
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			raw, rollbackErr := runner.Run(ctx, node.target, script)
			cancel()
			if rollbackErr != nil {
				retErr = errors.Join(retErr, fmt.Errorf("%s automatic rollback: %w", node.role, rollbackErr))
				continue
			}
			writeReadyMarkers(out, raw)
		}
	}()
	for _, node := range txNodes {
		script, buildErr := transaction.BeginScript(inv.Cluster.Name, node.role, txID, node.endpoint)
		if buildErr != nil {
			return buildErr
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		raw, beginErr := runner.Run(ctx, node.target, script)
		cancel()
		if beginErr != nil {
			return fmt.Errorf("begin %s transaction: %w", node.role, beginErr)
		}
		node.started = true
		writeReadyMarkers(out, raw)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	exitRaw, err := runner.Run(ctx, exitTarget, deploylab.ExitTokenScript())
	cancel()
	if err != nil {
		return fmt.Errorf("prepare exit node token: %w", err)
	}
	exitAccess, err := deploylab.ParseExitAccess(exitRaw)
	if err != nil {
		return err
	}
	happDeeplink := ""
	happDeeplinkSHA := ""
	if inv.Subscription.HappRouting == "roscomvpn-default" {
		ctx, cancel = context.WithTimeout(context.Background(), 20*time.Second)
		happDeeplink, happDeeplinkSHA, err = fetchRoscomVPN(ctx)
		cancel()
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "3XUI_ROSCOMVPN_ASSET_READY commit=%s\n", routing.RoscomVPNCommit[:12])
	}
	entryScript, err := deploylab.EntryScript(inv, exitAccess, happDeeplink)
	if err != nil {
		return err
	}
	ctx, cancel = context.WithTimeout(context.Background(), 90*time.Second)
	entryRaw, err := runner.Run(ctx, entryTarget, entryScript)
	cancel()
	if err != nil {
		return fmt.Errorf("configure entry/master: %w", err)
	}
	writeReadyMarkers(out, entryRaw)
	if inv.Certificates.NodeTransport == "mtls" {
		masterCA, parseErr := deploylab.ParseMtlsCA(entryRaw)
		if parseErr != nil {
			return parseErr
		}
		ctx, cancel = context.WithTimeout(context.Background(), 20*time.Second)
		exitCertRaw, runErr := runner.Run(ctx, exitTarget, deploylab.ExitCertificateScript())
		cancel()
		if runErr != nil {
			return fmt.Errorf("read exit server certificate: %w", runErr)
		}
		exitCertificate, parseErr := deploylab.ParseExitCertificate(exitCertRaw)
		if parseErr != nil {
			return parseErr
		}
		entryTrustScript, buildErr := deploylab.EntryTrustExitCertificateScript(exitCertificate, inv.Exit.CascadeAddress)
		if buildErr != nil {
			return buildErr
		}
		ctx, cancel = context.WithTimeout(context.Background(), 30*time.Second)
		entryTrustRaw, runErr := runner.Run(ctx, entryTarget, entryTrustScript)
		cancel()
		if runErr != nil {
			return fmt.Errorf("trust exit panel certificate: %w", runErr)
		}
		writeReadyMarkers(out, entryTrustRaw)
		exitTrustScript, buildErr := deploylab.ExitTrustMtlsScript(masterCA)
		if buildErr != nil {
			return buildErr
		}
		ctx, cancel = context.WithTimeout(context.Background(), 45*time.Second)
		exitMtlsRaw, runErr := runner.Run(ctx, exitTarget, exitTrustScript)
		cancel()
		if runErr != nil {
			return fmt.Errorf("enable exit mTLS trust: %w", runErr)
		}
		writeReadyMarkers(out, exitMtlsRaw)
		entrySwitchScript, buildErr := deploylab.EntrySwitchNodeMtlsScript(inv)
		if buildErr != nil {
			return buildErr
		}
		ctx, cancel = context.WithTimeout(context.Background(), 30*time.Second)
		entrySwitchRaw, runErr := runner.Run(ctx, entryTarget, entrySwitchScript)
		cancel()
		if runErr != nil {
			return fmt.Errorf("switch node transport to mTLS: %w", runErr)
		}
		writeReadyMarkers(out, entrySwitchRaw)
	}
	if *simulateFailure {
		return errors.New("simulated lab failure after managed mutation")
	}

	ctx, cancel = context.WithTimeout(context.Background(), 60*time.Second)
	exitVerifyRaw, err := runner.Run(ctx, exitTarget, deploylab.ExitVerifyScript(inv.InterserverAlternativePort("reality-xhttp")))
	cancel()
	if err != nil {
		return fmt.Errorf("verify exit/node: %w", err)
	}
	writeReadyMarkers(out, exitVerifyRaw)

	e2eScript, err := deploylab.E2EScript(inv, happDeeplinkSHA)
	if err != nil {
		return err
	}
	ctx, cancel = context.WithTimeout(context.Background(), 180*time.Second)
	e2eRaw, err := runner.Run(ctx, entryTarget, e2eScript)
	cancel()
	if err != nil {
		return fmt.Errorf("cascade end-to-end: %w", err)
	}
	writeReadyMarkers(out, e2eRaw)
	for _, node := range txNodes {
		script, buildErr := transaction.CommitScript(inv.Cluster.Name, node.role, txID, node.endpoint)
		if buildErr != nil {
			return buildErr
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		raw, commitErr := runner.Run(ctx, node.target, script)
		cancel()
		if commitErr != nil {
			return fmt.Errorf("commit %s transaction: %w", node.role, commitErr)
		}
		writeReadyMarkers(out, raw)
	}
	transactionActive = false
	fmt.Fprintln(out, "3XUI_LAB_DEPLOY_READY")
	return nil
}

func fetchRoscomVPN(ctx context.Context) (string, string, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, routing.RoscomVPNDeeplinkURL, nil)
	if err != nil {
		return "", "", fmt.Errorf("prepare RoscomVPN request: %w", err)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return "", "", fmt.Errorf("download pinned RoscomVPN profile: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("download pinned RoscomVPN profile: HTTP %d", response.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, 64*1024))
	if err != nil {
		return "", "", fmt.Errorf("read RoscomVPN profile: %w", err)
	}
	return routing.AdaptRoscomVPNForCascade(raw)
}

func writeReadyMarkers(out io.Writer, raw string) {
	for _, line := range strings.Split(raw, "\n") {
		isInternalMaterial := strings.HasPrefix(line, "3XUI_NODE_TOKEN") ||
			strings.HasPrefix(line, "3XUI_NODE_PIN") ||
			strings.HasPrefix(line, "3XUI_EXIT_CERT") ||
			strings.HasPrefix(line, "3XUI_MTLS_CA")
		if strings.HasPrefix(line, "3XUI_") && !isInternalMaterial {
			fmt.Fprintln(out, line)
		}
	}
}

func runPreflight(args []string, out, errOut io.Writer) error {
	flags := flag.NewFlagSet("preflight", flag.ContinueOnError)
	flags.SetOutput(errOut)
	inventoryPath := flags.String("inventory", "inventory.yml", "inventory path")
	knownHosts := flags.String("known-hosts", "~/.ssh/known_hosts", "pinned SSH known_hosts file")
	proxyJump := flags.String("proxy-jump", "", "optional OpenSSH jump target")
	labMode := flags.Bool("lab", false, "allow container limitations; never use as production proof")
	jsonOutput := flags.Bool("json", false, "print machine-readable JSON")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("preflight accepts no positional arguments")
	}

	inv, err := inventory.Load(*inventoryPath)
	if err != nil {
		return err
	}
	runner, err := remote.NewOpenSSH(*knownHosts, *proxyJump)
	if err != nil {
		return err
	}

	type target struct {
		role   string
		server inventory.Server
	}
	targets := []target{{role: "entry", server: inv.Entry}, {role: "exit", server: inv.Exit}}
	reports := make([]preflight.Report, 0, len(targets))
	blocked := false
	for _, item := range targets {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		raw, runErr := runner.Run(ctx, remote.Target{
			Host: item.server.Host, User: item.server.SSHUser, Port: item.server.SSHPort,
			IdentityFile: item.server.SSHIdentityFile,
		}, preflight.Script)
		cancel()
		if runErr != nil {
			return fmt.Errorf("%s preflight: %w", item.role, runErr)
		}
		facts, parseErr := preflight.Parse(strings.NewReader(raw))
		if parseErr != nil {
			return fmt.Errorf("%s preflight response: %w", item.role, parseErr)
		}
		report := preflight.Assess(item.role, item.server.Host, facts, *labMode)
		if !*labMode {
			report = preflight.AssessRequiredPorts(report, requiredCleanHostPorts(item.role, inv))
			if item.role == "entry" && inv.Transport.Hysteria2.Enabled {
				report = preflight.AssessRequiredUDPPorts(report, []int{inv.Transport.Hysteria2.Port})
			}
		}
		reports = append(reports, report)
		blocked = blocked || report.Status == preflight.StatusBlocked
	}

	if *jsonOutput {
		encoded, err := json.MarshalIndent(reports, "", "  ")
		if err != nil {
			return fmt.Errorf("encode preflight report: %w", err)
		}
		fmt.Fprintln(out, string(encoded))
	} else {
		fmt.Fprintln(out, "PREFLIGHT (read-only SSH — no server changes)")
		for _, report := range reports {
			fmt.Fprintf(out, "\n%s %s: %s\n", strings.ToUpper(report.Role), report.Host, report.Status)
			fmt.Fprintf(out, "  OS: %s %s; arch: %s; kernel: %s\n", report.Facts.OSID, report.Facts.OSVersion, report.Facts.Arch, report.Facts.Kernel)
			fmt.Fprintf(out, "  IPv4 default route: %s; global IPv6: %s; TCP/443: %s\n", report.Facts.IPv4Default, report.Facts.IPv6Global, report.Facts.Port443)
			for _, warning := range report.Warnings {
				fmt.Fprintln(out, "  WARN:", warning)
			}
			for _, problem := range report.Problems {
				fmt.Fprintln(out, "  BLOCK:", problem)
			}
		}
	}
	if blocked {
		return ErrPreflightBlocked
	}
	return nil
}

func requiredCleanHostPorts(role string, inv inventory.Inventory) []int {
	ports := []int{inv.Panel.Port, inv.Subscription.Port}
	if inv.Certificates.SubscriptionTLS == "acme-ip" {
		ports = append(ports, 80)
	}
	if role == "entry" {
		ports = append(ports, inv.Transport.ClientPort)
		for _, alternative := range inv.Transport.ClientAlternatives {
			ports = append(ports, alternative.Port)
		}
	} else {
		ports = append(ports, inv.Transport.InterserverPort)
		for _, alternative := range inv.Transport.InterserverAlternatives {
			ports = append(ports, alternative.Port)
		}
	}
	return ports
}

func runInit(args []string, in io.Reader, out, errOut io.Writer) error {
	flags := flag.NewFlagSet("init", flag.ContinueOnError)
	flags.SetOutput(errOut)
	path := flags.String("output", "inventory.yml", "inventory path")
	force := flags.Bool("force", false, "replace an existing inventory")
	profile := flags.String("profile", "base", "transport profile: base or extended")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("init accepts no positional arguments")
	}
	if _, err := os.Stat(*path); err == nil && !*force {
		return fmt.Errorf("%s already exists; use --force to replace it", *path)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect output path: %w", err)
	}

	inv := inventory.Default()
	switch strings.ToLower(strings.TrimSpace(*profile)) {
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
		return errors.New("init --profile must be base or extended")
	}
	reader := bufio.NewReader(in)
	var err error
	if inv.Cluster.Name, err = prompt(reader, out, "Cluster name", inv.Cluster.Name); err != nil {
		return err
	}
	if inv.Entry.Host, err = promptRequired(reader, out, "Entry server IPv4 or hostname"); err != nil {
		return err
	}
	if inv.Exit.Host, err = promptRequired(reader, out, "Exit server IPv4 or hostname"); err != nil {
		return err
	}
	if inv.Entry.SSHUser, err = prompt(reader, out, "Entry SSH user", inv.Entry.SSHUser); err != nil {
		return err
	}
	if inv.Exit.SSHUser, err = prompt(reader, out, "Exit SSH user", inv.Exit.SSHUser); err != nil {
		return err
	}
	if inv.Entry.SSHIdentityFile, err = prompt(reader, out, "Entry SSH identity file", inv.Entry.SSHIdentityFile); err != nil {
		return err
	}
	if inv.Exit.SSHIdentityFile, err = prompt(reader, out, "Exit SSH identity file", inv.Exit.SSHIdentityFile); err != nil {
		return err
	}
	// The working RU/NL cascade uses publicly trusted, short-lived IP
	// certificates. Select the same 3x-ui IP-certificate flow automatically;
	// XUI_ACME_EMAIL is optional upstream and is not required in inventory.
	inv.Certificates.SubscriptionTLS = "acme-ip"

	if err := inventory.Save(*path, inv); err != nil {
		return err
	}
	fmt.Fprintf(out, "\nCreated %s with mode 0600. No passwords or VPN keys were stored.\n", *path)
	fmt.Fprintf(out, "Transport profile: %s.\n", strings.ToLower(strings.TrimSpace(*profile)))
	fmt.Fprintln(out, "Next: vpnctl plan --inventory", *path)
	return nil
}

func runPlan(args []string, out, errOut io.Writer) error {
	flags := flag.NewFlagSet("plan", flag.ContinueOnError)
	flags.SetOutput(errOut)
	path := flags.String("inventory", "inventory.yml", "inventory path")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("plan accepts no positional arguments")
	}
	inv, err := inventory.Load(*path)
	if err != nil {
		return err
	}
	productionPlan, err := production.BuildPlan(inv)
	if err != nil {
		return fmt.Errorf("production plan: %w", err)
	}
	var validatedCertificates []string
	if inv.Certificates.SubscriptionTLS == "existing" {
		expected := strings.TrimSpace(inv.Subscription.PublicDomain)
		if expected == "" {
			expected = inv.Entry.Host
		}
		if _, err := certificate.LoadExisting(inv.Certificates.SubscriptionCertFile, inv.Certificates.SubscriptionKeyFile, expected, time.Now()); err != nil {
			return fmt.Errorf("validate existing subscription TLS: %w", err)
		}
		validatedCertificates = append(validatedCertificates, "subscription TLS covers "+expected+" and chains to a system root")
	}
	if inv.Certificates.PanelTLS == "existing" {
		if _, err := certificate.LoadExisting(inv.Certificates.PanelCertFile, inv.Certificates.PanelKeyFile, inv.Panel.PublicDomain, time.Now()); err != nil {
			return fmt.Errorf("validate existing panel TLS: %w", err)
		}
		validatedCertificates = append(validatedCertificates, "panel TLS covers "+inv.Panel.PublicDomain+" and chains to a system root")
	}

	fmt.Fprintln(out, "PLAN (local validation only — no SSH connections, no server changes)")
	fmt.Fprintf(out, "Cluster: %s\n", inv.Cluster.Name)
	fmt.Fprintln(out, "1. Pin SSH host keys for entry and exit")
	fmt.Fprintln(out, "2. Run read-only OS, network, port, firewall and package preflight")
	fmt.Fprintln(out, "3. Install and verify the exit node")
	fmt.Fprintln(out, "4. Install the entry master and create the client subscription")
	fmt.Fprintln(out, "5. Enroll the exit with scoped token, then switch node trust to mTLS")
	fmt.Fprintln(out, "6. Create IPv4/IPv6 inter-server outbounds and server-side routing")
	fmt.Fprintln(out, "7. Validate candidates, restart in stages, and run end-to-end checks")
	fmt.Fprintln(out, "\nPinned production candidate and firewall ownership:")
	for _, line := range productionPlan.Lines() {
		fmt.Fprintln(out, "-", line)
	}
	for _, line := range validatedCertificates {
		fmt.Fprintln(out, "- validated:", line)
	}
	fmt.Fprintln(out, "\nNext: run vpnctl preflight. Remote deploy remains disabled in this design preview.")
	return nil
}

func prompt(reader *bufio.Reader, out io.Writer, label, defaultValue string) (string, error) {
	fmt.Fprintf(out, "%s [%s]: ", label, defaultValue)
	value, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return defaultValue, nil
	}
	return value, nil
}

func promptRequired(reader *bufio.Reader, out io.Writer, label string) (string, error) {
	fmt.Fprintf(out, "%s: ", label)
	value, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return "", fmt.Errorf("%s is required", label)
	}
	return value, nil
}
