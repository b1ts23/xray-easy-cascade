// SPDX-License-Identifier: GPL-3.0-only

package deployprod

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"time"

	"github.com/b1ts23/xray-easy-cascade/internal/deploylab"
	"github.com/b1ts23/xray-easy-cascade/internal/inventory"
	"github.com/b1ts23/xray-easy-cascade/internal/transaction"
)

const runtimeTimeout = 2 * time.Minute
const publicIPv6Prefix = "3XUI_PUBLIC_IPV6\t"

func effectiveAddress(server inventory.Server) string {
	if address := strings.TrimSpace(server.CascadeAddress); address != "" {
		return address
	}
	return strings.TrimSpace(server.Host)
}

func discoverPublicIPv6Script() string {
	return `set -eu
command -v ip >/dev/null
address=$(ip -6 -o addr show scope global | awk '$3=="inet6" {sub(/\/.*/, "", $4); print $4; exit}')
if [ -z "$address" ]; then address=disabled; fi
printf '3XUI_PUBLIC_IPV6\t%s\n' "$address"
`
}

func parsePublicIPv6(raw string) (string, error) {
	value := ""
	for _, line := range strings.Split(raw, "\n") {
		if !strings.HasPrefix(line, publicIPv6Prefix) {
			continue
		}
		if value != "" {
			return "", errors.New("node returned more than one public IPv6 marker")
		}
		value = strings.TrimPrefix(line, publicIPv6Prefix)
	}
	if value == "disabled" {
		return value, nil
	}
	address, err := netip.ParseAddr(value)
	if err != nil || !address.Is6() || !address.IsGlobalUnicast() || address.IsPrivate() {
		return "", errors.New("node returned no valid public IPv6 address")
	}
	return address.String(), nil
}

// ResolveProductionNetwork turns auto IPv6 into explicit addresses before the
// firewall plan is built. This is deliberately done over read-only SSH on the
// clean hosts, so exit IPv6 rules exist before 3x-ui is activated.
func ResolveProductionNetwork(ctx context.Context, runner Runner, inv inventory.Inventory) (inventory.Inventory, error) {
	if runner == nil {
		return inventory.Inventory{}, errors.New("production network runner is required")
	}
	work := inv
	work.Entry.CascadeAddress = effectiveAddress(work.Entry)
	work.Exit.CascadeAddress = effectiveAddress(work.Exit)
	for role, raw := range map[string]string{"entry": work.Entry.CascadeAddress, "exit": work.Exit.CascadeAddress} {
		address, parseErr := netip.ParseAddr(raw)
		if parseErr != nil || !address.IsGlobalUnicast() || address.IsPrivate() {
			return inventory.Inventory{}, fmt.Errorf("production %s cascade address must be a public IP", role)
		}
	}
	if work.Transport.IPv6Fallback == "disabled" || work.Entry.PublicIPv6 == "disabled" || work.Exit.PublicIPv6 == "disabled" {
		work.Entry.PublicIPv6 = "disabled"
		work.Exit.PublicIPv6 = "disabled"
		return work, nil
	}
	resolve := func(server inventory.Server) (string, error) {
		if server.PublicIPv6 != "auto" {
			return parsePublicIPv6(publicIPv6Prefix + server.PublicIPv6)
		}
		runCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		raw, runErr := runner.Run(runCtx, target(server), discoverPublicIPv6Script())
		if runErr != nil {
			return "", runErr
		}
		return parsePublicIPv6(raw)
	}
	entryIPv6, entryErr := resolve(work.Entry)
	exitIPv6, exitErr := resolve(work.Exit)
	if entryErr != nil || exitErr != nil || entryIPv6 == "disabled" || exitIPv6 == "disabled" {
		if work.Transport.IPv6Fallback == "required" {
			return inventory.Inventory{}, errors.Join(errors.New("global IPv6 is required on both nodes"), entryErr, exitErr)
		}
		work.Entry.PublicIPv6 = "disabled"
		work.Exit.PublicIPv6 = "disabled"
		return work, nil
	}
	work.Entry.PublicIPv6 = entryIPv6
	work.Exit.PublicIPv6 = exitIPv6
	return work, nil
}

func productionExitTokenScript() string {
	return `set -eu
cd /usr/local/x-ui
token=$(./x-ui setting -tokenName xray-cascade-master -tokenScope node-sync -getApiToken | sed -n 's/^apiToken: //p' | tail -n 1)
test -n "$token"
pin=$(openssl x509 -in /root/cert/ip/fullchain.pem -outform DER | sha256sum | awk '{print $1}')
test "${#pin}" -eq 64
printf '3XUI_NODE_TOKEN\t%s\n' "$token"
printf '3XUI_NODE_PIN\t%s\n' "$pin"
unset token pin
`
}

func productionExitVerifyScript(panelPort int) string {
	return fmt.Sprintf(`set -eu
cd /usr/local/x-ui
token=$(./x-ui setting -tokenName xray-cascade-verifier -tokenScope admin -getApiToken | sed -n 's/^apiToken: //p' | tail -n 1)
test -n "$token"
umask 077
printf 'Authorization: Bearer %%s\n' "$token" > /run/xray-cascade-header
unset token
trap 'rm -f /run/xray-cascade-header /run/xray-cascade-runtime.json' EXIT INT TERM
curl --fail-with-body -k -sS -H @/run/xray-cascade-header https://127.0.0.1:%d/exit/panel/api/server/getConfigJson > /run/xray-cascade-runtime.json
jq -e '.success==true and (.obj.inbounds|any(.tag=="in-cascade-exit"))' /run/xray-cascade-runtime.json >/dev/null
echo 3XUI_PRODUCTION_EXIT_CONFIG_READY
`, panelPort)
}

// ConfigureRuntime mutates only the two fresh 3x-ui databases. Both nodes are
// snapshotted first and rolled back in reverse order unless every runtime and
// mTLS check succeeds. Host installation is intentionally a separate gate.
func ConfigureRuntime(ctx context.Context, runner Runner, inv inventory.Inventory, happDeeplink, happSHA string, out io.Writer) (retErr error) {
	if runner == nil {
		return errors.New("production runtime runner is required")
	}
	if err := inv.Validate(); err != nil {
		return err
	}
	if inv.Certificates.SubscriptionTLS != "acme-ip" {
		return errors.New("production runtime currently requires acme-ip certificates")
	}
	if inv.Subscription.HappRouting == "roscomvpn-default" {
		actual := fmt.Sprintf("%x", sha256.Sum256([]byte(happDeeplink)))
		if strings.TrimSpace(happDeeplink) == "" || !strings.EqualFold(actual, happSHA) {
			return errors.New("pinned RoscomVPN deeplink and SHA-256 are required")
		}
	}
	work, err := ResolveProductionNetwork(ctx, runner, inv)
	if err != nil {
		return err
	}
	if work.Entry.PublicIPv6 != "disabled" && work.Exit.PublicIPv6 != "disabled" {
		fmt.Fprintln(out, "3XUI_PRODUCTION_DUAL_STACK_READY")
	}

	txID, err := transaction.NewID()
	if err != nil {
		return err
	}
	type txNode struct {
		role     string
		target   inventory.Server
		endpoint transaction.Endpoint
		started  bool
	}
	nodes := []*txNode{
		{role: "exit", target: work.Exit, endpoint: transaction.Endpoint{Scheme: "https", BasePath: "/exit/panel/", CurlTLS: "-k", Port: work.Panel.Port}},
		{role: "entry", target: work.Entry, endpoint: transaction.Endpoint{Scheme: "https", BasePath: "/entry/panel/", CurlTLS: "-k", Port: work.Panel.Port}},
	}
	defer func() {
		if retErr == nil {
			return
		}
		for index := len(nodes) - 1; index >= 0; index-- {
			node := nodes[index]
			if !node.started {
				continue
			}
			script, buildErr := transaction.RollbackScript(work.Cluster.Name, node.role, txID, node.endpoint)
			if buildErr != nil {
				retErr = errors.Join(retErr, buildErr)
				continue
			}
			rollbackCtx, cancel := context.WithTimeout(context.Background(), runtimeTimeout)
			raw, runErr := runner.Run(rollbackCtx, target(node.target), script)
			cancel()
			if runErr != nil {
				retErr = errors.Join(retErr, fmt.Errorf("rollback %s runtime: %w", node.role, runErr))
				continue
			}
			if !strings.Contains(raw, "3XUI_TRANSACTION_ROLLED_BACK role="+node.role) {
				retErr = errors.Join(retErr, fmt.Errorf("rollback %s runtime returned no readiness marker", node.role))
			}
		}
	}()
	for _, node := range nodes {
		script, buildErr := transaction.BeginScript(work.Cluster.Name, node.role, txID, node.endpoint)
		if buildErr != nil {
			return buildErr
		}
		runCtx, cancel := context.WithTimeout(ctx, runtimeTimeout)
		raw, runErr := runner.Run(runCtx, target(node.target), script)
		cancel()
		if runErr != nil {
			return fmt.Errorf("begin %s runtime transaction: %w", node.role, runErr)
		}
		node.started = true
		if !strings.Contains(raw, "3XUI_TRANSACTION_SNAPSHOT_READY role="+node.role) {
			return fmt.Errorf("begin %s runtime transaction returned no readiness marker", node.role)
		}
	}

	run := func(server inventory.Server, label, script, marker string) (string, error) {
		runCtx, cancel := context.WithTimeout(ctx, runtimeTimeout)
		defer cancel()
		raw, runErr := runner.Run(runCtx, target(server), script)
		if runErr != nil {
			return "", fmt.Errorf("%s: %w", label, runErr)
		}
		if marker != "" && !strings.Contains(raw, marker) {
			return "", fmt.Errorf("%s returned no readiness marker", label)
		}
		if marker != "" {
			fmt.Fprintln(out, marker)
		}
		return raw, nil
	}
	exitRaw, err := run(work.Exit, "prepare exit node token", productionExitTokenScript(), "3XUI_NODE_TOKEN\t")
	if err != nil {
		return err
	}
	access, err := deploylab.ParseExitAccess(exitRaw)
	if err != nil {
		return err
	}
	entryScript, err := deploylab.EntryScriptWithOptions(work, access, happDeeplink, deploylab.ProductionRuntimeOptions())
	if err != nil {
		return err
	}
	entryRaw, err := run(work.Entry, "configure production entry", entryScript, "3XUI_ENTRY_CONFIG_READY")
	if err != nil {
		return err
	}
	if work.Certificates.NodeTransport == "mtls" {
		masterCA, parseErr := deploylab.ParseMtlsCA(entryRaw)
		if parseErr != nil {
			return parseErr
		}
		trustScript, buildErr := deploylab.ExitTrustMtlsScriptAt(masterCA, work.Panel.Port)
		if buildErr != nil {
			return buildErr
		}
		if _, runErr := run(work.Exit, "enable production exit mTLS trust", trustScript, "3XUI_NODE_MTLS_TRUST_READY"); runErr != nil {
			return runErr
		}
		switchScript, buildErr := deploylab.EntrySwitchNodeMtlsScriptWithOptions(work, deploylab.ProductionRuntimeOptions())
		if buildErr != nil {
			return buildErr
		}
		if _, runErr := run(work.Entry, "switch production node to mTLS", switchScript, "3XUI_NODE_MTLS_READY"); runErr != nil {
			return runErr
		}
	}
	if _, err = run(work.Exit, "verify production exit runtime", productionExitVerifyScript(work.Panel.Port), "3XUI_PRODUCTION_EXIT_CONFIG_READY"); err != nil {
		return err
	}
	// Do not commit either database until a real client launched on the exit
	// host has crossed the public entry edge, reached the expected exit IP and
	// fetched the HAPP subscription with the pinned routing header.
	if err = VerifyProduction(ctx, runner, work, happSHA, out); err != nil {
		return err
	}
	for _, node := range nodes {
		script, buildErr := transaction.CommitScript(work.Cluster.Name, node.role, txID, node.endpoint)
		if buildErr != nil {
			return buildErr
		}
		if _, runErr := run(node.target, "commit "+node.role+" runtime", script, "3XUI_TRANSACTION_COMMITTED role="+node.role); runErr != nil {
			return runErr
		}
	}
	for _, node := range nodes {
		node.started = false
	}
	fmt.Fprintln(out, "3XUI_PRODUCTION_RUNTIME_READY")
	return nil
}
