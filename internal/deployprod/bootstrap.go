// SPDX-License-Identifier: GPL-3.0-only

// Package deployprod coordinates the clean-host production bootstrap. Nothing
// in this package opens SSH by itself; vpnctl production deploy remains gated.
package deployprod

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/b1ts23/xray-easy-cascade/internal/inventory"
	"github.com/b1ts23/xray-easy-cascade/internal/production"
	"github.com/b1ts23/xray-easy-cascade/internal/remote"
)

type Runner interface {
	Run(context.Context, remote.Target, string) (string, error)
}

type node struct {
	role   string
	target remote.Target
	steps  []production.InstallStep
}

const stepTimeout = 3 * time.Minute

func target(server inventory.Server) remote.Target {
	return remote.Target{
		Host:         server.Host,
		User:         server.SSHUser,
		Port:         server.SSHPort,
		IdentityFile: server.SSHIdentityFile,
	}
}

func expectedMarker(step, role string) string {
	switch step {
	case "candidate":
		return "3XUI_PRODUCTION_CANDIDATE_READY role=" + role
	case "stage":
		return "3XUI_PRODUCTION_STAGED role=" + role
	case "firewall":
		return "3XUI_PRODUCTION_FIREWALL_READY role=" + role
	case "activate":
		return "3XUI_PRODUCTION_ACTIVATED role=" + role
	case "acme-ip":
		return "3XUI_PRODUCTION_ACME_READY role=" + role
	case "subscription-tls":
		return "3XUI_PRODUCTION_SUBSCRIPTION_TLS_READY"
	default:
		return ""
	}
}

// BootstrapHosts executes only the clean-host lifecycle. Cascade inbounds,
// node enrollment, mTLS and final E2E are deliberately separate gates.
func BootstrapHosts(ctx context.Context, runner Runner, inv inventory.Inventory, out io.Writer) (retErr error) {
	if runner == nil {
		return errors.New("production bootstrap runner is required")
	}
	if err := inv.Validate(); err != nil {
		return err
	}
	exitSteps, err := production.BuildInstallSteps("exit", inv)
	if err != nil {
		return err
	}
	entrySteps, err := production.BuildInstallSteps("entry", inv)
	if err != nil {
		return err
	}
	nodes := []node{
		{role: "exit", target: target(inv.Exit), steps: exitSteps},
		{role: "entry", target: target(inv.Entry), steps: entrySteps},
	}
	var owned []node
	defer func() {
		if retErr == nil {
			return
		}
		var rollbackErr error
		for index := len(owned) - 1; index >= 0; index-- {
			script, buildErr := production.InstallRollbackScript(owned[index].role)
			if buildErr != nil {
				rollbackErr = errors.Join(rollbackErr, buildErr)
				continue
			}
			rollbackCtx, cancel := context.WithTimeout(context.Background(), stepTimeout)
			raw, runErr := runner.Run(rollbackCtx, owned[index].target, script)
			cancel()
			if runErr != nil {
				rollbackErr = errors.Join(rollbackErr, fmt.Errorf("rollback %s bootstrap: %w", owned[index].role, runErr))
				continue
			}
			marker := "3XUI_PRODUCTION_INSTALL_ROLLED_BACK role=" + owned[index].role
			if !strings.Contains(raw, marker) {
				rollbackErr = errors.Join(rollbackErr, fmt.Errorf("rollback %s bootstrap returned no readiness marker", owned[index].role))
				continue
			}
			fmt.Fprintln(out, marker)
		}
		if rollbackErr != nil {
			retErr = errors.Join(retErr, rollbackErr)
		}
	}()

	for _, current := range nodes {
		ownedCurrent := false
		for _, step := range current.steps {
			stepCtx, cancel := context.WithTimeout(ctx, stepTimeout)
			raw, runErr := runner.Run(stepCtx, current.target, step.Script)
			cancel()
			if runErr != nil {
				return fmt.Errorf("%s %s: %w", current.role, step.Name, runErr)
			}
			// A successful stage command owns clean-host paths even if its final
			// marker is lost. Register it before marker validation so the defer
			// still performs a conservative rollback.
			if step.Name == "stage" && !ownedCurrent {
				owned = append(owned, current)
				ownedCurrent = true
			}
			marker := expectedMarker(step.Name, current.role)
			if marker == "" || !strings.Contains(raw, marker) {
				return fmt.Errorf("%s %s returned no readiness marker", current.role, step.Name)
			}
			fmt.Fprintln(out, marker)
		}
	}
	fmt.Fprintln(out, "3XUI_PRODUCTION_HOST_BOOTSTRAP_READY")
	return nil
}
