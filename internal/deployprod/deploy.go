// SPDX-License-Identifier: GPL-3.0-only

package deployprod

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/b1ts23/xray-easy-cascade/internal/inventory"
	"github.com/b1ts23/xray-easy-cascade/internal/production"
)

// DeployFreshHosts composes the already fail-closed host bootstrap and runtime
// transaction. It is intentionally not wired to the public CLI until the same
// path passes real ACME and cascade E2E on two independent public IPs.
func DeployFreshHosts(ctx context.Context, runner Runner, inv inventory.Inventory, happDeeplink, happSHA string, out io.Writer) (retErr error) {
	resolved, err := ResolveProductionNetwork(ctx, runner, inv)
	if err != nil {
		return err
	}
	if err := BootstrapHosts(ctx, runner, resolved, out); err != nil {
		return err
	}
	bootstrapOwned := true
	defer func() {
		if retErr == nil || !bootstrapOwned {
			return
		}
		for _, item := range []struct {
			role   string
			server inventory.Server
		}{{"entry", resolved.Entry}, {"exit", resolved.Exit}} {
			script, buildErr := production.InstallRollbackScript(item.role)
			if buildErr != nil {
				retErr = errors.Join(retErr, buildErr)
				continue
			}
			raw, runErr := runner.Run(context.Background(), target(item.server), script)
			if runErr != nil {
				retErr = errors.Join(retErr, fmt.Errorf("rollback %s fresh-host install: %w", item.role, runErr))
				continue
			}
			marker := "3XUI_PRODUCTION_INSTALL_ROLLED_BACK role=" + item.role
			if !strings.Contains(raw, marker) {
				retErr = errors.Join(retErr, fmt.Errorf("rollback %s fresh-host install returned no readiness marker", item.role))
				continue
			}
			fmt.Fprintln(out, marker)
		}
	}()
	if err := ConfigureRuntime(ctx, runner, resolved, happDeeplink, happSHA, out); err != nil {
		return err
	}
	bootstrapOwned = false
	fmt.Fprintln(out, "3XUI_PRODUCTION_DEPLOY_READY")
	return nil
}
