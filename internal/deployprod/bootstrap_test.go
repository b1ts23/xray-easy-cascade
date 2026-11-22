// SPDX-License-Identifier: GPL-3.0-only

package deployprod

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/b1ts23/xray-cascade/internal/inventory"
	"github.com/b1ts23/xray-cascade/internal/remote"
)

type fakeRunner struct {
	calls  []string
	failAt string
	omitAt string
}

func classify(script string) string {
	markers := []string{
		"3XUI_PRODUCTION_CANDIDATE_READY",
		"3XUI_PRODUCTION_STAGED",
		"3XUI_PRODUCTION_FIREWALL_READY",
		"3XUI_PRODUCTION_ACTIVATED",
		"3XUI_PRODUCTION_ACME_READY",
		"3XUI_PRODUCTION_SUBSCRIPTION_TLS_READY",
		"3XUI_PRODUCTION_INSTALL_ROLLED_BACK",
	}
	for _, marker := range markers {
		if strings.Contains(script, marker) {
			return marker
		}
	}
	return "unknown"
}

func (f *fakeRunner) Run(_ context.Context, target remote.Target, script string) (string, error) {
	kind := classify(script)
	call := target.Host + ":" + kind
	f.calls = append(f.calls, call)
	if call == f.failAt {
		return "", errors.New("simulated failure")
	}
	if call == f.omitAt {
		return "command completed without marker", nil
	}
	role := "entry"
	if target.Host == "198.51.100.20" {
		role = "exit"
	}
	return kind + " role=" + role + " address=203.0.113.10 port=2096\n", nil
}

func validInventory() inventory.Inventory {
	inv := inventory.Default()
	inv.Entry.Host = "203.0.113.10"
	inv.Exit.Host = "198.51.100.20"
	inv.Entry.PublicIPv6 = "disabled"
	inv.Exit.PublicIPv6 = "disabled"
	inv.Certificates.SubscriptionTLS = "acme-ip"
	return inv
}

func TestBootstrapHostsOrdersExitBeforeEntry(t *testing.T) {
	runner := &fakeRunner{}
	var out bytes.Buffer
	if err := BootstrapHosts(context.Background(), runner, validInventory(), &out); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"198.51.100.20:3XUI_PRODUCTION_CANDIDATE_READY",
		"198.51.100.20:3XUI_PRODUCTION_STAGED",
		"198.51.100.20:3XUI_PRODUCTION_FIREWALL_READY",
		"198.51.100.20:3XUI_PRODUCTION_ACTIVATED",
		"198.51.100.20:3XUI_PRODUCTION_ACME_READY",
		"203.0.113.10:3XUI_PRODUCTION_CANDIDATE_READY",
		"203.0.113.10:3XUI_PRODUCTION_STAGED",
		"203.0.113.10:3XUI_PRODUCTION_FIREWALL_READY",
		"203.0.113.10:3XUI_PRODUCTION_ACTIVATED",
		"203.0.113.10:3XUI_PRODUCTION_ACME_READY",
		"203.0.113.10:3XUI_PRODUCTION_SUBSCRIPTION_TLS_READY",
	}
	if strings.Join(runner.calls, "\n") != strings.Join(want, "\n") {
		t.Fatalf("unexpected call order:\n%s", strings.Join(runner.calls, "\n"))
	}
	if !strings.Contains(out.String(), "3XUI_PRODUCTION_HOST_BOOTSTRAP_READY") {
		t.Fatalf("missing completion marker: %s", out.String())
	}
}

func TestBootstrapHostsRollsBackBothNodesInReverseOrder(t *testing.T) {
	runner := &fakeRunner{failAt: "203.0.113.10:3XUI_PRODUCTION_ACME_READY"}
	err := BootstrapHosts(context.Background(), runner, validInventory(), &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "entry acme-ip") {
		t.Fatalf("unexpected error: %v", err)
	}
	got := strings.Join(runner.calls, "\n")
	wantTail := strings.Join([]string{
		"203.0.113.10:3XUI_PRODUCTION_INSTALL_ROLLED_BACK",
		"198.51.100.20:3XUI_PRODUCTION_INSTALL_ROLLED_BACK",
	}, "\n")
	if !strings.HasSuffix(got, wantTail) {
		t.Fatalf("rollback order is not entry then exit:\n%s", got)
	}
}

func TestBootstrapHostsDoesNotRollbackCandidateOnlyFailure(t *testing.T) {
	runner := &fakeRunner{failAt: "198.51.100.20:3XUI_PRODUCTION_CANDIDATE_READY"}
	err := BootstrapHosts(context.Background(), runner, validInventory(), &bytes.Buffer{})
	if err == nil {
		t.Fatal("expected candidate failure")
	}
	if len(runner.calls) != 1 {
		t.Fatalf("unexpected calls after candidate-only failure: %v", runner.calls)
	}
}

func TestBootstrapHostsRollsBackSuccessfulStageWithLostMarker(t *testing.T) {
	runner := &fakeRunner{omitAt: "198.51.100.20:3XUI_PRODUCTION_STAGED"}
	err := BootstrapHosts(context.Background(), runner, validInventory(), &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "returned no readiness marker") {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := runner.calls[len(runner.calls)-1]; got != "198.51.100.20:3XUI_PRODUCTION_INSTALL_ROLLED_BACK" {
		t.Fatalf("staged host was not rolled back: %v", runner.calls)
	}
}
