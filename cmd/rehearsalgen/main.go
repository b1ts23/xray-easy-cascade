// SPDX-License-Identifier: GPL-3.0-only

// Command rehearsalgen renders production scripts for the disposable CI
// systemd container. It is intentionally not part of the public vpnctl CLI.
package main

import (
	"fmt"
	"os"

	"github.com/b1ts23/xray-easy-cascade/internal/inventory"
	"github.com/b1ts23/xray-easy-cascade/internal/production"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: rehearsalgen <entry|exit> <candidate|stage|firewall|activate|acme|subscription|rollback>")
		os.Exit(2)
	}
	role, step := os.Args[1], os.Args[2]
	inv := inventory.Default()
	inv.Entry.Host = "203.0.113.10"
	inv.Exit.Host = "198.51.100.20"
	inv.Entry.PublicIPv6 = "disabled"
	inv.Exit.PublicIPv6 = "disabled"
	inv.Certificates.SubscriptionTLS = "acme-ip"
	inv.Transport.ClientReality.Target = "example.com:443"
	inv.Transport.ClientReality.ServerName = "example.com"
	inv.Transport.InterserverReality.Target = "example.net:443"
	inv.Transport.InterserverReality.ServerName = "example.net"
	var script string
	var err error
	switch step {
	case "candidate":
		script, err = production.CandidateScript(role)
	case "stage":
		script, err = production.StageInstallScript(role, inv)
	case "firewall":
		script, err = production.FirewallScript(role, inv)
	case "activate":
		script, err = production.ActivationScript(role, inv)
	case "acme":
		script, err = production.ACMEIPScript(role, inv)
	case "subscription":
		if role != "entry" {
			err = fmt.Errorf("subscription step is entry-only")
		} else {
			script, err = production.SubscriptionTLSScript(inv)
		}
	case "rollback":
		script, err = production.InstallRollbackScript(role)
	default:
		err = fmt.Errorf("unknown step %q", step)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Print(script)
}
