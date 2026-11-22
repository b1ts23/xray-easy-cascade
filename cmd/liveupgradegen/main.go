// SPDX-License-Identifier: GPL-3.0-only

// Command liveupgradegen renders non-public scripts for isolated rehearsals.
package main

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/b1ts23/xray-easy-cascade/internal/deploylab"
	"github.com/b1ts23/xray-easy-cascade/internal/inventory"
	"github.com/b1ts23/xray-easy-cascade/internal/liveupgrade"
)

func main() {
	if len(os.Args) < 2 || len(os.Args) > 3 {
		fmt.Fprintln(os.Stderr, "usage: liveupgradegen <apply|launcher|launcher-failure|reference-verify-lab|reference-verify|reference-launcher|xhttp-apply-lab|xhttp-launcher-lab|xhttp-launcher-failure-lab|hysteria-apply-lab|hysteria-verify-lab|hysteria-launcher-lab|hysteria-launcher-failure-lab|reference-xhttp-apply|reference-xhttp-verify|reference-xhttp-launcher|reference-hysteria-apply|reference-hysteria-verify|reference-hysteria-launcher|commit|status> [transaction-id]")
		os.Exit(2)
	}
	options := liveupgrade.Options{
		Scheme: "http", Port: 2053, BasePath: "/entry/panel/",
		IPv4OutboundTag: "cascade-exit-ipv4", IPv6OutboundTag: "cascade-exit-ipv6",
		BalancerTag: "cascade-exit", ClientInboundTag: "in-client-entry", ObservatoryInterval: "2s",
		RequireOperatorCommit: true,
	}
	var script string
	var err error
	switch os.Args[1] {
	case "apply":
		script, err = liveupgrade.ApplyScript(options)
	case "reference-verify-lab":
		script, err = liveupgrade.ReferenceVerifyScript(options, liveupgrade.ReferenceVerifyOptions{
			InboundTag: "in-client-entry", ClientPort: 10443, SubscriptionPort: 2096,
			EntryAddress:     "127.0.0.1",
			ExpectedExitIPv4: "192.0.2.30",
			ExpectedExitIPv6: "2001:db8:3::30",
		})
	case "launcher", "launcher-failure":
		if len(os.Args) != 3 {
			err = fmt.Errorf("launcher requires transaction ID")
			break
		}
		inv := inventory.Default()
		inv.Entry.CascadeAddress = "172.29.10.10"
		inv.Exit.CascadeAddress = "172.29.10.11"
		inv.Entry.PublicIPv6 = "fd29:10::10"
		inv.Exit.PublicIPv6 = "fd29:10::11"
		inv.Transport.ClientPort = 10443
		inv.Transport.InterserverPort = 11443
		inv.Subscription.HappRouting = "disabled"
		inv.Certificates.SubscriptionTLS = "existing"
		verify, buildErr := deploylab.E2EScript(inv, "")
		if buildErr != nil {
			err = buildErr
			break
		}
		script, err = liveupgrade.LauncherScript(options, os.Args[2], verify, os.Args[1] == "launcher-failure")
	case "reference-launcher":
		if len(os.Args) != 3 {
			err = fmt.Errorf("reference-launcher requires transaction ID")
			break
		}
		options, err = referenceOptions(os.Getenv("XRAY_CASCADE_REFERENCE_PANEL_URL"))
		if err != nil {
			break
		}
		verify, buildErr := liveupgrade.ReferenceVerifyScript(options, liveupgrade.ReferenceVerifyOptions{
			InboundTag: "in-443-tcp", ClientPort: 443, SubscriptionPort: 2096,
			EntryAddress:     "203.0.113.10",
			ExpectedExitIPv4: "198.51.100.20",
			ExpectedExitIPv6: "2001:db8:2::20",
		})
		if buildErr != nil {
			err = buildErr
			break
		}
		script, err = liveupgrade.LauncherScript(options, os.Args[2], verify, false)
	case "reference-verify":
		options, err = referenceOptions(os.Getenv("XRAY_CASCADE_REFERENCE_PANEL_URL"))
		if err != nil {
			break
		}
		script, err = liveupgrade.ReferenceVerifyScript(options, liveupgrade.ReferenceVerifyOptions{
			InboundTag: "in-443-tcp", ClientPort: 443, SubscriptionPort: 2096,
			EntryAddress: "203.0.113.10", ExpectedExitIPv4: "198.51.100.20", ExpectedExitIPv6: "2001:db8:2::20",
		})
	case "xhttp-apply-lab", "xhttp-launcher-lab", "xhttp-launcher-failure-lab":
		transport := labXHTTPOptions()
		apply, buildErr := liveupgrade.XHTTPApplyScript(options, transport)
		if buildErr != nil {
			err = buildErr
			break
		}
		if os.Args[1] == "xhttp-apply-lab" {
			script = apply
			break
		}
		if len(os.Args) != 3 {
			err = fmt.Errorf("XHTTP lab launcher requires transaction ID")
			break
		}
		verify, buildErr := liveupgrade.XHTTPVerifyScript(options, liveupgrade.XHTTPVerifyOptions{
			Transport: transport, SubscriptionPort: 2096,
			ExpectedExitIPv4: "192.0.2.30", ExpectedExitIPv6: "2001:db8:3::30",
		})
		if buildErr != nil {
			err = buildErr
			break
		}
		script, err = liveupgrade.LauncherWithApplyScript(options, os.Args[2], apply, verify, os.Args[1] == "xhttp-launcher-failure-lab")
	case "reference-xhttp-apply", "reference-xhttp-verify", "reference-xhttp-launcher":
		options, err = referenceOptions(os.Getenv("XRAY_CASCADE_REFERENCE_PANEL_URL"))
		if err != nil {
			break
		}
		transport := referenceXHTTPOptions()
		apply, buildErr := liveupgrade.XHTTPApplyScript(options, transport)
		if buildErr != nil {
			err = buildErr
			break
		}
		if os.Args[1] == "reference-xhttp-apply" {
			script = apply
			break
		}
		xhttpVerify, buildErr := liveupgrade.XHTTPVerifyScript(options, liveupgrade.XHTTPVerifyOptions{
			Transport: transport, SubscriptionPort: 2096,
			ExpectedExitIPv4: "198.51.100.20", ExpectedExitIPv6: "2001:db8:2::20",
		})
		if buildErr != nil {
			err = buildErr
			break
		}
		if os.Args[1] == "reference-xhttp-verify" {
			script = xhttpVerify
			break
		}
		if len(os.Args) != 3 {
			err = fmt.Errorf("reference XHTTP launcher requires transaction ID")
			break
		}
		primaryVerify, buildErr := liveupgrade.ReferenceVerifyScript(options, liveupgrade.ReferenceVerifyOptions{
			InboundTag: "in-443-tcp", ClientPort: 443, SubscriptionPort: 2096,
			EntryAddress: "203.0.113.10", ExpectedExitIPv4: "198.51.100.20", ExpectedExitIPv6: "2001:db8:2::20",
		})
		if buildErr != nil {
			err = buildErr
			break
		}
		verify := sequenceScripts(primaryVerify, xhttpVerify)
		script, err = liveupgrade.LauncherWithApplyScript(options, os.Args[2], apply, verify, false)
	case "hysteria-apply-lab", "hysteria-verify-lab", "hysteria-launcher-lab", "hysteria-launcher-failure-lab":
		transport := labHysteriaOptions()
		apply, buildErr := liveupgrade.HysteriaApplyScript(options, transport)
		if buildErr != nil {
			err = buildErr
			break
		}
		if os.Args[1] == "hysteria-apply-lab" {
			script = apply
			break
		}
		verify, buildErr := liveupgrade.HysteriaVerifyScript(options, liveupgrade.HysteriaVerifyOptions{
			Transport: transport, SubscriptionPort: 2096,
			ExpectedExitIPv4: os.Getenv("XRAY_CASCADE_LAB_EXPECTED_EXIT_IPV4"),
			ExpectedExitIPv6: "2001:db8:3::30",
		})
		if buildErr != nil {
			err = buildErr
			break
		}
		if os.Args[1] == "hysteria-verify-lab" {
			script = verify
			break
		}
		if len(os.Args) != 3 {
			err = fmt.Errorf("Hysteria lab launcher requires transaction ID")
			break
		}
		script, err = liveupgrade.LauncherWithApplyScript(options, os.Args[2], apply, verify, os.Args[1] == "hysteria-launcher-failure-lab")
	case "reference-hysteria-apply", "reference-hysteria-verify", "reference-hysteria-launcher":
		entryAddress := os.Getenv("XRAY_CASCADE_REFERENCE_ENTRY_IP")
		options, err = referenceOptionsForAddress(os.Getenv("XRAY_CASCADE_REFERENCE_PANEL_URL"), entryAddress)
		if err != nil {
			break
		}
		options.RollbackAfter = "15m"
		transport := referenceHysteriaOptions(entryAddress)
		apply, buildErr := liveupgrade.HysteriaApplyScript(options, transport)
		if buildErr != nil {
			err = buildErr
			break
		}
		if os.Args[1] == "reference-hysteria-apply" {
			script = apply
			break
		}
		verify, buildErr := liveupgrade.HysteriaVerifyScript(options, liveupgrade.HysteriaVerifyOptions{
			Transport: transport, SubscriptionPort: 2096,
			ExpectedExitIPv4: os.Getenv("XRAY_CASCADE_REFERENCE_EXIT_IPV4"),
			ExpectedExitIPv6: os.Getenv("XRAY_CASCADE_REFERENCE_EXIT_IPV6"),
		})
		if buildErr != nil {
			err = buildErr
			break
		}
		if os.Args[1] == "reference-hysteria-verify" {
			script = verify
			break
		}
		if len(os.Args) != 3 {
			err = fmt.Errorf("reference Hysteria launcher requires transaction ID")
			break
		}
		script, err = liveupgrade.LauncherWithApplyScript(options, os.Args[2], apply, verify, false)
	case "commit":
		if len(os.Args) != 3 {
			err = fmt.Errorf("commit requires transaction ID")
			break
		}
		script, err = liveupgrade.CommitScript(os.Args[2])
	case "status":
		if len(os.Args) != 3 {
			err = fmt.Errorf("status requires transaction ID")
			break
		}
		script, err = liveupgrade.StatusScript(os.Args[2])
	default:
		err = fmt.Errorf("unknown step %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if !strings.HasSuffix(script, "\n") {
		script += "\n"
	}
	fmt.Print(script)
}

func labXHTTPOptions() liveupgrade.XHTTPOptions {
	return liveupgrade.XHTTPOptions{
		PrimaryInboundTag: "in-client-entry", PrimaryPort: 10443,
		InboundTag: "in-client-entry-xhttp-adopt", Remark: "lab-client-entry-xhttp-adopt",
		Port: 10447, EntryAddress: "172.29.10.10", BalancerTag: "cascade-exit", AllowPrivateEntry: true,
	}
}

func labHysteriaOptions() liveupgrade.HysteriaOptions {
	return liveupgrade.HysteriaOptions{
		PrimaryInboundTag: "in-client-entry", InboundTag: "in-client-entry-hysteria2-adopt", Remark: "lab-client-entry-hysteria2-adopt",
		Port: 10448, EntryAddress: "172.29.10.10", BalancerTag: "cascade-exit",
		CertificateFile: "/etc/x-ui/subscription.crt", KeyFile: "/etc/x-ui/subscription.key",
		PinCertificate: true, AllowPrivateEntry: true,
	}
}

func referenceXHTTPOptions() liveupgrade.XHTTPOptions {
	return liveupgrade.XHTTPOptions{
		PrimaryInboundTag: "in-443-tcp", PrimaryPort: 443,
		InboundTag: "in-client-xhttp", Remark: "entry-xhttp",
		Port: 8443, EntryAddress: "203.0.113.10", BalancerTag: "Balancer",
	}
}

func referenceHysteriaOptions(entryAddress string) liveupgrade.HysteriaOptions {
	return liveupgrade.HysteriaOptions{
		PrimaryInboundTag: "in-443-tcp", InboundTag: "in-client-hysteria2", Remark: "entry-hysteria2",
		Port: 443, EntryAddress: entryAddress, BalancerTag: "Balancer",
		CertificateFile: "/root/cert/ip/fullchain.pem", KeyFile: "/root/cert/ip/privkey.pem",
	}
}

func sequenceScripts(scripts ...string) string {
	var result strings.Builder
	result.WriteString("set -eu\n")
	for _, script := range scripts {
		result.WriteString("printf '%s' '")
		result.WriteString(base64.StdEncoding.EncodeToString([]byte(script)))
		result.WriteString("' | base64 -d | /bin/bash\n")
	}
	return result.String()
}

func referenceOptions(rawURL string) (liveupgrade.Options, error) {
	return referenceOptionsForAddress(rawURL, "203.0.113.10")
}

func referenceOptionsForAddress(rawURL, address string) (liveupgrade.Options, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() != address || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return liveupgrade.Options{}, fmt.Errorf("reference panel URL is missing or unsafe")
	}
	port, err := strconv.Atoi(parsed.Port())
	if err != nil || port < 1 || port > 65535 {
		return liveupgrade.Options{}, fmt.Errorf("reference panel URL requires an explicit valid port")
	}
	basePath := parsed.EscapedPath()
	if basePath == "" || strings.Contains(basePath, "%") {
		return liveupgrade.Options{}, fmt.Errorf("reference panel URL requires a plain base path")
	}
	if !strings.HasSuffix(basePath, "/") {
		basePath += "/"
	}
	if !strings.HasSuffix(basePath, "/panel/") {
		basePath += "panel/"
	}
	return liveupgrade.Options{
		Scheme: "https", Port: port, BasePath: basePath, CurlTLS: "-k",
		IPv4OutboundTag: "exit-ipv4", IPv6OutboundTag: "exit-ipv6",
		BalancerTag: "cascade-exit", ClientInboundTag: "in-client-tcp", ObservatoryInterval: "10s",
		RequireOperatorCommit: true,
	}, nil
}
