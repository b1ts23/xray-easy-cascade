// SPDX-License-Identifier: GPL-3.0-only

package inventory

import (
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

const SchemaVersion = 1

type Inventory struct {
	Schema       int          `yaml:"schema"`
	Cluster      Cluster      `yaml:"cluster"`
	Entry        Server       `yaml:"entry"`
	Exit         Server       `yaml:"exit"`
	Panel        Panel        `yaml:"panel"`
	Subscription Subscription `yaml:"subscription"`
	Certificates Certificates `yaml:"certificates"`
	Transport    Transport    `yaml:"transport"`
}

type Cluster struct {
	Name           string `yaml:"name"`
	RoutingProfile string `yaml:"routing_profile"`
}

type Server struct {
	Host            string `yaml:"host"`
	CascadeAddress  string `yaml:"cascade_address"`
	SSHUser         string `yaml:"ssh_user"`
	SSHPort         int    `yaml:"ssh_port"`
	SSHIdentityFile string `yaml:"ssh_identity_file"`
	PublicIPv6      string `yaml:"public_ipv6"`
}

type Panel struct {
	Access       string `yaml:"access"`
	PublicDomain string `yaml:"public_domain"`
	Port         int    `yaml:"port"`
}

type Subscription struct {
	PublicDomain string `yaml:"public_domain"`
	HappRouting  string `yaml:"happ_routing"`
	Port         int    `yaml:"port"`
}

type Certificates struct {
	NodeTransport        string `yaml:"node_transport"`
	PanelTLS             string `yaml:"panel_tls"`
	SubscriptionTLS      string `yaml:"subscription_tls"`
	PanelCertFile        string `yaml:"panel_cert_file"`
	PanelKeyFile         string `yaml:"panel_key_file"`
	SubscriptionCertFile string `yaml:"subscription_cert_file"`
	SubscriptionKeyFile  string `yaml:"subscription_key_file"`
}

type Transport struct {
	Client                  string                   `yaml:"client"`
	ClientPort              int                      `yaml:"client_port"`
	ClientAlternatives      []ClientAlternative      `yaml:"client_alternatives,omitempty"`
	Hysteria2               Hysteria2                `yaml:"hysteria2,omitempty"`
	Interserver             string                   `yaml:"interserver"`
	InterserverPort         int                      `yaml:"interserver_port"`
	InterserverAlternatives []InterserverAlternative `yaml:"interserver_alternatives,omitempty"`
	PreferInterserver       string                   `yaml:"prefer_interserver"`
	IPv6Fallback            string                   `yaml:"ipv6_fallback"`
	ClientReality           Reality                  `yaml:"client_reality"`
	InterserverReality      Reality                  `yaml:"interserver_reality"`
}

// Hysteria2 is an optional UDP+TLS client protocol. It is deliberately not a
// ClientAlternative: those entries are VLESS transports over TCP, while HY2
// has different certificate, firewall and preflight requirements.
type Hysteria2 struct {
	Enabled bool `yaml:"enabled"`
	Port    int  `yaml:"port"`
}

// ClientAlternative is an additional entry transport published under the
// same 3x-ui subscription identity as the primary client transport. Keeping
// the list typed makes later gRPC/Hysteria additions explicit instead of
// growing a set of loosely related port fields.
type ClientAlternative struct {
	Kind string `yaml:"kind"`
	Port int    `yaml:"port"`
}

// InterserverAlternative is an additional hidden entry-to-exit transport.
// It is never published to client subscriptions.
type InterserverAlternative struct {
	Kind string `yaml:"kind"`
	Port int    `yaml:"port"`
}

type Reality struct {
	Target     string `yaml:"target"`
	ServerName string `yaml:"server_name"`
}

func Default() Inventory {
	return Inventory{
		Schema: SchemaVersion,
		Cluster: Cluster{
			Name:           "my-cascade",
			RoutingProfile: "roscomvpn-default",
		},
		Entry:        Server{SSHUser: "root", SSHPort: 22, SSHIdentityFile: "~/.ssh/id_ed25519", PublicIPv6: "auto"},
		Exit:         Server{SSHUser: "root", SSHPort: 22, SSHIdentityFile: "~/.ssh/id_ed25519", PublicIPv6: "auto"},
		Panel:        Panel{Access: "ssh-tunnel", Port: 2053},
		Subscription: Subscription{HappRouting: "roscomvpn-default", Port: 2096},
		Certificates: Certificates{NodeTransport: "mtls", PanelTLS: "disabled", SubscriptionTLS: "pending"},
		Transport: Transport{
			Client:            "reality-vision-tcp",
			ClientPort:        443,
			Interserver:       "reality-vision-tcp",
			InterserverPort:   443,
			PreferInterserver: "ipv4",
			IPv6Fallback:      "auto",
		},
	}
}

func Load(path string) (Inventory, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Inventory{}, fmt.Errorf("read inventory: %w", err)
	}

	inv := Default()
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(&inv); err != nil {
		return Inventory{}, fmt.Errorf("parse inventory: %w", err)
	}
	if err := inv.Validate(); err != nil {
		return Inventory{}, err
	}
	return inv, nil
}

func Save(path string, inv Inventory) error {
	if err := inv.Validate(); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return errors.New("refusing to replace inventory through a symbolic link")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect inventory path: %w", err)
	}
	raw, err := yaml.Marshal(inv)
	if err != nil {
		return fmt.Errorf("encode inventory: %w", err)
	}

	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".inventory-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary inventory: %w", err)
	}
	tmpPath := tmp.Name()
	removeTemp := true
	defer func() {
		if removeTemp {
			_ = os.Remove(tmpPath)
		}
	}()

	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("protect temporary inventory: %w", err)
	}
	if _, err := io.Copy(tmp, strings.NewReader(string(raw))); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temporary inventory: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync temporary inventory: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temporary inventory: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("replace inventory atomically: %w", err)
	}
	removeTemp = false
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("protect inventory: %w", err)
	}
	return nil
}

func (inv Inventory) Validate() error {
	var problems []string
	if inv.Schema != SchemaVersion {
		problems = append(problems, fmt.Sprintf("schema must be %d", SchemaVersion))
	}
	if strings.TrimSpace(inv.Cluster.Name) == "" {
		problems = append(problems, "cluster.name is required")
	}
	if inv.Cluster.RoutingProfile != "roscomvpn-default" && inv.Cluster.RoutingProfile != "cascade-all" {
		problems = append(problems, "cluster.routing_profile must be roscomvpn-default or cascade-all")
	}
	validateServer := func(role string, server Server) {
		if strings.TrimSpace(server.Host) == "" {
			problems = append(problems, role+".host is required")
		}
		if strings.TrimSpace(server.SSHUser) == "" {
			problems = append(problems, role+".ssh_user is required")
		}
		if server.SSHPort < 1 || server.SSHPort > 65535 {
			problems = append(problems, role+".ssh_port must be between 1 and 65535")
		}
		if strings.TrimSpace(server.SSHIdentityFile) == "" {
			problems = append(problems, role+".ssh_identity_file is required")
		}
		if server.PublicIPv6 != "auto" && server.PublicIPv6 != "disabled" && strings.TrimSpace(server.PublicIPv6) == "" {
			problems = append(problems, role+".public_ipv6 must be auto, disabled, or an address")
		}
	}
	validateServer("entry", inv.Entry)
	validateServer("exit", inv.Exit)
	if inv.Entry.Host != "" && inv.Entry.Host == inv.Exit.Host && inv.Entry.SSHPort == inv.Exit.SSHPort {
		problems = append(problems, "entry and exit SSH endpoints must be different")
	}
	if inv.Panel.Access != "ssh-tunnel" && inv.Panel.Access != "public-https" {
		problems = append(problems, "panel.access must be ssh-tunnel or public-https")
	}
	if inv.Panel.Access == "public-https" && strings.TrimSpace(inv.Panel.PublicDomain) == "" {
		problems = append(problems, "panel.public_domain is required for public-https")
	}
	if inv.Panel.Port < 1 || inv.Panel.Port > 65535 {
		problems = append(problems, "panel.port must be between 1 and 65535")
	}
	if inv.Subscription.HappRouting != "roscomvpn-default" && inv.Subscription.HappRouting != "disabled" {
		problems = append(problems, "subscription.happ_routing must be roscomvpn-default or disabled")
	}
	if inv.Subscription.Port < 1 || inv.Subscription.Port > 65535 {
		problems = append(problems, "subscription.port must be between 1 and 65535")
	}
	if inv.Certificates.NodeTransport != "pin" && inv.Certificates.NodeTransport != "mtls" {
		problems = append(problems, "certificates.node_transport must be pin or mtls")
	}
	if inv.Certificates.PanelTLS != "disabled" && inv.Certificates.PanelTLS != "acme-domain" && inv.Certificates.PanelTLS != "existing" {
		problems = append(problems, "certificates.panel_tls must be disabled, acme-domain, or existing")
	}
	if inv.Panel.Access == "public-https" && inv.Certificates.PanelTLS == "disabled" {
		problems = append(problems, "certificates.panel_tls cannot be disabled for public-https panel access")
	}
	if inv.Certificates.PanelTLS == "existing" && (strings.TrimSpace(inv.Certificates.PanelCertFile) == "" || strings.TrimSpace(inv.Certificates.PanelKeyFile) == "") {
		problems = append(problems, "panel_cert_file and panel_key_file are required for existing panel TLS")
	}
	if inv.Certificates.SubscriptionTLS != "pending" && inv.Certificates.SubscriptionTLS != "acme-domain" && inv.Certificates.SubscriptionTLS != "acme-ip" && inv.Certificates.SubscriptionTLS != "existing" {
		problems = append(problems, "certificates.subscription_tls must be pending, acme-domain, acme-ip, or existing")
	}
	if inv.Certificates.SubscriptionTLS == "acme-domain" && strings.TrimSpace(inv.Subscription.PublicDomain) == "" {
		problems = append(problems, "subscription.public_domain is required for acme-domain subscription TLS")
	}
	if inv.Certificates.SubscriptionTLS == "acme-ip" {
		for role, host := range map[string]string{"entry": inv.Entry.Host, "exit": inv.Exit.Host} {
			address, err := netip.ParseAddr(strings.TrimSpace(host))
			if err != nil || !address.Is4() || !address.IsGlobalUnicast() || address.IsPrivate() {
				problems = append(problems, role+".host must be an explicit public IPv4 address for acme-ip")
			}
		}
	}
	if inv.Certificates.SubscriptionTLS == "existing" && (strings.TrimSpace(inv.Certificates.SubscriptionCertFile) == "" || strings.TrimSpace(inv.Certificates.SubscriptionKeyFile) == "") {
		problems = append(problems, "subscription_cert_file and subscription_key_file are required for existing subscription TLS")
	}
	if inv.Transport.Client != "reality-vision-tcp" {
		problems = append(problems, "transport.client must be reality-vision-tcp in the MVP")
	}
	if inv.Transport.Interserver != "reality-vision-tcp" {
		problems = append(problems, "transport.interserver must be reality-vision-tcp in the MVP")
	}
	if inv.Transport.ClientPort < 1 || inv.Transport.ClientPort > 65535 {
		problems = append(problems, "transport.client_port must be between 1 and 65535")
	}
	clientPorts := map[int]string{inv.Transport.ClientPort: "primary client transport"}
	alternativeKinds := map[string]bool{}
	for index, alternative := range inv.Transport.ClientAlternatives {
		field := fmt.Sprintf("transport.client_alternatives[%d]", index)
		if alternative.Kind != "reality-xhttp" {
			if alternative.Kind == "reality-xhttp-pq" || alternative.Kind == "reality-grpc" {
				problems = append(problems, field+".kind is experimental and cannot be enabled in the released profile")
			} else {
				problems = append(problems, field+".kind must be reality-xhttp in the released profile")
			}
		}
		if alternativeKinds[alternative.Kind] {
			problems = append(problems, field+".kind must be unique")
		}
		alternativeKinds[alternative.Kind] = true
		if alternative.Port < 1 || alternative.Port > 65535 {
			problems = append(problems, field+".port must be between 1 and 65535")
		} else if owner, exists := clientPorts[alternative.Port]; exists {
			problems = append(problems, fmt.Sprintf("%s.port conflicts with %s on port %d", field, owner, alternative.Port))
		} else {
			clientPorts[alternative.Port] = alternative.Kind
		}
	}
	if inv.Transport.Hysteria2.Enabled {
		problems = append(problems, "transport.hysteria2 is experimental and cannot be enabled in the released profile")
		if inv.Transport.Hysteria2.Port < 1 || inv.Transport.Hysteria2.Port > 65535 {
			problems = append(problems, "transport.hysteria2.port must be between 1 and 65535 when enabled")
		}
		if inv.Certificates.SubscriptionTLS != "existing" && inv.Certificates.SubscriptionTLS != "acme-ip" {
			problems = append(problems, "transport.hysteria2 requires subscription_tls existing or acme-ip")
		}
	}
	if inv.Transport.InterserverPort < 1 || inv.Transport.InterserverPort > 65535 {
		problems = append(problems, "transport.interserver_port must be between 1 and 65535")
	}
	interserverKinds := map[string]bool{}
	if len(inv.Transport.InterserverAlternatives) > 0 {
		problems = append(problems, "transport.interserver_alternatives is experimental and cannot be enabled in the released profile")
	}
	for index, alternative := range inv.Transport.InterserverAlternatives {
		field := fmt.Sprintf("transport.interserver_alternatives[%d]", index)
		if alternative.Kind != "reality-xhttp" {
			problems = append(problems, field+".kind must be reality-xhttp")
		}
		if interserverKinds[alternative.Kind] {
			problems = append(problems, field+".kind must be unique")
		}
		interserverKinds[alternative.Kind] = true
		if alternative.Port < 1 || alternative.Port > 65535 {
			problems = append(problems, field+".port must be between 1 and 65535")
		}
	}
	if inv.Transport.PreferInterserver != "ipv4" && inv.Transport.PreferInterserver != "lowest-latency" {
		problems = append(problems, "transport.prefer_interserver must be ipv4 or lowest-latency")
	}
	if inv.Transport.IPv6Fallback != "auto" && inv.Transport.IPv6Fallback != "disabled" && inv.Transport.IPv6Fallback != "required" {
		problems = append(problems, "transport.ipv6_fallback must be auto, disabled, or required")
	}
	checkNodePorts := func(role string, items map[string]int) {
		owners := map[int]string{}
		for name, port := range items {
			if port < 1 || port > 65535 {
				continue
			}
			if owner, exists := owners[port]; exists {
				problems = append(problems, fmt.Sprintf("%s port %d is assigned to both %s and %s", role, port, owner, name))
			} else {
				owners[port] = name
			}
		}
	}
	entryPorts := map[string]int{"ssh": inv.Entry.SSHPort, "panel": inv.Panel.Port, "subscription": inv.Subscription.Port, "primary-client": inv.Transport.ClientPort}
	for _, alternative := range inv.Transport.ClientAlternatives {
		entryPorts["client-"+alternative.Kind] = alternative.Port
	}
	exitPorts := map[string]int{"ssh": inv.Exit.SSHPort, "panel": inv.Panel.Port, "subscription": inv.Subscription.Port, "interserver": inv.Transport.InterserverPort}
	for _, alternative := range inv.Transport.InterserverAlternatives {
		exitPorts["interserver-"+alternative.Kind] = alternative.Port
	}
	if inv.Certificates.SubscriptionTLS == "acme-ip" {
		entryPorts["acme-http-01"] = 80
		exitPorts["acme-http-01"] = 80
	}
	checkNodePorts("entry", entryPorts)
	checkNodePorts("exit", exitPorts)
	if len(problems) > 0 {
		return errors.New("invalid inventory:\n- " + strings.Join(problems, "\n- "))
	}
	return nil
}

func (inv Inventory) InterserverAlternativePort(kind string) int {
	for _, alternative := range inv.Transport.InterserverAlternatives {
		if alternative.Kind == kind {
			return alternative.Port
		}
	}
	return 0
}

func (inv Inventory) ClientAlternativePort(kind string) int {
	for _, alternative := range inv.Transport.ClientAlternatives {
		if alternative.Kind == kind {
			return alternative.Port
		}
	}
	return 0
}
