// SPDX-License-Identifier: GPL-3.0-only

package preflight

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

const (
	StatusReady    = "READY"
	StatusLabReady = "LAB_READY"
	StatusBlocked  = "BLOCKED"
)

const Script = `set -u
emit() {
  key=$1
  value=$(printf '%s' "$2" | tr '\t\r\n' '   ')
  printf '%s\t%s\n' "$key" "$value"
}
os_id=unknown
os_version=unknown
if [ -r /etc/os-release ]; then
  . /etc/os-release
  os_id=${ID:-unknown}
  os_version=${VERSION_ID:-unknown}
fi
emit schema 1
emit uid "$(id -u)"
emit os_id "$os_id"
emit os_version "$os_version"
emit arch "$(uname -m)"
emit kernel "$(uname -r)"
emit pid1 "$(cat /proc/1/comm 2>/dev/null || echo unknown)"
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then emit systemd yes; else emit systemd no; fi
if command -v apt-get >/dev/null 2>&1; then emit apt_get yes; else emit apt_get no; fi
if command -v curl >/dev/null 2>&1; then emit curl yes; else emit curl no; fi
if command -v ss >/dev/null 2>&1; then emit ss yes; else emit ss no; fi
if ip -4 route show default 2>/dev/null | grep -q .; then emit ipv4_default yes; else emit ipv4_default no; fi
if ip -6 -o addr show scope global 2>/dev/null | grep -q .; then emit ipv6_global yes; else emit ipv6_global no; fi
if ss -H -ltn 2>/dev/null | awk '{print $4}' | grep -Eq '(^|\]|:|\.)443$'; then emit port_443 busy; else emit port_443 free; fi
emit tcp_listeners "$(ss -H -ltn 2>/dev/null | awk '{address=$4; sub(/^.*:/, "", address); if (address ~ /^[0-9]+$/) print address}' | sort -nu | paste -sd, -)"
emit udp_listeners "$(ss -H -lun 2>/dev/null | awk '{address=$5; if (address == "") address=$4; sub(/^.*:/, "", address); if (address ~ /^[0-9]+$/) print address}' | sort -nu | paste -sd, -)"
emit memory_kib "$(awk '/MemTotal:/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)"
memory_limit=max
if [ -r /sys/fs/cgroup/memory.max ]; then memory_limit=$(cat /sys/fs/cgroup/memory.max); fi
emit memory_limit_bytes "$memory_limit"
emit disk_available_kib "$(df -Pk / 2>/dev/null | awk 'NR==2 {print $4}')"
if command -v ufw >/dev/null 2>&1; then
  if ufw status 2>/dev/null | grep -qi '^Status: active'; then emit ufw active; else emit ufw inactive; fi
else
  emit ufw absent
fi
`

type Facts struct {
	Schema           int    `json:"schema"`
	UID              int    `json:"uid"`
	OSID             string `json:"os_id"`
	OSVersion        string `json:"os_version"`
	Arch             string `json:"arch"`
	Kernel           string `json:"kernel"`
	PID1             string `json:"pid1"`
	Systemd          string `json:"systemd"`
	APTGet           string `json:"apt_get"`
	Curl             string `json:"curl"`
	SS               string `json:"ss"`
	IPv4Default      string `json:"ipv4_default"`
	IPv6Global       string `json:"ipv6_global"`
	Port443          string `json:"port_443"`
	TCPListeners     []int  `json:"tcp_listeners"`
	UDPListeners     []int  `json:"udp_listeners"`
	MemoryKiB        int64  `json:"memory_kib"`
	MemoryLimitBytes string `json:"memory_limit_bytes"`
	DiskAvailableKiB int64  `json:"disk_available_kib"`
	UFW              string `json:"ufw"`
}

type Report struct {
	Role     string   `json:"role"`
	Host     string   `json:"host"`
	Status   string   `json:"status"`
	Facts    Facts    `json:"facts"`
	Warnings []string `json:"warnings,omitempty"`
	Problems []string `json:"problems,omitempty"`
}

func Parse(reader io.Reader) (Facts, error) {
	values := make(map[string]string)
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		key, value, ok := strings.Cut(scanner.Text(), "\t")
		if !ok || key == "" {
			return Facts{}, fmt.Errorf("invalid fact line %q", scanner.Text())
		}
		if _, duplicate := values[key]; duplicate {
			return Facts{}, fmt.Errorf("duplicate fact %q", key)
		}
		values[key] = value
	}
	if err := scanner.Err(); err != nil {
		return Facts{}, fmt.Errorf("read facts: %w", err)
	}
	integer := func(key string) (int64, error) {
		value, ok := values[key]
		if !ok {
			return 0, fmt.Errorf("missing fact %q", key)
		}
		parsed, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("invalid integer fact %q", key)
		}
		return parsed, nil
	}
	required := func(key string) (string, error) {
		value, ok := values[key]
		if !ok || value == "" {
			return "", fmt.Errorf("missing fact %q", key)
		}
		return value, nil
	}

	schema, err := integer("schema")
	if err != nil || schema != 1 {
		return Facts{}, errors.New("unsupported or missing preflight schema")
	}
	uid, err := integer("uid")
	if err != nil {
		return Facts{}, err
	}
	memory, err := integer("memory_kib")
	if err != nil {
		return Facts{}, err
	}
	disk, err := integer("disk_available_kib")
	if err != nil {
		return Facts{}, err
	}
	get := func(key string) string { return values[key] }
	parsePorts := func(key string) ([]int, error) {
		var ports []int
		raw := strings.TrimSpace(get(key))
		if raw == "" {
			return ports, nil
		}
		for _, item := range strings.Split(raw, ",") {
			port, parseErr := strconv.Atoi(item)
			if parseErr != nil || port < 1 || port > 65535 {
				return nil, fmt.Errorf("invalid %s fact", key)
			}
			ports = append(ports, port)
		}
		return ports, nil
	}
	tcpListeners, err := parsePorts("tcp_listeners")
	if err != nil {
		return Facts{}, err
	}
	udpListeners, err := parsePorts("udp_listeners")
	if err != nil {
		return Facts{}, err
	}
	for _, key := range []string{"os_id", "os_version", "arch", "kernel", "pid1", "systemd", "apt_get", "curl", "ss", "ipv4_default", "ipv6_global", "port_443", "memory_limit_bytes", "ufw"} {
		if _, err := required(key); err != nil {
			return Facts{}, err
		}
	}
	return Facts{
		Schema: int(schema), UID: int(uid), OSID: get("os_id"), OSVersion: get("os_version"),
		Arch: get("arch"), Kernel: get("kernel"), PID1: get("pid1"), Systemd: get("systemd"),
		APTGet: get("apt_get"), Curl: get("curl"), SS: get("ss"), IPv4Default: get("ipv4_default"),
		IPv6Global: get("ipv6_global"), Port443: get("port_443"), TCPListeners: tcpListeners, UDPListeners: udpListeners, MemoryKiB: memory,
		MemoryLimitBytes: get("memory_limit_bytes"), DiskAvailableKiB: disk, UFW: get("ufw"),
	}, nil
}

func Assess(role, host string, facts Facts, labMode bool) Report {
	report := Report{Role: role, Host: host, Facts: facts}
	problem := func(message string) { report.Problems = append(report.Problems, message) }
	warn := func(message string) { report.Warnings = append(report.Warnings, message) }
	if facts.UID != 0 {
		problem("SSH session is not root; passwordless sudo support is not implemented yet")
	}
	if facts.OSID != "ubuntu" || facts.OSVersion != "24.04" {
		problem("first release requires Ubuntu 24.04")
	}
	if facts.Arch != "x86_64" && facts.Arch != "amd64" {
		problem("first release requires amd64/x86_64")
	}
	if facts.APTGet != "yes" || facts.Curl != "yes" || facts.SS != "yes" {
		problem("required base commands apt-get, curl and ss are not all available")
	}
	if facts.IPv4Default != "yes" {
		problem("no default IPv4 route detected")
	}
	if facts.Systemd != "yes" {
		if labMode {
			warn("systemd is absent; container lab cannot prove production service integration")
		} else {
			problem("systemd is required for production deployment")
		}
	}
	if facts.IPv6Global != "yes" {
		warn("global IPv6 is absent; IPv6 inter-server fallback will be disabled")
	}
	if facts.DiskAvailableKiB < 1024*1024 {
		problem("less than 1 GiB disk space is available")
	}
	if facts.MemoryLimitBytes != "max" {
		limit, err := strconv.ParseInt(facts.MemoryLimitBytes, 10, 64)
		if err != nil {
			problem("cannot parse cgroup memory limit")
		} else if limit < 512*1024*1024 {
			if labMode {
				warn("container memory limit is below the production minimum")
			} else {
				problem("memory limit is below 512 MiB")
			}
		}
	}
	if len(report.Problems) > 0 {
		report.Status = StatusBlocked
	} else if labMode {
		report.Status = StatusLabReady
	} else {
		report.Status = StatusReady
	}
	return report
}

// AssessRequiredPorts adds clean-host port conflicts after the generic host
// checks. Lab deploy intentionally skips it because idempotent runs inspect
// already managed listeners.
func AssessRequiredPorts(report Report, ports []int) Report {
	listening := make(map[int]bool, len(report.Facts.TCPListeners))
	for _, port := range report.Facts.TCPListeners {
		listening[port] = true
	}
	seen := map[int]bool{}
	for _, port := range ports {
		if port < 1 || port > 65535 || seen[port] {
			continue
		}
		seen[port] = true
		if listening[port] {
			report.Problems = append(report.Problems, fmt.Sprintf("TCP/%d is already listening", port))
		}
	}
	if len(report.Problems) > 0 {
		report.Status = StatusBlocked
	}
	return report
}

func AssessRequiredUDPPorts(report Report, ports []int) Report {
	listening := make(map[int]bool, len(report.Facts.UDPListeners))
	for _, port := range report.Facts.UDPListeners {
		listening[port] = true
	}
	seen := map[int]bool{}
	for _, port := range ports {
		if port < 1 || port > 65535 || seen[port] {
			continue
		}
		seen[port] = true
		if listening[port] {
			report.Problems = append(report.Problems, fmt.Sprintf("UDP/%d is already listening", port))
		}
	}
	if len(report.Problems) > 0 {
		report.Status = StatusBlocked
	}
	return report
}
