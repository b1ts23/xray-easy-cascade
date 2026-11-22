// SPDX-License-Identifier: GPL-3.0-only

package preflight

import (
	"strings"
	"testing"
)

const goodFacts = `schema	1
uid	0
os_id	ubuntu
os_version	24.04
arch	x86_64
kernel	6.8.0
pid1	systemd
systemd	yes
apt_get	yes
curl	yes
ss	yes
ipv4_default	yes
ipv6_global	yes
port_443	free
tcp_listeners	22,2053,8443
udp_listeners	443,10443
memory_kib	2097152
memory_limit_bytes	max
disk_available_kib	10485760
ufw	active
`

func TestParseAndAssessReady(t *testing.T) {
	facts, err := Parse(strings.NewReader(goodFacts))
	if err != nil {
		t.Fatal(err)
	}
	report := Assess("entry", "example.test", facts, false)
	if report.Status != StatusReady || len(report.Problems) != 0 {
		t.Fatalf("unexpected report: %#v", report)
	}
}

func TestAssessRequiredUDPPorts(t *testing.T) {
	facts, err := Parse(strings.NewReader(goodFacts))
	if err != nil {
		t.Fatal(err)
	}
	report := AssessRequiredUDPPorts(Assess("entry", "example.test", facts, false), []int{443, 9443})
	if report.Status != StatusBlocked || !strings.Contains(strings.Join(report.Problems, " "), "UDP/443") {
		t.Fatalf("unexpected UDP conflict report: %#v", report)
	}
}

func TestAssessRequiredPortsFindsEveryDeclaredConflict(t *testing.T) {
	facts, err := Parse(strings.NewReader(goodFacts))
	if err != nil {
		t.Fatal(err)
	}
	report := Assess("entry", "example.test", facts, false)
	report = AssessRequiredPorts(report, []int{443, 8443, 9443, 2053})
	if report.Status != StatusBlocked || len(report.Problems) != 2 {
		t.Fatalf("unexpected port conflict report: %#v", report)
	}
	joined := strings.Join(report.Problems, " ")
	for _, port := range []string{"TCP/8443", "TCP/2053"} {
		if !strings.Contains(joined, port) {
			t.Fatalf("missing %s conflict: %v", port, report.Problems)
		}
	}
}

func TestLabAllowsExpectedContainerLimits(t *testing.T) {
	raw := strings.ReplaceAll(goodFacts, "systemd\tyes", "systemd\tno")
	raw = strings.ReplaceAll(raw, "ipv6_global\tyes", "ipv6_global\tno")
	raw = strings.ReplaceAll(raw, "memory_limit_bytes\tmax", "memory_limit_bytes\t402653184")
	facts, err := Parse(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	report := Assess("entry", "127.0.0.1", facts, true)
	if report.Status != StatusLabReady || len(report.Warnings) < 3 {
		t.Fatalf("unexpected report: %#v", report)
	}
	if production := Assess("entry", "127.0.0.1", facts, false); production.Status != StatusBlocked {
		t.Fatalf("container must not pass production preflight: %#v", production)
	}
}

func TestParseRejectsDuplicateFact(t *testing.T) {
	_, err := Parse(strings.NewReader(goodFacts + "uid\t0\n"))
	if err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("unexpected error: %v", err)
	}
}
