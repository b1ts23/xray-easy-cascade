// SPDX-License-Identifier: GPL-3.0-only

package routing

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestParseHappDeeplink(t *testing.T) {
	payload := `{"Name":"RoscomVPN","GlobalProxy":"true","Geoipurl":"https://cdn.example/geoip@20261120/release/geoip.dat","Geositeurl":"https://cdn.example/geosite@20261120/release/geosite.dat","RouteOrder":"block-proxy-direct","DomainStrategy":"IPIfNonMatch"}`
	link := "happ://routing/onadd/" + base64.StdEncoding.EncodeToString([]byte(payload))
	profile, err := ParseHappDeeplink(link)
	if err != nil {
		t.Fatal(err)
	}
	if profile.Name != "RoscomVPN" {
		t.Fatalf("name=%q", profile.Name)
	}
}

func TestAdaptRoscomVPNForCascadeKeepsPublicTrafficInTunnel(t *testing.T) {
	payload := `{"Name":"RoscomVPN","GlobalProxy":"true","Geoipurl":"https://cdn.example/geoip@20261120/release/geoip.dat","Geositeurl":"https://cdn.example/geosite@20261120/release/geosite.dat","RouteOrder":"block-proxy-direct","DomainStrategy":"IPIfNonMatch","DirectSites":["geosite:private","geosite:category-ru"],"DirectIp":["geoip:private","geoip:direct"],"BlockSites":["geosite:category-ads"]}`
	link, checksum, err := adaptRoscomVPNJSONForCascade([]byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	if checksum == "" {
		t.Fatal("adapted checksum is empty")
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(link, "happ://routing/onadd/"))
	if err != nil {
		t.Fatal(err)
	}
	var profile map[string]any
	if err := json.Unmarshal(decoded, &profile); err != nil {
		t.Fatal(err)
	}
	if profile["Name"] != "RoscomVPN Cascade" {
		t.Fatalf("unexpected profile name: %#v", profile["Name"])
	}
	if got := profile["DirectSites"].([]any); len(got) != 1 || got[0] != "geosite:private" {
		t.Fatalf("unexpected client-direct domains: %#v", got)
	}
	if got := profile["DirectIp"].([]any); len(got) != 1 || got[0] != "geoip:private" {
		t.Fatalf("unexpected client-direct IPs: %#v", got)
	}
}

func TestParseHappDeeplinkRejectsUnpinnedAssets(t *testing.T) {
	payload := `{"Name":"RoscomVPN","GlobalProxy":"true","Geoipurl":"https://cdn.example/geoip.dat","Geositeurl":"http://cdn.example/geosite@main.dat","RouteOrder":"block-proxy-direct","DomainStrategy":"IPIfNonMatch"}`
	link := "happ://routing/onadd/" + base64.StdEncoding.EncodeToString([]byte(payload))
	if _, err := ParseHappDeeplink(link); err == nil {
		t.Fatal("unpinned routing assets were accepted")
	}
}
