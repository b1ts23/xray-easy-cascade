// SPDX-License-Identifier: GPL-3.0-only

package routing

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

const (
	RoscomVPNCommit         = "bbc59bc58d44f7b39d63ea78cc14f04b87c302a2"
	RoscomVPNDeeplinkSHA256 = "47f637abe2091d64091f7e9b5c6cbac5caf2478a51a779410f2409a99ffe57e0"
	RoscomVPNJSONSHA256     = "c5edd1adbd9cea81f1265724ab24b4aa7acf7044b9e13534d9af88927f5c0091"
	RoscomVPNDeeplinkURL    = "https://raw.githubusercontent.com/hydraponique/roscomvpn-routing/" + RoscomVPNCommit + "/HAPP/DEFAULT.DEEPLINK"
	RoscomVPNGeoIPURL       = "https://cdn.jsdelivr.net/gh/hydraponique/roscomvpn-geoip@202611201128/release/geoip.dat"
	RoscomVPNGeoIPSHA256    = "97b323419502b2793e978e92902bbf4a84eb5513cc4f43058c66875d3365b956"
	RoscomVPNGeoSiteURL     = "https://cdn.jsdelivr.net/gh/hydraponique/roscomvpn-geosite@202610120948/release/geosite.dat"
	RoscomVPNGeoSiteSHA256  = "95f15c43e6f3356c51e14a444bc9d99a5e4810640070089b7ba46b31d6cdf001"
)

type HappProfile struct {
	Name           string `json:"Name"`
	GlobalProxy    string `json:"GlobalProxy"`
	GeoIPURL       string `json:"Geoipurl"`
	GeoSiteURL     string `json:"Geositeurl"`
	RouteOrder     string `json:"RouteOrder"`
	DomainStrategy string `json:"DomainStrategy"`
}

// AdaptRoscomVPNForCascade keeps RoscomVPN's pinned data sources and blocking
// policy, but prevents public destinations from bypassing the VPN on the
// client. Public traffic must reach entry, where the server-side policy can
// choose entry/direct or cascade-exit. Only private ranges stay client-direct.
func AdaptRoscomVPNForCascade(raw []byte) (string, string, error) {
	if _, err := VerifyRoscomVPNDeeplink(raw); err != nil {
		return "", "", err
	}
	const prefix = "happ://routing/onadd/"
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(strings.TrimSpace(string(raw)), prefix))
	if err != nil {
		return "", "", fmt.Errorf("decode verified HAPP deeplink: %w", err)
	}
	return adaptRoscomVPNJSONForCascade(decoded)
}

func adaptRoscomVPNJSONForCascade(decoded []byte) (string, string, error) {
	const prefix = "happ://routing/onadd/"
	var profile map[string]any
	if err := json.Unmarshal(decoded, &profile); err != nil {
		return "", "", fmt.Errorf("decode verified HAPP routing JSON: %w", err)
	}
	profile["Name"] = "RoscomVPN Cascade"
	profile["DirectSites"] = []string{"geosite:private"}
	profile["DirectIp"] = []string{"geoip:private"}
	adaptedJSON, err := json.Marshal(profile)
	if err != nil {
		return "", "", fmt.Errorf("encode cascade HAPP routing JSON: %w", err)
	}
	adapted := prefix + base64.StdEncoding.EncodeToString(adaptedJSON)
	sum := sha256.Sum256([]byte(adapted + "\n"))
	return adapted, hex.EncodeToString(sum[:]), nil
}

func VerifyRoscomVPNDeeplink(raw []byte) (HappProfile, error) {
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != RoscomVPNDeeplinkSHA256 {
		return HappProfile{}, errors.New("RoscomVPN DEFAULT.DEEPLINK checksum mismatch")
	}
	return ParseHappDeeplink(string(raw))
}

func ParseHappDeeplink(raw string) (HappProfile, error) {
	const prefix = "happ://routing/onadd/"
	raw = strings.TrimSpace(raw)
	if !strings.HasPrefix(raw, prefix) {
		return HappProfile{}, errors.New("routing asset is not a HAPP onadd deeplink")
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(raw, prefix))
	if err != nil {
		return HappProfile{}, fmt.Errorf("decode HAPP deeplink: %w", err)
	}
	var profile HappProfile
	if err := json.Unmarshal(decoded, &profile); err != nil {
		return HappProfile{}, fmt.Errorf("decode HAPP routing JSON: %w", err)
	}
	if profile.Name != "RoscomVPN" || profile.GlobalProxy != "true" || profile.RouteOrder != "block-proxy-direct" || profile.DomainStrategy != "IPIfNonMatch" {
		return HappProfile{}, errors.New("unexpected RoscomVPN DEFAULT profile invariants")
	}
	for label, value := range map[string]string{"GeoIP": profile.GeoIPURL, "GeoSite": profile.GeoSiteURL} {
		parsed, err := url.Parse(value)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" || !strings.Contains(value, "@") {
			return HappProfile{}, fmt.Errorf("%s asset URL is not pinned HTTPS", label)
		}
	}
	return profile, nil
}
