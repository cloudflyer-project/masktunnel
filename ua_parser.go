package masktunnel

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/mileusna/useragent"
)

// BrowserInfo contains browser information
type BrowserInfo struct {
	Name    string
	Version string
	Major   int
}

// HTTP2Fingerprint contains HTTP/2 fingerprint configuration
type HTTP2Fingerprint struct {
	Settings     string
	WindowUpdate string
	Priority     string
	PseudoHeader string
}

// BrowserFingerprint contains complete browser fingerprint
type BrowserFingerprint struct {
	Browser          string
	HTTP2Fingerprint string
	TLSProfile       string
}

// utls version mapping
var utlsDict = map[string]map[int]string{
	"Firefox": {
		-1:  "120", // default to latest supported
		55:  "55",
		56:  "56",
		63:  "63",
		65:  "65",
		99:  "99",
		102: "102",
		105: "105",
		120: "120",
	},
	"Chrome": {
		-1:  "133", // default to latest supported
		58:  "58",
		62:  "62",
		70:  "70",
		72:  "72",
		83:  "83",
		87:  "87",
		96:  "96",
		100: "100",
		102: "102",
		106: "106",
		112: "112_PSK",
		114: "114_PSK",
		115: "115_PQ",
		120: "120",
		131: "131",
		133: "133",
	},
	"iOS": {
		-1: "14",  // default to latest supported
		11: "111", // legacy "111" means 11.1
		12: "12.1",
		13: "13",
		14: "14",
	},
	"Android": {
		-1: "11",
	},
	"Edge": {
		-1: "85",
		85: "85",
	},
	"Safari": {
		-1: "16.0",
	},
}

// HTTP/2 fingerprint database
var http2Fingerprints = map[string]HTTP2Fingerprint{
	"Chrome": {
		Settings:     "1:65536,2:0,4:6291456,6:262144",
		WindowUpdate: "15663105",
		Priority:     "0",
		PseudoHeader: "m,a,s,p",
	},
	"Firefox": {
		Settings:     "1:65536,2:0,4:131072,5:16384",
		WindowUpdate: "12517377",
		Priority:     "0",
		PseudoHeader: "m,s,a,p",
	},
	"Safari": {
		Settings:     "2:0,3:100,4:2097152,8:1,9:1",
		WindowUpdate: "10420225",
		Priority:     "0",
		PseudoHeader: "m,s,a,p",
	},
	"Edge": {
		Settings:     "1:65536,2:0,4:6291456,6:262144",
		WindowUpdate: "15663105",
		Priority:     "0",
		PseudoHeader: "m,s,a,p",
	},
}

// ParseUserAgent parses User-Agent string
func ParseUserAgent(userAgent string) (*BrowserInfo, error) {
	ua := useragent.Parse(userAgent)

	if ua.Name == "" {
		return nil, fmt.Errorf("failed to parse User-Agent: %s", userAgent)
	}

	// Extract major version number
	majorVersionStr := strings.Split(ua.Version, ".")[0]
	majorVersion, err := strconv.Atoi(majorVersionStr)
	if err != nil {
		majorVersion = -1 // use default version
	}

	return &BrowserInfo{
		Name:    ua.Name,
		Version: ua.Version,
		Major:   majorVersion,
	}, nil
}

// GetBrowserFingerprint gets complete browser fingerprint from User-Agent
func GetBrowserFingerprint(userAgent string) (*BrowserFingerprint, error) {
	browserInfo, err := ParseUserAgent(userAgent)
	if err != nil {
		return nil, err
	}

	// Get UTLS version
	utlsVersion, err := getUTLSVersion(browserInfo.Name, browserInfo.Major)
	if err != nil {
		// If unrecognized, default to Chrome
		browserInfo.Name = "Chrome"
		utlsVersion = "133"
	}

	// Get HTTP/2 fingerprint
	http2fp := getHTTP2Fingerprint(browserInfo.Name)
	http2FingerprintStr := fmt.Sprintf("%s|%s|%s|%s",
		http2fp.Settings,
		http2fp.WindowUpdate,
		http2fp.Priority,
		http2fp.PseudoHeader)

	return &BrowserFingerprint{
		Browser:          browserInfo.Name,
		HTTP2Fingerprint: http2FingerprintStr,
		TLSProfile:       utlsVersion,
	}, nil
}

// getUTLSVersion gets corresponding UTLS version
func getUTLSVersion(browserName string, majorVersion int) (string, error) {
	versions, ok := utlsDict[browserName]
	if !ok {
		return "", fmt.Errorf("unsupported browser: %s", browserName)
	}

	// Find the highest version that is less than or equal to current version
	selectedVersion := -1
	for version := range versions {
		if version <= majorVersion && version > selectedVersion {
			selectedVersion = version
		}
	}

	if utls, ok := versions[selectedVersion]; ok {
		return utls, nil
	}

	return "", fmt.Errorf("no UTLS value found for browser '%s' with version '%d'", browserName, majorVersion)
}

// getHTTP2Fingerprint gets corresponding HTTP/2 fingerprint
func getHTTP2Fingerprint(browserName string) HTTP2Fingerprint {
	if fp, ok := http2Fingerprints[browserName]; ok {
		return fp
	}

	// Default to Chrome fingerprint
	return http2Fingerprints["Chrome"]
}

// GetSupportedBrowsers returns list of supported browsers
func GetSupportedBrowsers() []string {
	browsers := make([]string, 0, len(utlsDict))
	for browser := range utlsDict {
		browsers = append(browsers, browser)
	}
	return browsers
}

// GetSupportedVersions returns list of supported versions for specified browser
func GetSupportedVersions(browserName string) []int {
	if versions, ok := utlsDict[browserName]; ok {
		versionList := make([]int, 0, len(versions))
		for version := range versions {
			if version != -1 { // exclude default version
				versionList = append(versionList, version)
			}
		}
		return versionList
	}
	return nil
}
