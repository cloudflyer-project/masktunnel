package masktunnel

import (
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

const (
	testChromeUA  = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36"
	testFirefoxUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0"
	testSafariUA  = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Safari/605.1.15"
)

var (
	ja4Pattern = regexp.MustCompile(`^t\d{2}[di]\d{2}\d{2}[0-9a-z]{2}_[0-9a-f]{12}_[0-9a-f]{12}$`)
	md5Pattern = regexp.MustCompile(`^[0-9a-f]{32}$`)
)

func mustFingerprintReport(t *testing.T, userAgent string) *FingerprintReport {
	t.Helper()
	report, err := GetFingerprintReport(userAgent)
	if err != nil {
		t.Fatalf("GetFingerprintReport(%q): %v", userAgent, err)
	}
	return report
}

func TestFingerprintReportChrome(t *testing.T) {
	report := mustFingerprintReport(t, testChromeUA)

	if report.Browser != "Chrome" || report.TLSProfile != "133" {
		t.Errorf("unexpected browser/profile: %s/%s", report.Browser, report.TLSProfile)
	}
	if report.UserAgent != testChromeUA {
		t.Errorf("report must echo the user agent")
	}

	segments := strings.Split(report.JA3, ",")
	if len(segments) != 5 {
		t.Fatalf("JA3 must have 5 comma-separated segments, got %q", report.JA3)
	}
	if _, err := strconv.Atoi(segments[0]); err != nil {
		t.Errorf("JA3 version segment must be numeric: %q", segments[0])
	}
	for _, segment := range segments[1:] {
		for _, part := range strings.Split(segment, "-") {
			value, err := strconv.ParseUint(part, 10, 16)
			if err != nil {
				t.Fatalf("invalid JA3 segment value %q in %q", part, report.JA3)
			}
			if isGREASE(uint16(value)) {
				t.Errorf("JA3 must exclude GREASE values, found %d in %q", value, report.JA3)
			}
		}
	}

	if !md5Pattern.MatchString(report.JA3Hash) || report.JA3Hash != md5Hex(report.JA3) {
		t.Errorf("JA3 hash must be the md5 of the JA3 text: %q", report.JA3Hash)
	}
	if !ja4Pattern.MatchString(report.JA4) {
		t.Errorf("JA4 must match the JA4 format: %q", report.JA4)
	}
	if !strings.HasPrefix(report.JA4, "t13d") {
		t.Errorf("Chrome JA4 must be TLS 1.3 with SNI: %q", report.JA4)
	}

	const chromeHTTP2 = "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"
	if report.AkamaiFingerprint != chromeHTTP2 {
		t.Errorf("unexpected Akamai fingerprint: %q", report.AkamaiFingerprint)
	}
	if report.AkamaiHash != md5Hex(report.AkamaiFingerprint) {
		t.Errorf("Akamai hash must be the md5 of the fingerprint: %q", report.AkamaiHash)
	}
}

func TestFingerprintReportBrowsersDiffer(t *testing.T) {
	reports := map[string]*FingerprintReport{
		"chrome":  mustFingerprintReport(t, testChromeUA),
		"firefox": mustFingerprintReport(t, testFirefoxUA),
		"safari":  mustFingerprintReport(t, testSafariUA),
	}

	seen := make(map[string]string)
	for name, report := range reports {
		if other, exists := seen[report.JA4]; exists {
			t.Errorf("JA4 collision between %s and %s: %s", other, name, report.JA4)
		}
		seen[report.JA4] = name
	}

	const firefoxHTTP2 = "1:65536;2:0;4:131072;5:16384|12517377|0|m,s,a,p"
	if reports["firefox"].AkamaiFingerprint != firefoxHTTP2 {
		t.Errorf("unexpected Firefox Akamai fingerprint: %q", reports["firefox"].AkamaiFingerprint)
	}
}

func TestFingerprintReportIsNormalizedStable(t *testing.T) {
	for _, userAgent := range []string{testChromeUA, testFirefoxUA, testSafariUA} {
		first := mustFingerprintReport(t, userAgent)
		second := mustFingerprintReport(t, userAgent)
		if first.JA4 != second.JA4 {
			t.Errorf("JA4 must be stable across calls: %s vs %s", first.JA4, second.JA4)
		}
	}

	// Firefox ships without shuffled extensions or GREASE values, so its
	// JA3 must be identical across builds.
	first := mustFingerprintReport(t, testFirefoxUA)
	second := mustFingerprintReport(t, testFirefoxUA)
	if first.JA3 != second.JA3 {
		t.Errorf("Firefox JA3 must be deterministic:\n  %s\n  %s", first.JA3, second.JA3)
	}
}

func TestFingerprintReportFallsBackToChrome(t *testing.T) {
	chrome := mustFingerprintReport(t, testChromeUA)

	// A User-Agent that parses to an unknown browser uses the Chrome preset
	// with the database HTTP/2 settings.
	unknown := mustFingerprintReport(t, "SomeBrowser/1.0 (Windows)")
	if unknown.Browser != "Chrome" {
		t.Errorf("unknown browsers must fall back to Chrome, got %s", unknown.Browser)
	}
	if unknown.JA4 != chrome.JA4 {
		t.Errorf("unknown browsers must use the Chrome TLS preset: %s vs %s", unknown.JA4, chrome.JA4)
	}
	const chromeHTTP2 = "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"
	if unknown.AkamaiFingerprint != chromeHTTP2 {
		t.Errorf("unexpected Akamai fingerprint for unknown browser: %q", unknown.AkamaiFingerprint)
	}

	// A completely unparseable User-Agent uses the same Chrome preset with
	// the fallback HTTP/2 settings from Manager.createSession.
	empty := mustFingerprintReport(t, "")
	if empty.Browser != "Chrome" {
		t.Errorf("unparseable User-Agents must fall back to Chrome, got %s", empty.Browser)
	}
	if empty.JA4 != chrome.JA4 {
		t.Errorf("fallback must use the Chrome TLS preset: %s vs %s", empty.JA4, chrome.JA4)
	}
	const fallbackHTTP2 = "1:65536;2:0;4:6291456;6:262144|15663105|0|m,s,a,p"
	if empty.AkamaiFingerprint != fallbackHTTP2 {
		t.Errorf("unexpected fallback Akamai fingerprint: %q", empty.AkamaiFingerprint)
	}
}

func TestGetFingerprintReportJSON(t *testing.T) {
	encoded, err := GetFingerprintReportJSON(testChromeUA)
	if err != nil {
		t.Fatalf("GetFingerprintReportJSON: %v", err)
	}

	var decoded FingerprintReport
	if err := json.Unmarshal([]byte(encoded), &decoded); err != nil {
		t.Fatalf("failed to decode report JSON: %v", err)
	}

	direct := mustFingerprintReport(t, testChromeUA)
	if decoded.JA4 != direct.JA4 {
		t.Errorf("JA4 mismatch between JSON and direct report: %s vs %s", decoded.JA4, direct.JA4)
	}
	if decoded.AkamaiFingerprint != direct.AkamaiFingerprint {
		t.Errorf("Akamai mismatch between JSON and direct report")
	}
	if decoded.JA3Hash != md5Hex(decoded.JA3) {
		t.Errorf("decoded JA3 hash must match the decoded JA3 text")
	}
}
