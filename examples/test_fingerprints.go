package main

import (
	"fmt"
	"log"

	"github.com/zetxtech/masktunnel/internal/fingerprint"
)

func main() {
	fmt.Println("🔍 Testing MaskTunnel Fingerprint Detection")
	fmt.Println("==========================================")

	testCases := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Safari/605.1.15",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
	}

	for i, userAgent := range testCases {
		fmt.Printf("\n%d. Testing User-Agent:\n", i+1)
		fmt.Printf("   %s\n", userAgent)

		// Parse browser info
		browserInfo, err := fingerprint.ParseUserAgent(userAgent)
		if err != nil {
			log.Printf("   ❌ Failed to parse: %v", err)
			continue
		}

		fmt.Printf("   📱 Detected: %s v%s (major: %d)\n",
			browserInfo.Name, browserInfo.Version, browserInfo.Major)

		// Get complete fingerprint
		fp, err := fingerprint.GetBrowserFingerprint(userAgent)
		if err != nil {
			log.Printf("   ❌ Failed to get fingerprint: %v", err)
			continue
		}

		fmt.Printf("   🎭 Browser: %s\n", fp.Browser)
		fmt.Printf("   🔐 TLS Profile: %s\n", fp.TLSProfile)
		fmt.Printf("   📡 HTTP/2 Fingerprint: %s\n", fp.HTTP2Fingerprint)
		fmt.Printf("   ✅ Success!\n")
	}

	fmt.Println("\n🎯 Supported Browsers:")
	browsers := fingerprint.GetSupportedBrowsers()
	for _, browser := range browsers {
		versions := fingerprint.GetSupportedVersions(browser)
		fmt.Printf("   • %s: %v\n", browser, versions)
	}

	fmt.Println("\n🎉 Fingerprint testing completed!")
}
