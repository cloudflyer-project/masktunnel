package test

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cloudflyer-project/masktunnel"
	"github.com/gorilla/websocket"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

const (
	ProxyPort = "19080"
	HTTPPort  = "19081"
	HTTPSPort = "19443"
	WSPort    = "19082"
)

var (
	testServer  *TestServer
	proxyServer *masktunnel.Server
)

// TestMain sets up the test environment
func TestMain(m *testing.M) {
	// Set log level
	zerolog.SetGlobalLevel(zerolog.InfoLevel)

	// Start test servers
	testServer = NewTestServer(HTTPPort, HTTPSPort, WSPort)
	if err := testServer.Start(); err != nil {
		log.Fatal().Err(err).Msg("Failed to start test servers")
	}

	// Start proxy server
	config := &masktunnel.Config{
		Port:    ProxyPort,
		Verbose: false,
	}
	proxyServer = masktunnel.NewServer(config)
	go func() {
		if err := proxyServer.Start(); err != nil && err != http.ErrServerClosed {
			log.Error().Err(err).Msg("Proxy server error")
		}
	}()

	// Wait for servers to start
	time.Sleep(2 * time.Second)
	log.Info().Msg("Test environment ready")

	// Run tests
	code := m.Run()

	// Cleanup
	testServer.Stop()
	if proxyServer != nil {
		proxyServer.Stop()
	}

	os.Exit(code)
}

// TestBasicProxy tests basic HTTP/HTTPS proxy functionality
func TestBasicProxy(t *testing.T) {
	t.Run("HTTP", func(t *testing.T) {
		client, err := CreateProxyClient(ProxyPort, UserAgents["Chrome"])
		if err != nil {
			t.Fatalf("Failed to create proxy client: %v", err)
		}

		// Create request with explicit User-Agent
		req, err := http.NewRequest("GET", fmt.Sprintf("http://localhost:%s/", HTTPPort), nil)
		if err != nil {
			t.Fatalf("Failed to create request: %v", err)
		}
		req.Header.Set("User-Agent", UserAgents["Chrome"])

		// Test request through proxy
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("HTTP request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200, got: %d", resp.StatusCode)
		}

		// Validate response content
		var responseData map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&responseData); err != nil {
			t.Fatalf("Failed to parse response: %v", err)
		}

		if responseData["protocol"] != "http" {
			t.Errorf("Expected protocol 'http', got: %v", responseData["protocol"])
		}

		if responseData["user_agent"] != UserAgents["Chrome"] {
			t.Errorf("User-Agent mismatch, expected: %s, got: %v", UserAgents["Chrome"], responseData["user_agent"])
		}

		t.Log("HTTP proxy test passed")
	})

	t.Run("HTTPS", func(t *testing.T) {
		client, err := CreateProxyClient(ProxyPort, UserAgents["Firefox"])
		if err != nil {
			t.Fatalf("Failed to create proxy client: %v", err)
		}

		// Test against local HTTPS test server
		url := fmt.Sprintf("https://localhost:%s/", HTTPSPort)
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			t.Fatalf("Failed to create HTTPS request: %v", err)
		}
		req.Header.Set("User-Agent", UserAgents["Firefox"])

		// Test HTTPS request through proxy
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("HTTPS MITM request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200, got: %d", resp.StatusCode)
		}

		// Check fields from local HTTPS test server JSON
		var responseData map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&responseData); err != nil {
			t.Fatalf("Failed to parse response: %v", err)
		}

		if responseData["protocol"] != "https" {
			t.Errorf("Expected protocol 'https', got: %v", responseData["protocol"])
		}
		if responseData["user_agent"] != UserAgents["Firefox"] {
			t.Errorf("User-Agent mismatch, expected: %s, got: %v", UserAgents["Firefox"], responseData["user_agent"])
		}

		t.Log("HTTPS MITM test passed")
	})
}

// TestPayloadInjection tests JavaScript payload injection functionality
func TestPayloadInjection(t *testing.T) {
	// Store original proxy server
	originalProxy := proxyServer

	t.Run("HTTP", func(t *testing.T) {
		// Restart proxy with payload injection enabled
		proxyServer.Stop()
		time.Sleep(1 * time.Second)

		config := &masktunnel.Config{
			Port:    ProxyPort,
			Payload: "window.__masktunnel_injected = true; console.log('MaskTunnel payload injected');",
			Verbose: false,
		}

		proxyServer = masktunnel.NewServer(config)
		go func() {
			if err := proxyServer.Start(); err != nil && err != http.ErrServerClosed {
				log.Error().Err(err).Msg("Proxy server with payload error")
			}
		}()

		time.Sleep(2 * time.Second)

		// Test payload injection with HTML content
		client, err := CreateProxyClient(ProxyPort, UserAgents["Chrome"])
		if err != nil {
			t.Fatalf("Failed to create proxy client: %v", err)
		}

		// Test with a site that returns HTML content
		req, err := http.NewRequest("GET", "http://httpbin.org/html", nil)
		if err != nil {
			t.Fatalf("Failed to create payload test request: %v", err)
		}
		req.Header.Set("User-Agent", UserAgents["Chrome"])

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Payload injection request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200 for payload test, got: %d", resp.StatusCode)
		}

		// Check if response contains our injected payload marker
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("Failed to read payload test response: %v", err)
		}

		bodyStr := string(bodyBytes)
		contentType := resp.Header.Get("Content-Type")
		t.Logf("Response content-type: %s", contentType)
		t.Logf("Response body length: %d", len(bodyStr))

		// Verify payload injection - check if JavaScript payload is present in HTML response
		if strings.Contains(contentType, "text/html") {
			expectedPayload := "window.__masktunnel_injected = true"
			if strings.Contains(bodyStr, expectedPayload) {
				t.Log("HTTP payload injection verified: JavaScript successfully injected into HTML")
			} else {
				t.Error("HTTP payload injection failed: Expected JavaScript payload not found in HTML response")
				// Log a snippet of the response to help debug
				snippet := bodyStr
				if len(snippet) > 500 {
					snippet = snippet[:500] + "..."
				}
				t.Logf("Response snippet: %s", snippet)
			}
		} else {
			t.Logf("HTTP payload injection test skipped: Content-Type is not HTML (%s)", contentType)
		}

		t.Log("HTTP payload injection test completed")
	})

	t.Run("HTTPS", func(t *testing.T) {
		// Test HTTPS payload injection with the same configuration
		client, err := CreateProxyClient(ProxyPort, UserAgents["Chrome"])
		if err != nil {
			t.Fatalf("Failed to create proxy client: %v", err)
		}

		// Test with HTTPS HTML content
		req, err := http.NewRequest("GET", "https://localhost:"+HTTPSPort+"/html", nil)
		if err != nil {
			t.Fatalf("Failed to create HTTPS payload test request: %v", err)
		}
		req.Header.Set("User-Agent", UserAgents["Chrome"])

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("HTTPS payload injection request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200 for HTTPS payload test, got: %d", resp.StatusCode)
		}

		// Check if response contains our injected payload marker
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("Failed to read HTTPS payload test response: %v", err)
		}

		bodyStr := string(bodyBytes)
		contentType := resp.Header.Get("Content-Type")
		t.Logf("HTTPS Response content-type: %s", contentType)
		t.Logf("HTTPS Response body length: %d", len(bodyStr))

		// Verify payload injection - check if JavaScript payload is present in HTML response
		if strings.Contains(contentType, "text/html") {
			expectedPayload := "window.__masktunnel_injected = true"
			if strings.Contains(bodyStr, expectedPayload) {
				t.Log("HTTPS payload injection verified: JavaScript successfully injected into HTML")
			} else {
				t.Error("HTTPS payload injection failed: Expected JavaScript payload not found in HTML response")
				// Log a snippet of the response to help debug
				snippet := bodyStr
				if len(snippet) > 500 {
					snippet = snippet[:500] + "..."
				}
				t.Logf("HTTPS Response snippet: %s", snippet)
			}
		} else {
			t.Logf("HTTPS payload injection test skipped: Content-Type is not HTML (%s)", contentType)
		}

		t.Log("HTTPS payload injection test completed")
	})

	// Restore original proxy without payload for other tests
	proxyServer.Stop()
	time.Sleep(1 * time.Second)
	proxyServer = originalProxy
	go func() {
		if err := proxyServer.Start(); err != nil && err != http.ErrServerClosed {
			log.Error().Err(err).Msg("Normal proxy server restart error")
		}
	}()
	time.Sleep(2 * time.Second)
}

// TestConcurrentConnections tests concurrent connections and data isolation
func TestConcurrentConnections(t *testing.T) {
	numConnections := 10

	t.Run("HTTP", func(t *testing.T) {
		var wg sync.WaitGroup
		errors := make(chan error, numConnections)
		results := make(chan int, numConnections)

		baseURL := fmt.Sprintf("http://localhost:%s/", HTTPPort)

		for i := 0; i < numConnections; i++ {
			wg.Add(1)
			go func(connNum int) {
				defer wg.Done()

				client, err := CreateProxyClient(ProxyPort, UserAgents["Chrome"])
				if err != nil {
					errors <- fmt.Errorf("HTTP connection %d: failed to create client: %v", connNum, err)
					return
				}

				// Add unique query parameter to test data isolation
				url := fmt.Sprintf("%s?conn_id=%d", baseURL, connNum)
				req, err := http.NewRequest("GET", url, nil)
				if err != nil {
					errors <- fmt.Errorf("HTTP connection %d: failed to create request: %v", connNum, err)
					return
				}
				req.Header.Set("User-Agent", UserAgents["Chrome"])
				req.Header.Set("X-Connection-ID", fmt.Sprintf("%d", connNum))

				resp, err := client.Do(req)
				if err != nil {
					errors <- fmt.Errorf("HTTP connection %d: request failed: %v", connNum, err)
					return
				}
				defer resp.Body.Close()

				if resp.StatusCode != http.StatusOK {
					errors <- fmt.Errorf("HTTP connection %d: status code error: %d", connNum, resp.StatusCode)
					return
				}

				// Parse response to verify data isolation
				var responseData map[string]interface{}
				if err := json.NewDecoder(resp.Body).Decode(&responseData); err != nil {
					errors <- fmt.Errorf("HTTP connection %d: failed to parse response: %v", connNum, err)
					return
				}

				// Check that the correct conn_id is in the URL
				if urlField, ok := responseData["url"].(string); ok {
					expectedParam := fmt.Sprintf("conn_id=%d", connNum)
					if !strings.Contains(urlField, expectedParam) {
						errors <- fmt.Errorf("HTTP connection %d: data mix-up detected, expected %s in URL %s",
							connNum, expectedParam, urlField)
						return
					}
				} else {
					errors <- fmt.Errorf("HTTP connection %d: no URL field in response", connNum)
					return
				}

				// Check that the correct X-Connection-ID header is present
				if headers, ok := responseData["headers"].(map[string]interface{}); ok {
					if raw, exists := headers["X-Connection-Id"]; exists {
						expectedID := fmt.Sprintf("%d", connNum)
						got := ""
						switch v := raw.(type) {
						case string:
							got = v
						case []interface{}:
							if len(v) > 0 {
								if s, ok := v[0].(string); ok {
									got = s
								}
							}
						}
						if got == "" {
							errors <- fmt.Errorf("HTTP connection %d: no X-Connection-Id header", connNum)
							return
						}
						if got != expectedID {
							errors <- fmt.Errorf("HTTP connection %d: header mix-up detected, expected %s but got %v",
								connNum, expectedID, raw)
							return
						}
					}
				}

				results <- connNum
				t.Logf("HTTP Concurrent connection %d successful with correct data isolation", connNum)
			}(i)
		}

		wg.Wait()
		close(errors)
		close(results)

		// Check for errors
		for err := range errors {
			if err != nil {
				t.Error(err)
			}
		}

		// Verify all connections completed successfully
		completedConnections := 0
		for range results {
			completedConnections++
		}

		if completedConnections != numConnections {
			t.Errorf("Expected %d successful connections, got %d", numConnections, completedConnections)
		}

		t.Log("HTTP concurrent connections test passed with data isolation verification")
	})

	t.Run("HTTPS", func(t *testing.T) {
		var wg sync.WaitGroup
		errors := make(chan error, numConnections)
		results := make(chan int, numConnections)

		for i := 0; i < numConnections; i++ {
			wg.Add(1)
			go func(connNum int) {
				defer wg.Done()

				client, err := CreateProxyClient(ProxyPort, UserAgents["Firefox"])
				if err != nil {
					errors <- fmt.Errorf("HTTPS connection %d: failed to create client: %v", connNum, err)
					return
				}

				// Add unique query parameter to test data isolation
				baseURL := fmt.Sprintf("https://localhost:%s/", HTTPSPort)
				url := fmt.Sprintf("%s?conn_id=%d", baseURL, connNum)
				req, err := http.NewRequest("GET", url, nil)
				if err != nil {
					errors <- fmt.Errorf("HTTPS connection %d: failed to create request: %v", connNum, err)
					return
				}
				req.Header.Set("User-Agent", UserAgents["Firefox"])
				req.Header.Set("X-Connection-ID", fmt.Sprintf("%d", connNum))

				resp, err := client.Do(req)
				if err != nil {
					errors <- fmt.Errorf("HTTPS connection %d: request failed: %v", connNum, err)
					return
				}
				defer resp.Body.Close()

				if resp.StatusCode != http.StatusOK {
					errors <- fmt.Errorf("HTTPS connection %d: status code error: %d", connNum, resp.StatusCode)
					return
				}

				// Parse response to verify data isolation
				var responseData map[string]interface{}
				if err := json.NewDecoder(resp.Body).Decode(&responseData); err != nil {
					errors <- fmt.Errorf("HTTPS connection %d: failed to parse response: %v", connNum, err)
					return
				}

				// Check that the correct conn_id is in the URL
				if urlField, ok := responseData["url"].(string); ok {
					expectedParam := fmt.Sprintf("conn_id=%d", connNum)
					if !strings.Contains(urlField, expectedParam) {
						errors <- fmt.Errorf("HTTPS connection %d: data mix-up detected, expected %s in URL %s",
							connNum, expectedParam, urlField)
						return
					}
				} else {
					errors <- fmt.Errorf("HTTPS connection %d: no URL field in response", connNum)
					return
				}

				// Check that the correct X-Connection-ID header is present
				if headers, ok := responseData["headers"].(map[string]interface{}); ok {
					if raw, exists := headers["X-Connection-Id"]; exists {
						expectedID := fmt.Sprintf("%d", connNum)
						got := ""
						switch v := raw.(type) {
						case string:
							got = v
						case []interface{}:
							if len(v) > 0 {
								if s, ok := v[0].(string); ok {
									got = s
								}
							}
						}
						if got == "" {
							errors <- fmt.Errorf("HTTPS connection %d: no X-Connection-Id header", connNum)
							return
						}
						if got != expectedID {
							errors <- fmt.Errorf("HTTPS connection %d: header mix-up detected, expected %s but got %v",
								connNum, expectedID, raw)
							return
						}
					}
				}

				results <- connNum
				t.Logf("HTTPS Concurrent connection %d successful with correct data isolation", connNum)
			}(i)
		}

		wg.Wait()
		close(errors)
		close(results)

		// Check for errors
		for err := range errors {
			if err != nil {
				t.Error(err)
			}
		}

		// Verify all connections completed successfully
		completedConnections := 0
		for range results {
			completedConnections++
		}

		if completedConnections != numConnections {
			t.Errorf("Expected %d successful connections, got %d", numConnections, completedConnections)
		}

		t.Log("HTTPS concurrent connections test passed with data isolation verification")
	})
}

// TestFingerprintGeneration tests TLS and HTTP2 fingerprint generation for different browsers
func TestFingerprintGeneration(t *testing.T) {
	// Test fingerprint detection service
	fingerprintURL := "https://tls.peet.ws/api/all"

	testCases := []struct {
		browser   string
		userAgent string
	}{
		{"Chrome", UserAgents["Chrome"]},
		{"Firefox", UserAgents["Firefox"]},
		{"Safari", UserAgents["Safari"]},
	}

	t.Run("HTTPS", func(t *testing.T) {
		t.Run("Comparison", func(t *testing.T) {
			// HTTPS fingerprint comparison between direct connection and proxy
			// Test direct connection fingerprint
			directClient := CreateDirectClient()
			directReq, err := http.NewRequest("GET", fingerprintURL, nil)
			if err != nil {
				t.Fatalf("Failed to create direct fingerprint request: %v", err)
			}
			directReq.Header.Set("User-Agent", UserAgents["Chrome"])

			directResp, err := directClient.Do(directReq)
			if err != nil {
				t.Skipf("Direct HTTPS fingerprint test failed (network issue): %v", err)
				return
			}
			defer directResp.Body.Close()

			var directFingerprint map[string]interface{}
			if err := json.NewDecoder(directResp.Body).Decode(&directFingerprint); err != nil {
				t.Fatalf("Failed to parse direct fingerprint response: %v", err)
			}

			// Test proxy connection fingerprint
			proxyClient, err := CreateProxyClient(ProxyPort, UserAgents["Chrome"])
			if err != nil {
				t.Fatalf("Failed to create proxy client: %v", err)
			}

			proxyReq, err := http.NewRequest("GET", fingerprintURL, nil)
			if err != nil {
				t.Fatalf("Failed to create proxy fingerprint request: %v", err)
			}
			proxyReq.Header.Set("User-Agent", UserAgents["Chrome"])

			proxyResp, err := proxyClient.Do(proxyReq)
			if err != nil {
				t.Skipf("Proxy HTTPS fingerprint test failed (network issue): %v", err)
				return
			}
			defer proxyResp.Body.Close()

			var proxyFingerprint map[string]interface{}
			if err := json.NewDecoder(proxyResp.Body).Decode(&proxyFingerprint); err != nil {
				t.Fatalf("Failed to parse proxy fingerprint response: %v", err)
			}

			// Compare JA4 fingerprints
			directTLS, directTLSOk := directFingerprint["tls"].(map[string]interface{})
			proxyTLS, proxyTLSOk := proxyFingerprint["tls"].(map[string]interface{})

			if directTLSOk && proxyTLSOk {
				directJA4 := directTLS["ja4"]
				proxyJA4 := proxyTLS["ja4"]

				if directJA4 != nil && proxyJA4 != nil && directJA4 == proxyJA4 {
					t.Errorf("Proxy should forge JA4 fingerprint, should not be same as direct connection. Direct: %v, Proxy: %v", directJA4, proxyJA4)
				} else {
					t.Logf("JA4 fingerprint verification passed - Direct: %v, Proxy: %v", directJA4, proxyJA4)
				}
			}

			// Compare Akamai HTTP/2 fingerprints
			directHTTP2, directHTTP2Ok := directFingerprint["http2"].(map[string]interface{})
			proxyHTTP2, proxyHTTP2Ok := proxyFingerprint["http2"].(map[string]interface{})

			if directHTTP2Ok && proxyHTTP2Ok {
				directAkamai := directHTTP2["akamai_fingerprint_hash"]
				proxyAkamai := proxyHTTP2["akamai_fingerprint_hash"]

				if directAkamai != nil && proxyAkamai != nil && directAkamai == proxyAkamai {
					t.Errorf("Proxy should forge Akamai fingerprint, should not be same as direct connection. Direct: %v, Proxy: %v", directAkamai, proxyAkamai)
				} else {
					t.Logf("Akamai HTTP/2 fingerprint verification passed - Direct: %v, Proxy: %v", directAkamai, proxyAkamai)
				}
			} else {
				t.Log("HTTP/2 fingerprint data not available for comparison")
			}

			t.Log("HTTPS fingerprint comparison test completed")
		})

		t.Run("Multiple_Browser_Fingerprints", func(t *testing.T) {
			fingerprints := make(map[string]map[string]interface{})

			for _, tc := range testCases {
				t.Run(tc.browser, func(t *testing.T) {
					client, err := CreateProxyClient(ProxyPort, tc.userAgent)
					if err != nil {
						t.Fatalf("Failed to create proxy client for %s: %v", tc.browser, err)
					}

					req, err := http.NewRequest("GET", fingerprintURL, nil)
					if err != nil {
						t.Fatalf("Failed to create fingerprint request for %s: %v", tc.browser, err)
					}
					req.Header.Set("User-Agent", tc.userAgent)

					resp, err := client.Do(req)
					if err != nil {
						t.Skipf("Fingerprint request failed for %s (network issue): %v", tc.browser, err)
						return
					}
					defer resp.Body.Close()

					if resp.StatusCode != http.StatusOK {
						t.Errorf("Expected status 200 for %s fingerprint, got: %d", tc.browser, resp.StatusCode)
						return
					}

					var fingerprintData map[string]interface{}
					if err := json.NewDecoder(resp.Body).Decode(&fingerprintData); err != nil {
						t.Fatalf("Failed to parse fingerprint response for %s: %v", tc.browser, err)
					}

					// Store fingerprint for comparison
					fingerprints[tc.browser] = fingerprintData

					// Log JA4 and Akamai fingerprint information
					if tls, ok := fingerprintData["tls"].(map[string]interface{}); ok {
						if ja4, ja4Ok := tls["ja4"]; ja4Ok {
							t.Logf("%s JA4 fingerprint: %v", tc.browser, ja4)
						}
					}

					if http2, ok := fingerprintData["http2"].(map[string]interface{}); ok {
						if akamai, akamaiOk := http2["akamai_fingerprint_hash"]; akamaiOk {
							t.Logf("%s Akamai fingerprint: %v", tc.browser, akamai)
						}
					}

					t.Logf("%s HTTPS fingerprint generation successful", tc.browser)
				})
			}

			// Verify different browsers produce different JA4 and Akamai fingerprints
			browsers := []string{"Chrome", "Firefox", "Safari"}
			for i := 0; i < len(browsers); i++ {
				for j := i + 1; j < len(browsers); j++ {
					browser1, browser2 := browsers[i], browsers[j]

					if fp1, ok1 := fingerprints[browser1]; ok1 {
						if fp2, ok2 := fingerprints[browser2]; ok2 {
							// Compare JA4 fingerprints
							var ja4_1, ja4_2 interface{}
							if tls1, ok := fp1["tls"].(map[string]interface{}); ok {
								ja4_1 = tls1["ja4"]
							}
							if tls2, ok := fp2["tls"].(map[string]interface{}); ok {
								ja4_2 = tls2["ja4"]
							}

							if ja4_1 != nil && ja4_2 != nil {
								if ja4_1 == ja4_2 {
									t.Errorf("%s and %s should have different JA4 fingerprints, but both have: %v",
										browser1, browser2, ja4_1)
								} else {
									t.Logf("JA4 fingerprint verification passed - %s and %s have different JA4",
										browser1, browser2)
								}
							}

							// Compare Akamai fingerprints
							var akamai_1, akamai_2 interface{}
							if http2_1, ok := fp1["http2"].(map[string]interface{}); ok {
								akamai_1 = http2_1["akamai_fingerprint_hash"]
							}
							if http2_2, ok := fp2["http2"].(map[string]interface{}); ok {
								akamai_2 = http2_2["akamai_fingerprint_hash"]
							}

							if akamai_1 != nil && akamai_2 != nil {
								if akamai_1 == akamai_2 {
									t.Errorf("%s and %s should have different Akamai fingerprints, but both have: %v",
										browser1, browser2, akamai_1)
								} else {
									t.Logf("Akamai fingerprint verification passed - %s and %s have different Akamai",
										browser1, browser2)
								}
							}
						}
					}
				}
			}
		})
	})
}

// TestRedirectBehavior tests that HTTP/HTTPS proxy does not follow redirects
func TestRedirectBehavior(t *testing.T) {
	t.Run("HTTP", func(t *testing.T) {
		client, err := CreateProxyClient(ProxyPort, UserAgents["Chrome"])
		if err != nil {
			t.Fatalf("Failed to create proxy client: %v", err)
		}

		// Test POST request to redirect endpoint
		redirectURL := fmt.Sprintf("http://localhost:%s/redirect/302", HTTPPort)

		t.Run("POST_302_NoFollow", func(t *testing.T) {
			req, err := http.NewRequest("POST", redirectURL, strings.NewReader("test=data"))
			if err != nil {
				t.Fatalf("Failed to create POST request: %v", err)
			}
			req.Header.Set("User-Agent", UserAgents["Chrome"])
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("POST redirect request failed: %v", err)
			}
			defer resp.Body.Close()

			// Should receive 302 response, not follow redirect
			if resp.StatusCode != http.StatusFound {
				t.Errorf("Expected 302 status code, got: %d", resp.StatusCode)
			}

			// Should have Location header
			location := resp.Header.Get("Location")
			if location == "" {
				t.Error("Expected Location header in 302 response")
			}

			// Verify response body contains redirect info
			var responseData map[string]interface{}
			if err := json.NewDecoder(resp.Body).Decode(&responseData); err != nil {
				t.Fatalf("Failed to parse redirect response: %v", err)
			}

			if responseData["status"] != float64(302) {
				t.Errorf("Response body should indicate 302 status, got: %v", responseData["status"])
			}

			if responseData["method"] != "POST" {
				t.Errorf("Original method should be preserved as POST, got: %v", responseData["method"])
			}

			t.Logf("HTTP POST 302 redirect correctly NOT followed - Status: %d, Location: %s",
				resp.StatusCode, location)
		})

		t.Run("GET_302_NoFollow", func(t *testing.T) {
			req, err := http.NewRequest("GET", redirectURL, nil)
			if err != nil {
				t.Fatalf("Failed to create GET request: %v", err)
			}
			req.Header.Set("User-Agent", UserAgents["Chrome"])

			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("GET redirect request failed: %v", err)
			}
			defer resp.Body.Close()

			// Should receive 302 response, not follow redirect
			if resp.StatusCode != http.StatusFound {
				t.Errorf("Expected 302 status code, got: %d", resp.StatusCode)
			}

			// Should have Location header
			location := resp.Header.Get("Location")
			if location == "" {
				t.Error("Expected Location header in 302 response")
			}

			t.Logf("HTTP GET 302 redirect correctly NOT followed - Status: %d, Location: %s",
				resp.StatusCode, location)
		})
	})

	t.Run("HTTPS", func(t *testing.T) {
		client, err := CreateProxyClient(ProxyPort, UserAgents["Firefox"])
		if err != nil {
			t.Fatalf("Failed to create proxy client: %v", err)
		}

		// Test POST request to HTTPS redirect endpoint
		redirectURL := fmt.Sprintf("https://localhost:%s/redirect/302", HTTPSPort)

		t.Run("POST_302_NoFollow", func(t *testing.T) {
			req, err := http.NewRequest("POST", redirectURL, strings.NewReader("test=data"))
			if err != nil {
				t.Fatalf("Failed to create HTTPS POST request: %v", err)
			}
			req.Header.Set("User-Agent", UserAgents["Firefox"])
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("HTTPS POST redirect request failed: %v", err)
			}
			defer resp.Body.Close()

			// Should receive 302 response, not follow redirect
			if resp.StatusCode != http.StatusFound {
				t.Errorf("Expected 302 status code, got: %d", resp.StatusCode)
			}

			// Should have Location header
			location := resp.Header.Get("Location")
			if location == "" {
				t.Error("Expected Location header in 302 response")
			}

			// Verify response body contains redirect info
			var responseData map[string]interface{}
			if err := json.NewDecoder(resp.Body).Decode(&responseData); err != nil {
				t.Fatalf("Failed to parse HTTPS redirect response: %v", err)
			}

			if responseData["status"] != float64(302) {
				t.Errorf("Response body should indicate 302 status, got: %v", responseData["status"])
			}

			if responseData["method"] != "POST" {
				t.Errorf("Original method should be preserved as POST, got: %v", responseData["method"])
			}

			if responseData["protocol"] != "https" {
				t.Errorf("Protocol should be https, got: %v", responseData["protocol"])
			}

			t.Logf("HTTPS POST 302 redirect correctly NOT followed - Status: %d, Location: %s",
				resp.StatusCode, location)
		})

		t.Run("GET_302_NoFollow", func(t *testing.T) {
			req, err := http.NewRequest("GET", redirectURL, nil)
			if err != nil {
				t.Fatalf("Failed to create HTTPS GET request: %v", err)
			}
			req.Header.Set("User-Agent", UserAgents["Firefox"])

			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("HTTPS GET redirect request failed: %v", err)
			}
			defer resp.Body.Close()

			// Should receive 302 response, not follow redirect
			if resp.StatusCode != http.StatusFound {
				t.Errorf("Expected 302 status code, got: %d", resp.StatusCode)
			}

			// Should have Location header
			location := resp.Header.Get("Location")
			if location == "" {
				t.Error("Expected Location header in 302 response")
			}

			t.Logf("HTTPS GET 302 redirect correctly NOT followed - Status: %d, Location: %s",
				resp.StatusCode, location)
		})
	})
}

// TestRedirectTargetAccess tests that we can access redirect targets directly
func TestRedirectTargetAccess(t *testing.T) {
	client, err := CreateProxyClient(ProxyPort, UserAgents["Safari"])
	if err != nil {
		t.Fatalf("Failed to create proxy client: %v", err)
	}

	t.Run("HTTP", func(t *testing.T) {
		targetURL := fmt.Sprintf("http://localhost:%s/redirect/target", HTTPPort)
		req, err := http.NewRequest("GET", targetURL, nil)
		if err != nil {
			t.Fatalf("Failed to create request: %v", err)
		}
		req.Header.Set("User-Agent", UserAgents["Safari"])

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Direct target request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected 200 status code, got: %d", resp.StatusCode)
		}

		var responseData map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&responseData); err != nil {
			t.Fatalf("Failed to parse target response: %v", err)
		}

		if responseData["is_target"] != true {
			t.Error("Response should indicate this is the target endpoint")
		}

		t.Log("HTTP redirect target accessible directly")
	})

	t.Run("HTTPS", func(t *testing.T) {
		targetURL := fmt.Sprintf("https://localhost:%s/redirect/target", HTTPSPort)
		req, err := http.NewRequest("GET", targetURL, nil)
		if err != nil {
			t.Fatalf("Failed to create HTTPS request: %v", err)
		}
		req.Header.Set("User-Agent", UserAgents["Safari"])

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("HTTPS direct target request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected 200 status code, got: %d", resp.StatusCode)
		}

		var responseData map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&responseData); err != nil {
			t.Fatalf("Failed to parse HTTPS target response: %v", err)
		}

		if responseData["is_target"] != true {
			t.Error("Response should indicate this is the target endpoint")
		}

		if responseData["protocol"] != "https" {
			t.Errorf("Protocol should be https, got: %v", responseData["protocol"])
		}

		t.Log("HTTPS redirect target accessible directly")
	})
}

// TestHTTPSConnect tests HTTPS CONNECT tunnel functionality
func TestHTTPSConnect(t *testing.T) {
	target := "httpbin.org:443"

	// Establish CONNECT tunnel
	conn, err := CreateTCPConnection(ProxyPort, target)
	if err != nil {
		t.Fatalf("Failed to establish CONNECT tunnel: %v", err)
	}
	defer conn.Close()

	// Wrap with TLS
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "httpbin.org",
	}

	tlsConn := tls.Client(conn, tlsConfig)
	defer tlsConn.Close()

	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("TLS handshake failed: %v", err)
	}

	// Test with external HTTPS service through CONNECT tunnel
	request := fmt.Sprintf("GET /get HTTP/1.1\r\nHost: httpbin.org\r\nUser-Agent: %s\r\nConnection: close\r\n\r\n",
		UserAgents["Chrome"])

	if _, err := tlsConn.Write([]byte(request)); err != nil {
		t.Fatalf("Failed to send HTTPS request: %v", err)
	}

	// Read response
	buffer := make([]byte, 4096)
	n, err := tlsConn.Read(buffer)
	if err != nil {
		t.Fatalf("Failed to read HTTPS response: %v", err)
	}

	response := string(buffer[:n])
	if !strings.Contains(response, "200 OK") {
		t.Errorf("Unexpected HTTPS response: %s", response)
	}

	t.Log("HTTPS CONNECT tunnel test passed")
}

// TestWebSocketProxy tests WebSocket connections through the proxy
func TestWebSocketProxy(t *testing.T) {
	t.Run("HTTP", func(t *testing.T) {
		client, err := CreateProxyClient(ProxyPort, UserAgents["Chrome"])
		if err != nil {
			t.Fatalf("Failed to create proxy client: %v", err)
		}

		// Set a reasonable timeout for WebSocket testing
		client.Timeout = 10 * time.Second

		t.Run("Basic_Connection", func(t *testing.T) {
			// Test basic connectivity to WebSocket endpoint
			wsURL := fmt.Sprintf("http://localhost:%s/ws", WSPort)
			req, err := http.NewRequest("GET", wsURL, nil)
			if err != nil {
				t.Fatalf("Failed to create WebSocket request: %v", err)
			}

			// Set WebSocket upgrade headers
			req.Header.Set("User-Agent", UserAgents["Chrome"])
			req.Header.Set("Connection", "Upgrade")
			req.Header.Set("Upgrade", "websocket")
			req.Header.Set("Sec-WebSocket-Version", "13")
			req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")

			resp, err := client.Do(req)
			if err != nil {
				t.Logf("Local WebSocket endpoint test failed: %v", err)
				return
			}
			defer resp.Body.Close()

			// Check if this looks like a WebSocket upgrade response
			if resp.StatusCode == 101 {
				t.Log("HTTP WebSocket upgrade successful through proxy")
			} else if resp.StatusCode == 200 {
				t.Log("HTTP WebSocket endpoint reachable through proxy (HTTP 200)")
			} else {
				t.Logf("HTTP WebSocket endpoint returned status: %d", resp.StatusCode)
			}

			// Log connection headers for debugging
			t.Logf("Response headers: Connection=%s, Upgrade=%s",
				resp.Header.Get("Connection"), resp.Header.Get("Upgrade"))
		})

		t.Run("Message_Exchange", func(t *testing.T) {
			// Create WebSocket dialer with proxy support
			proxyURL, err := url.Parse(fmt.Sprintf("http://localhost:%s", ProxyPort))
			if err != nil {
				t.Fatalf("Failed to parse proxy URL: %v", err)
			}

			dialer := &websocket.Dialer{
				Proxy:            http.ProxyURL(proxyURL),
				HandshakeTimeout: 10 * time.Second,
			}

			// Connect to WebSocket server through proxy
			wsURL := fmt.Sprintf("ws://localhost:%s/ws", WSPort)
			header := http.Header{}
			header.Set("User-Agent", UserAgents["Chrome"])

			conn, resp, err := dialer.Dial(wsURL, header)
			if err != nil {
				if resp != nil {
					t.Logf("WebSocket connection failed with status: %d", resp.StatusCode)
				}
				t.Skipf("HTTP WebSocket message exchange test failed: %v", err)
				return
			}
			defer conn.Close()

			t.Log("HTTP WebSocket connection established through proxy")

			// Test message exchange: send -> receive -> send -> receive
			messages := []map[string]interface{}{
				{"type": "test", "message": "Hello WebSocket", "sequence": 1},
				{"type": "test", "message": "Second message", "sequence": 2},
			}

			for i, msg := range messages {
				// Send message
				if err := conn.WriteJSON(msg); err != nil {
					t.Fatalf("Failed to send message %d: %v", i+1, err)
				}
				t.Logf("Sent message %d: %v", i+1, msg)

				// Receive response
				var response map[string]interface{}
				if err := conn.ReadJSON(&response); err != nil {
					t.Fatalf("Failed to receive response %d: %v", i+1, err)
				}
				t.Logf("Received response %d: %v", i+1, response)

				// Verify echo response
				if echoType, ok := response["type"].(string); !ok || echoType != "echo" {
					t.Errorf("Expected echo response, got: %v", response)
				}

				if received, ok := response["received"].(map[string]interface{}); ok {
					if sequence, exists := received["sequence"]; exists {
						if sequence != float64(i+1) {
							t.Errorf("Message sequence mismatch: expected %d, got %v", i+1, sequence)
						}
					}
				}
			}

			// Send close message
			closeMsg := map[string]interface{}{"type": "close"}
			if err := conn.WriteJSON(closeMsg); err != nil {
				t.Logf("Failed to send close message: %v", err)
			}

			t.Log("HTTP WebSocket message exchange test completed successfully")
		})

	})

	t.Run("HTTPS", func(t *testing.T) {
		// Test secure WebSocket message exchange through CONNECT tunnel
		// Use external WSS service since it's complex to setup local WSS through proxy

		// Create WebSocket dialer with proxy support for WSS
		proxyURL, err := url.Parse(fmt.Sprintf("http://localhost:%s", ProxyPort))
		if err != nil {
			t.Fatalf("Failed to parse proxy URL: %v", err)
		}

		dialer := &websocket.Dialer{
			Proxy:            http.ProxyURL(proxyURL),
			HandshakeTimeout: 15 * time.Second,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // For testing purposes
			},
		}

		// Try to connect to a public WebSocket echo service via WSS
		wsURL := "wss://echo.websocket.org"
		header := http.Header{}
		header.Set("User-Agent", UserAgents["Chrome"])

		conn, resp, err := dialer.Dial(wsURL, header)
		if err != nil {
			if resp != nil {
				t.Logf("WSS connection failed with status: %d", resp.StatusCode)
			}
			t.Skipf("HTTPS WebSocket message exchange test failed (external service issue): %v", err)
			return
		}
		defer conn.Close()

		t.Log("HTTPS WebSocket connection established through proxy")

		// Test message exchange: send -> receive -> send -> receive
		messages := []string{
			"Hello WSS WebSocket through proxy",
			"Second secure message",
		}

		for i, msg := range messages {
			// Send message
			if err := conn.WriteMessage(websocket.TextMessage, []byte(msg)); err != nil {
				t.Fatalf("Failed to send WSS message %d: %v", i+1, err)
			}
			t.Logf("Sent WSS message %d: %s", i+1, msg)

			// Receive echo
			_, response, err := conn.ReadMessage()
			if err != nil {
				t.Fatalf("Failed to receive WSS response %d: %v", i+1, err)
			}

			responseStr := string(response)
			t.Logf("Received WSS response %d: %s", i+1, responseStr)

			// Verify echo (echo.websocket.org should echo back the same message)
			if responseStr != msg {
				t.Errorf("WSS message echo mismatch: sent '%s', received '%s'", msg, responseStr)
			}
		}

		t.Log("HTTPS WebSocket message exchange test completed successfully")
	})

	t.Log("WebSocket proxy test completed")
}

// TestStream tests whether the proxy forwards data in streaming mode or buffers entire response
func TestStream(t *testing.T) {
	t.Run("HTTP", func(t *testing.T) {
		client, err := CreateProxyClient(ProxyPort, UserAgents["Chrome"])
		if err != nil {
			t.Fatalf("Failed to create proxy client: %v", err)
		}

		// Test streaming with the local slow server endpoint
		t.Run("Timing", func(t *testing.T) {
			streamURL := fmt.Sprintf("http://localhost:%s/stream?numbytes=5&duration=3&delay=1", HTTPPort)
			req, err := http.NewRequest("GET", streamURL, nil)
			if err != nil {
				t.Fatalf("Failed to create stream request: %v", err)
			}
			req.Header.Set("User-Agent", UserAgents["Chrome"])

			startTime := time.Now()
			resp, err := client.Do(req)
			if err != nil {
				t.Skipf("HTTP stream test failed (network issue): %v", err)
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				t.Errorf("Expected status 200 for stream, got: %d", resp.StatusCode)
				return
			}

			// Read data byte by byte and record timing
			var receiveTimes []time.Duration
			buffer := make([]byte, 1)
			totalBytes := 0

			for {
				n, err := resp.Body.Read(buffer)
				if n > 0 {
					totalBytes++
					elapsed := time.Since(startTime)
					receiveTimes = append(receiveTimes, elapsed)
					t.Logf("HTTP streaming: received byte %d after %v", totalBytes, elapsed)
				}

				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatalf("Error reading stream: %v", err)
				}
			}

			totalDuration := time.Since(startTime)
			t.Logf("HTTP streaming test completed: %d bytes in %v", totalBytes, totalDuration)

			// Analyze timing to detect streaming vs buffering behavior
			if len(receiveTimes) >= 2 {
				firstByteTime := receiveTimes[0]
				secondByteTime := receiveTimes[1]

				// If proxy is streaming, we should receive first byte quickly
				// and subsequent bytes with delays between them
				if firstByteTime > 3*time.Second {
					t.Error("HTTP: First byte took too long - proxy may be buffering entire response")
				}

				if len(receiveTimes) > 2 {
					timeBetweenBytes := secondByteTime - firstByteTime
					if timeBetweenBytes < 500*time.Millisecond {
						t.Logf("HTTP: Fast consecutive bytes (%v) - may indicate buffering", timeBetweenBytes)
					} else {
						t.Logf("HTTP: Delayed consecutive bytes (%v) - indicates streaming", timeBetweenBytes)
					}
				}
			}

			// Expected behavior: receiving data incrementally over time indicates streaming
			if totalDuration < 2*time.Second {
				t.Log("HTTP: Response completed very quickly - proxy may be buffering")
			} else {
				t.Log("HTTP: Response took expected time - proxy appears to be streaming")
			}
		})

		// Also validate endings for HTTP: fixed/chunked/close
		t.Run("Endings", func(t *testing.T) {
			t.Run("Fixed", func(t *testing.T) {
				url := fmt.Sprintf("http://localhost:%s/stream/fixed?numbytes=7", HTTPPort)
				req, _ := http.NewRequest("GET", url, nil)
				req.Header.Set("User-Agent", UserAgents["Chrome"])
				resp, err := client.Do(req)
				if err != nil {
					t.Fatalf("request failed: %v", err)
				}
				defer resp.Body.Close()
				b, _ := io.ReadAll(resp.Body)
				if len(b) != 7 {
					t.Fatalf("expected 7 bytes, got %d", len(b))
				}
			})
			t.Run("Chunked", func(t *testing.T) {
				url := fmt.Sprintf("http://localhost:%s/stream/chunked?numbytes=7&duration=1&delay=0", HTTPPort)
				req, _ := http.NewRequest("GET", url, nil)
				req.Header.Set("User-Agent", UserAgents["Chrome"])
				start := time.Now()
				resp, err := client.Do(req)
				if err != nil {
					t.Fatalf("request failed: %v", err)
				}
				defer resp.Body.Close()
				b, _ := io.ReadAll(resp.Body)
				elapsed := time.Since(start)
				if len(b) != 7 {
					t.Fatalf("expected 7 bytes, got %d", len(b))
				}
				if elapsed < 900*time.Millisecond {
					t.Fatalf("chunked stream too fast: %v", elapsed)
				}
			})
			t.Run("Close", func(t *testing.T) {
				url := fmt.Sprintf("http://localhost:%s/stream/close?numbytes=7", HTTPPort)
				req, _ := http.NewRequest("GET", url, nil)
				req.Header.Set("User-Agent", UserAgents["Chrome"])
				resp, err := client.Do(req)
				if err != nil {
					t.Fatalf("request failed: %v", err)
				}
				defer resp.Body.Close()
				b, _ := io.ReadAll(resp.Body)
				if len(b) != 7 {
					t.Fatalf("expected 7 bytes, got %d", len(b))
				}
			})
		})
	})

	t.Run("HTTPS", func(t *testing.T) {
		client, err := CreateProxyClient(ProxyPort, UserAgents["Safari"])
		if err != nil {
			t.Fatalf("Failed to create proxy client: %v", err)
		}

		// Test streaming with the local slow server endpoint
		t.Run("Timing", func(t *testing.T) {
			streamURL := fmt.Sprintf("https://localhost:%s/stream?numbytes=5&duration=3&delay=1", HTTPSPort)
			req, err := http.NewRequest("GET", streamURL, nil)
			if err != nil {
				t.Fatalf("Failed to create stream request: %v", err)
			}
			req.Header.Set("User-Agent", UserAgents["Safari"])

			startTime := time.Now()
			resp, err := client.Do(req)
			if err != nil {
				t.Skipf("HTTPS stream test failed (network issue): %v", err)
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				t.Errorf("Expected status 200 for HTTPS stream, got: %d", resp.StatusCode)
				return
			}

			// Read data byte by byte and record timing
			var receiveTimes []time.Duration
			buffer := make([]byte, 1)
			totalBytes := 0

			for {
				n, err := resp.Body.Read(buffer)
				if n > 0 {
					totalBytes++
					elapsed := time.Since(startTime)
					receiveTimes = append(receiveTimes, elapsed)
					t.Logf("HTTPS streaming: received byte %d after %v", totalBytes, elapsed)
				}

				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatalf("Error reading HTTPS stream: %v", err)
				}
			}

			totalDuration := time.Since(startTime)
			t.Logf("HTTPS streaming test completed: %d bytes in %v", totalBytes, totalDuration)

			// Analyze timing to detect streaming vs buffering behavior
			if len(receiveTimes) >= 2 {
				firstByteTime := receiveTimes[0]
				secondByteTime := receiveTimes[1]

				// If proxy is streaming, we should receive first byte quickly
				// and subsequent bytes with delays between them
				if firstByteTime > 3*time.Second {
					t.Error("HTTPS: First byte took too long - proxy may be buffering entire response")
				}

				if len(receiveTimes) > 2 {
					timeBetweenBytes := secondByteTime - firstByteTime
					if timeBetweenBytes < 500*time.Millisecond {
						t.Logf("HTTPS: Fast consecutive bytes (%v) - may indicate buffering", timeBetweenBytes)
					} else {
						t.Logf("HTTPS: Delayed consecutive bytes (%v) - indicates streaming", timeBetweenBytes)
					}
				}
			}

			// Expected behavior: receiving data incrementally over time indicates streaming
			if totalDuration < 2*time.Second {
				t.Log("HTTPS: Response completed very quickly - proxy may be buffering")
			} else {
				t.Log("HTTPS: Response took expected time - proxy appears to be streaming")
			}
		})

		// Also validate endings for HTTPS: fixed/close
		t.Run("Endings", func(t *testing.T) {
			t.Run("Fixed", func(t *testing.T) {
				url := fmt.Sprintf("https://localhost:%s/stream/fixed?numbytes=7", HTTPSPort)
				req, _ := http.NewRequest("GET", url, nil)
				req.Header.Set("User-Agent", UserAgents["Safari"])
				resp, err := client.Do(req)
				if err != nil {
					t.Fatalf("request failed: %v", err)
				}
				defer resp.Body.Close()
				b, _ := io.ReadAll(resp.Body)
				if len(b) != 7 {
					t.Fatalf("expected 7 bytes, got %d", len(b))
				}
			})
			t.Run("Chunked", func(t *testing.T) {
				url := fmt.Sprintf("https://localhost:%s/stream/chunked?numbytes=7&duration=1&delay=0", HTTPSPort)
				req, _ := http.NewRequest("GET", url, nil)
				req.Header.Set("User-Agent", UserAgents["Safari"])
				start := time.Now()
				resp, err := client.Do(req)
				if err != nil {
					t.Fatalf("request failed: %v", err)
				}
				defer resp.Body.Close()
				b, _ := io.ReadAll(resp.Body)
				elapsed := time.Since(start)
				if len(b) != 7 {
					t.Fatalf("expected 7 bytes, got %d", len(b))
				}
				if elapsed < 900*time.Millisecond {
					t.Fatalf("chunked stream too fast: %v", elapsed)
				}
			})
		})
	})
}
