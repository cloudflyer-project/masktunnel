package masktunnel

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Noooste/azuretls-client"
	tls "github.com/Noooste/utls"
)

// These tests compare MaskTunnel's locally computed fingerprints against
// tls.peet.ws, which reports what the server actually observed on the wire.
// They need internet access and are skipped unless MASKTUNNEL_PEET_TEST=1.

const peetAddress = "tls.peet.ws:443"

func requirePeet(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}
	if os.Getenv("MASKTUNNEL_PEET_TEST") == "" {
		t.Skip("set MASKTUNNEL_PEET_TEST=1 to run tests against tls.peet.ws")
	}
}

type peetResponse struct {
	TLS struct {
		JA3     string `json:"ja3"`
		JA3Hash string `json:"ja3_hash"`
		JA4     string `json:"ja4"`
	} `json:"tls"`
	HTTP2 struct {
		AkamaiFingerprint     string `json:"akamai_fingerprint"`
		AkamaiFingerprintHash string `json:"akamai_fingerprint_hash"`
	} `json:"http2"`
}

// TestJA3JA4MatchPeetOnCapturedHello sends a ClientHello to tls.peet.ws while
// capturing the exact bytes written to the wire, then checks that the JA3 and
// JA4 computed from those bytes equal what Peet observed for the same
// connection.
func TestJA3JA4MatchPeetOnCapturedHello(t *testing.T) {
	requirePeet(t)

	cases := []struct {
		name string
		spec func() *tls.ClientHelloSpec
	}{
		{"chrome", azuretls.GetLastChromeVersion},
		{"firefox", azuretls.GetLastFirefoxVersion},
		{"safari", azuretls.GetLastSafariVersion},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			record, observed := requestPeetViaCapturedHello(t, tc.spec)

			clientHello, err := parseClientHelloRecord(record)
			if err != nil {
				t.Fatalf("failed to parse captured hello: %v", err)
			}

			ja3 := ja3Of(clientHello)
			if ja3 != observed.TLS.JA3 {
				t.Errorf("JA3 mismatch for same bytes:\n  ours: %s\n  peet: %s", ja3, observed.TLS.JA3)
			}
			if hash := md5Hex(ja3); hash != observed.TLS.JA3Hash {
				t.Errorf("JA3 hash mismatch:\n  ours: %s\n  peet: %s", hash, observed.TLS.JA3Hash)
			}
			if ja4 := ja4Of(clientHello); ja4 != observed.TLS.JA4 {
				t.Errorf("JA4 mismatch for same bytes:\n  ours: %s\n  peet: %s", ja4, observed.TLS.JA4)
			}
		})
	}
}

// TestSessionFingerprintsMatchPeet runs a real azuretls session configured
// exactly like MaskTunnel's Manager and checks that the JA4 and HTTP/2
// fingerprints the session actually presents match the locally computed
// report.
func TestSessionFingerprintsMatchPeet(t *testing.T) {
	requirePeet(t)

	cases := []struct {
		name string
		ua   string
	}{
		{"chrome", testChromeUA},
		{"firefox", testFirefoxUA},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			report, err := GetFingerprintReport(tc.ua)
			if err != nil {
				t.Fatalf("GetFingerprintReport: %v", err)
			}
			browserFingerprint, err := GetBrowserFingerprint(tc.ua)
			if err != nil {
				t.Fatalf("GetBrowserFingerprint: %v", err)
			}

			session := azuretls.NewSession()
			defer session.Close()
			session.Browser = azuretlsBrowserConstant(report.Browser)
			session.GetClientHelloSpec = browserClientHelloSpec(report.Browser)
			session.InsecureSkipVerify = true
			if err := session.ApplyHTTP2(browserFingerprint.HTTP2Fingerprint); err != nil {
				t.Fatalf("ApplyHTTP2: %v", err)
			}

			response, err := session.Get("https://tls.peet.ws/api/all")
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			if response.StatusCode != 200 {
				t.Fatalf("unexpected status: %d, body: %s", response.StatusCode, response.String())
			}

			var observed peetResponse
			if err := response.JSON(&observed); err != nil {
				t.Fatalf("failed to parse peet response: %v", err)
			}

			if observed.TLS.JA4 != report.JA4 {
				t.Errorf("JA4 mismatch:\n  report: %s\n  peet:   %s", report.JA4, observed.TLS.JA4)
			}
			if observed.HTTP2.AkamaiFingerprint != report.AkamaiFingerprint {
				t.Errorf("Akamai fingerprint mismatch:\n  report: %s\n  peet:   %s",
					report.AkamaiFingerprint, observed.HTTP2.AkamaiFingerprint)
			}
			if observed.HTTP2.AkamaiFingerprintHash != report.AkamaiHash {
				t.Errorf("Akamai hash mismatch:\n  report: %s\n  peet:   %s",
					report.AkamaiHash, observed.HTTP2.AkamaiFingerprintHash)
			}

			// The Firefox preset has no shuffled extensions or randomized
			// GREASE values, so its JA3 must be identical across connections.
			if tc.name == "firefox" && observed.TLS.JA3 != report.JA3 {
				t.Errorf("JA3 mismatch for deterministic preset:\n  report: %s\n  peet:   %s",
					report.JA3, observed.TLS.JA3)
			}
		})
	}
}

// requestPeetViaCapturedHello performs a TLS handshake with tls.peet.ws using
// the given ClientHello generator, captures the ClientHello bytes written to
// the wire, issues an HTTP/1.1 request and returns both the record bytes and
// Peet's view of the connection.
func requestPeetViaCapturedHello(t *testing.T, specFn func() *tls.ClientHelloSpec) ([]byte, peetResponse) {
	t.Helper()

	conn, err := (&net.Dialer{Timeout: 15 * time.Second}).Dial("tcp", peetAddress)
	if err != nil {
		t.Fatalf("failed to dial %s: %v", peetAddress, err)
	}
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

	capturing := &capturingConn{Conn: conn}

	spec := specFn()
	forceHTTP1Only(spec)

	uconn := tls.UClient(capturing, &tls.Config{
		ServerName:         "tls.peet.ws",
		InsecureSkipVerify: true,
		NextProtos:         []string{"http/1.1"},
	}, tls.HelloCustom)
	if err := uconn.ApplyPreset(spec); err != nil {
		t.Fatalf("ApplyPreset: %v", err)
	}
	if err := uconn.Handshake(); err != nil {
		t.Fatalf("handshake: %v", err)
	}

	request := "GET /api/all HTTP/1.1\r\n" +
		"Host: tls.peet.ws\r\n" +
		"Accept: application/json\r\n" +
		"User-Agent: " + testChromeUA + "\r\n" +
		"Connection: close\r\n\r\n"
	if _, err := uconn.Write([]byte(request)); err != nil {
		t.Fatalf("request write: %v", err)
	}

	responseBytes, err := io.ReadAll(uconn)
	if err != nil && len(responseBytes) == 0 {
		t.Fatalf("response read: %v", err)
	}

	body := extractHTTPBody(t, responseBytes)

	var observed peetResponse
	if err := json.Unmarshal(body, &observed); err != nil {
		t.Fatalf("failed to parse peet response: %v\nbody: %s", err, body)
	}

	record := capturing.firstRecord()
	if len(record) == 0 {
		t.Fatal("no client hello captured")
	}
	return record, observed
}

// forceHTTP1Only rewrites the ALPN extension to http/1.1 so the response can
// be read with a plain HTTP/1.1 request. Both Peet and the local parser see
// the same modified hello, so the fingerprint comparison stays valid.
func forceHTTP1Only(spec *tls.ClientHelloSpec) {
	for _, extension := range spec.Extensions {
		if alpn, ok := extension.(*tls.ALPNExtension); ok {
			alpn.AlpnProtocols = []string{"http/1.1"}
		}
	}
}

// capturingConn records the first complete TLS record written by the client.
type capturingConn struct {
	net.Conn

	mu       sync.Mutex
	buffer   []byte
	captured bool
}

func (c *capturingConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	if !c.captured {
		c.buffer = append(c.buffer, b...)
		if len(c.buffer) >= 5 {
			length := int(c.buffer[3])<<8 | int(c.buffer[4])
			if len(c.buffer) >= 5+length {
				c.captured = true
			}
		}
	}
	c.mu.Unlock()
	return c.Conn.Write(b)
}

func (c *capturingConn) firstRecord() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.buffer) < 5 {
		return nil
	}
	length := int(c.buffer[3])<<8 | int(c.buffer[4])
	if len(c.buffer) < 5+length {
		return nil
	}
	return append([]byte(nil), c.buffer[:5+length]...)
}

func extractHTTPBody(t *testing.T, response []byte) []byte {
	t.Helper()

	index := bytes.Index(response, []byte("\r\n\r\n"))
	if index < 0 {
		t.Fatalf("no header terminator in response: %q", truncateForLog(response))
	}

	header := string(response[:index])
	body := response[index+4:]
	if strings.Contains(strings.ToLower(header), "transfer-encoding: chunked") {
		decoded, err := decodeChunked(body)
		if err != nil {
			t.Fatalf("failed to decode chunked response: %v", err)
		}
		body = decoded
	}
	return body
}

func decodeChunked(data []byte) ([]byte, error) {
	var out bytes.Buffer
	reader := bufio.NewReader(bytes.NewReader(data))
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return nil, err
		}
		sizeField := strings.TrimRight(line, "\r\n")
		if semi := strings.IndexByte(sizeField, ';'); semi >= 0 {
			sizeField = sizeField[:semi]
		}
		size, err := strconv.ParseUint(sizeField, 16, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid chunk size %q: %w", sizeField, err)
		}
		if size == 0 {
			return out.Bytes(), nil
		}
		chunk := make([]byte, size)
		if _, err := io.ReadFull(reader, chunk); err != nil {
			return nil, err
		}
		out.Write(chunk)
		if _, err := reader.ReadString('\n'); err != nil {
			return nil, err
		}
	}
}

func truncateForLog(b []byte) string {
	const limit = 400
	if len(b) <= limit {
		return string(b)
	}
	return string(b[:limit]) + "..."
}
