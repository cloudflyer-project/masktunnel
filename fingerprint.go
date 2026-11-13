package masktunnel

import (
	"bytes"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/Noooste/azuretls-client"
	tls "github.com/Noooste/utls"
	"github.com/gaukas/clienthellod"
)

// FingerprintReport describes the client fingerprints MaskTunnel applies for
// a given User-Agent: the JA3/JA4 of the ClientHello it sends and the
// HTTP/2 (Akamai) fingerprint it applies to outgoing connections.
type FingerprintReport struct {
	UserAgent         string
	Browser           string
	TLSProfile        string
	JA3               string
	JA3Hash           string
	JA4               string
	AkamaiFingerprint string
	AkamaiHash        string
}

// reportServerName is the SNI used when building a ClientHello for
// reporting. The value only has to be a syntactically valid hostname; the
// underlying fingerprint does not depend on which domain it names.
const reportServerName = "example.com"

// GetFingerprintReport computes the fingerprints for the given User-Agent.
// It performs no network I/O: the ClientHello is built locally with the
// same utls preset the proxy uses for real connections. Unparseable
// User-Agents fall back to the default Chrome fingerprint, mirroring how
// sessions are created for real traffic.
func GetFingerprintReport(userAgent string) (*FingerprintReport, error) {
	browserFingerprint, err := GetBrowserFingerprint(userAgent)
	if err != nil {
		browserFingerprint = defaultBrowserFingerprint()
	}

	record, err := buildClientHelloRecord(browserClientHelloSpec(browserFingerprint.Browser))
	if err != nil {
		return nil, err
	}

	clientHello, err := parseClientHelloRecord(record)
	if err != nil {
		return nil, err
	}

	ja3 := ja3Of(clientHello)
	akamai := akamaiFromHTTP2Fingerprint(browserFingerprint.HTTP2Fingerprint)

	return &FingerprintReport{
		UserAgent:         userAgent,
		Browser:           browserFingerprint.Browser,
		TLSProfile:        browserFingerprint.TLSProfile,
		JA3:               ja3,
		JA3Hash:           md5Hex(ja3),
		JA4:               ja4Of(clientHello),
		AkamaiFingerprint: akamai,
		AkamaiHash:        md5Hex(akamai),
	}, nil
}

// GetFingerprintReportJSON returns GetFingerprintReport as a JSON string.
func GetFingerprintReportJSON(userAgent string) (string, error) {
	report, err := GetFingerprintReport(userAgent)
	if err != nil {
		return "", err
	}
	b, err := json.Marshal(report)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// defaultBrowserFingerprint is the fallback used when a User-Agent cannot be
// parsed. Sessions for real traffic use the same fallback.
func defaultBrowserFingerprint() *BrowserFingerprint {
	return &BrowserFingerprint{
		Browser:          "Chrome",
		HTTP2Fingerprint: "1:65536,2:0,4:6291456,6:262144|15663105|0|m,s,a,p",
		TLSProfile:       "133",
	}
}

// browserClientHelloSpec returns the ClientHello generator used for a
// browser name, mirroring the mapping in Manager.configureTLSFingerprint.
func browserClientHelloSpec(browser string) func() *tls.ClientHelloSpec {
	switch browser {
	case "Firefox":
		return azuretls.GetLastFirefoxVersion
	case "Safari":
		return azuretls.GetLastSafariVersion
	case "iOS":
		return azuretls.GetLastIosVersion
	default:
		return azuretls.GetLastChromeVersion
	}
}

// azuretlsBrowserConstant maps a browser name to the azuretls browser
// constant used for sessions.
func azuretlsBrowserConstant(browser string) string {
	switch browser {
	case "Firefox":
		return azuretls.Firefox
	case "Safari":
		return azuretls.Safari
	case "Edge":
		return azuretls.Edge
	case "iOS":
		return azuretls.Ios
	default:
		return azuretls.Chrome
	}
}

// stubConn is a no-op net.Conn. Building a ClientHello never performs I/O.
type stubConn struct{}

func (stubConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (stubConn) Write(b []byte) (int, error)      { return len(b), nil }
func (stubConn) Close() error                     { return nil }
func (stubConn) LocalAddr() net.Addr              { return nil }
func (stubConn) RemoteAddr() net.Addr             { return nil }
func (stubConn) SetDeadline(time.Time) error      { return nil }
func (stubConn) SetReadDeadline(time.Time) error  { return nil }
func (stubConn) SetWriteDeadline(time.Time) error { return nil }

// buildClientHelloRecord builds the TLS record carrying the ClientHello for
// the given spec generator: a 5-byte record header followed by the
// handshake message, exactly as it would be sent on the wire.
func buildClientHelloRecord(specFn func() *tls.ClientHelloSpec) ([]byte, error) {
	uconn := tls.UClient(stubConn{}, &tls.Config{ServerName: reportServerName}, tls.HelloCustom)
	if err := uconn.ApplyPreset(specFn()); err != nil {
		return nil, fmt.Errorf("failed to apply hello spec: %w", err)
	}
	if err := uconn.BuildHandshakeState(); err != nil {
		return nil, fmt.Errorf("failed to build handshake state: %w", err)
	}
	raw := uconn.HandshakeState.Hello.Raw
	if len(raw) == 0 {
		return nil, fmt.Errorf("built an empty client hello")
	}
	record := make([]byte, 0, len(raw)+5)
	record = append(record, 0x16, 0x03, 0x01, byte(len(raw)>>8), byte(len(raw)))
	record = append(record, raw...)
	return record, nil
}

// parseClientHelloRecord parses a TLS record into a parsed ClientHello.
func parseClientHelloRecord(record []byte) (*clienthellod.ClientHello, error) {
	clientHello, err := clienthellod.ReadClientHello(bytes.NewReader(record))
	if err != nil {
		return nil, fmt.Errorf("failed to read client hello: %w", err)
	}
	if err := clientHello.ParseClientHello(); err != nil {
		return nil, fmt.Errorf("failed to parse client hello: %w", err)
	}
	return clientHello, nil
}

// ja3Of computes the JA3 text of a parsed ClientHello. GREASE values are
// excluded, matching passive fingerprint services like tls.peet.ws.
func ja3Of(clientHello *clienthellod.ClientHello) string {
	return fmt.Sprintf("%d,%s,%s,%s,%s",
		clientHello.TLSHandshakeVersion,
		joinUint16(filterGREASE(clientHello.CipherSuites), "-"),
		joinUint16(filterGREASE(clientHello.Extensions), "-"),
		joinUint16(filterGREASE(clientHello.NamedGroupList), "-"),
		joinUint8(clientHello.ECPointFormatList, "-"),
	)
}

// ja4Of computes the JA4 fingerprint of a parsed ClientHello.
func ja4Of(clientHello *clienthellod.ClientHello) string {
	ciphers := filterGREASE(clientHello.CipherSuites)
	extensions := filterGREASE(clientHello.Extensions)

	sni := "i"
	if containsUint16(extensions, 0x0000) {
		sni = "d"
	}

	cipherHash := hashHex12(hexListSorted(ciphers))
	extensionHash := hashHex12(ja4ExtensionString(extensions, clientHello.SignatureSchemeList))

	return fmt.Sprintf("t%s%s%02d%02d%s_%s_%s",
		ja4Version(clientHello),
		sni,
		minInt(len(ciphers), 99),
		minInt(len(extensions), 99),
		ja4ALPN(clientHello.ALPN),
		cipherHash,
		extensionHash,
	)
}

// ja4Version returns the JA4 TLS version code: the highest supported_versions
// value (GREASE excluded), falling back to the ClientHello version field.
func ja4Version(clientHello *clienthellod.ClientHello) string {
	var version uint16
	for _, candidate := range clientHello.SupportedVersions {
		if isGREASE(candidate) {
			continue
		}
		if candidate > version {
			version = candidate
		}
	}
	if version == 0 {
		version = clientHello.TLSHandshakeVersion
	}

	switch version {
	case tls.VersionTLS13:
		return "13"
	case tls.VersionTLS12:
		return "12"
	case tls.VersionTLS11:
		return "11"
	case tls.VersionTLS10:
		return "10"
	case 0x0300:
		return "s3"
	case 0x0002:
		return "s2"
	case 0xfeff:
		return "d1"
	case 0xfefd:
		return "d2"
	case 0xfefc:
		return "d3"
	default:
		return "00"
	}
}

// ja4ALPN returns the two ALPN characters used by JA4: the first and last
// ASCII alphanumeric characters of the first ALPN value, its hex
// representation when either character is not alphanumeric, or "00".
func ja4ALPN(alpn []string) string {
	if len(alpn) == 0 || alpn[0] == "" {
		return "00"
	}
	value := []byte(alpn[0])
	if isASCIIAlphanumeric(value[0]) && isASCIIAlphanumeric(value[len(value)-1]) {
		return string([]byte{value[0], value[len(value)-1]})
	}
	encoded := hex.EncodeToString(value)
	return string([]byte{encoded[0], encoded[len(encoded)-1]})
}

// ja4ExtensionString builds the pre-hash string for the JA4 extension hash:
// sorted extension codes without SNI and ALPN, followed by the signature
// algorithms in their original order.
func ja4ExtensionString(extensions []uint16, signatureAlgorithms []uint16) string {
	list := make([]uint16, 0, len(extensions))
	for _, extension := range extensions {
		if extension == 0x0000 || extension == 0x0010 {
			continue
		}
		list = append(list, extension)
	}
	if len(list) == 0 {
		return ""
	}

	parts := []string{hexListSorted(list)}
	if signatures := filterGREASE(signatureAlgorithms); len(signatures) > 0 {
		parts = append(parts, joinUint16Hex(signatures, ","))
	}
	return strings.Join(parts, "_")
}

// akamaiFromHTTP2Fingerprint converts the azuretls HTTP/2 fingerprint form
// ("1:65536,2:0|window|priority|order") into the semicolon-separated form
// used by passive fingerprint APIs.
func akamaiFromHTTP2Fingerprint(fingerprint string) string {
	parts := strings.Split(fingerprint, "|")
	if len(parts) != 4 {
		return fingerprint
	}
	parts[0] = strings.ReplaceAll(parts[0], ",", ";")
	return strings.Join(parts, "|")
}

// isGREASE reports whether a 16-bit TLS value is a GREASE reserved value.
func isGREASE(value uint16) bool {
	return (value>>8) == value&0xff && value&0xf == 0xa
}

func filterGREASE(values []uint16) []uint16 {
	filtered := make([]uint16, 0, len(values))
	for _, value := range values {
		if !isGREASE(value) {
			filtered = append(filtered, value)
		}
	}
	return filtered
}

func containsUint16(values []uint16, target uint16) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

// hexListSorted renders values as 4-digit lowercase hex codes joined by
// commas, sorted as strings (equivalent to hex order).
func hexListSorted(values []uint16) string {
	codes := make([]string, 0, len(values))
	for _, value := range values {
		codes = append(codes, fmt.Sprintf("%04x", value))
	}
	sort.Strings(codes)
	return strings.Join(codes, ",")
}

func joinUint16Hex(values []uint16, separator string) string {
	codes := make([]string, 0, len(values))
	for _, value := range values {
		codes = append(codes, fmt.Sprintf("%04x", value))
	}
	return strings.Join(codes, separator)
}

func joinUint16(values []uint16, separator string) string {
	parts := make([]string, 0, len(values))
	for _, value := range values {
		parts = append(parts, fmt.Sprintf("%d", value))
	}
	return strings.Join(parts, separator)
}

func joinUint8(values []uint8, separator string) string {
	parts := make([]string, 0, len(values))
	for _, value := range values {
		parts = append(parts, fmt.Sprintf("%d", value))
	}
	return strings.Join(parts, separator)
}

func isASCIIAlphanumeric(b byte) bool {
	return b >= '0' && b <= '9' || b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z'
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// hashHex12 returns the first 12 lowercase hex characters of the SHA-256 of
// s, or "000000000000" when s is empty (JA4 convention for empty lists).
func hashHex12(s string) string {
	if s == "" {
		return "000000000000"
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}

func md5Hex(s string) string {
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}
