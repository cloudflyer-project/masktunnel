package masktunnel

import (
	"bytes"
	"regexp"
	"strings"

	"github.com/cristalhq/base64"
)

// PayloadInjector handles JavaScript payload injection into responses
type PayloadInjector struct {
	payload string
}

// NewPayloadInjector creates a new payload injector
func NewPayloadInjector(payload string) *PayloadInjector {
	return &PayloadInjector{
		payload: payload,
	}
}

// InjectIntoResponse injects payload into HTTP response based on content type
func (p *PayloadInjector) InjectIntoResponse(body []byte, contentType string) []byte {
	if p.payload == "" {
		return body
	}

	// Handle JavaScript responses
	if p.isJavaScriptContent(contentType) {
		return p.injectIntoJavaScript(body)
	}

	// Handle HTML responses
	if p.isHTMLContent(contentType) {
		return p.injectIntoHTML(body)
	}

	return body
}

// isJavaScriptContent checks if content type is JavaScript
func (p *PayloadInjector) isJavaScriptContent(contentType string) bool {
	jsTypes := []string{
		"application/javascript",
		"application/x-javascript",
		"text/javascript",
		"text/x-javascript",
	}

	contentType = strings.ToLower(contentType)
	for _, jsType := range jsTypes {
		if strings.Contains(contentType, jsType) {
			return true
		}
	}
	return false
}

// isHTMLContent checks if content type is HTML
func (p *PayloadInjector) isHTMLContent(contentType string) bool {
	return strings.Contains(strings.ToLower(contentType), "text/html")
}

// injectIntoJavaScript prepends payload to JavaScript content
func (p *PayloadInjector) injectIntoJavaScript(body []byte) []byte {
	if len(body) == 0 {
		return body
	}

	// Prepend payload to JavaScript
	result := make([]byte, 0, len(p.payload)+len(body))
	result = append(result, []byte(p.payload)...)
	result = append(result, body...)

	return result
}

// injectIntoHTML injects payload into HTML, particularly base64 encoded JavaScript
func (p *PayloadInjector) injectIntoHTML(body []byte) []byte {
	if len(body) == 0 {
		return body
	}

	bodyStr := string(body)

	// Build a simple <script> wrapper for the payload
	script := "<script>" + p.payload + "</script>"

	lower := strings.ToLower(bodyStr)
	// Prefer injecting before </head>
	if idx := strings.Index(lower, "</head>"); idx != -1 {
		prefix := bodyStr[:idx]
		suffix := bodyStr[idx:]
		bodyStr = prefix + script + suffix
	} else if idx := strings.Index(lower, "</body>"); idx != -1 {
		prefix := bodyStr[:idx]
		suffix := bodyStr[idx:]
		bodyStr = prefix + script + suffix
	} else {
		// Fallback: append at end
		bodyStr += script
	}

	// Also try to modify base64 data:javascript if any
	bodyStr = p.injectIntoBase64Scripts(bodyStr)

	return []byte(bodyStr)
}

// injectIntoBase64Scripts injects payload into base64 encoded JavaScript in data URIs
func (p *PayloadInjector) injectIntoBase64Scripts(html string) string {
	// Regex to match base64 encoded JavaScript in data URIs
	base64JSRegex := regexp.MustCompile(`data:application/javascript;base64,([A-Za-z0-9+/=]+)`)

	return base64JSRegex.ReplaceAllStringFunc(html, func(match string) string {
		// Extract the base64 part
		parts := strings.Split(match, ",")
		if len(parts) != 2 {
			return match
		}

		// Decode base64
		decoded, err := base64.StdEncoding.DecodeString(parts[1])
		if err != nil {
			return match
		}

		// Inject payload
		injected := p.payload + string(decoded)

		// Re-encode to base64
		reencoded := base64.StdEncoding.EncodeToString([]byte(injected))

		return "data:application/javascript;base64," + reencoded
	})
}

// ShouldInject checks if payload should be injected based on content type
func (p *PayloadInjector) ShouldInject(contentType string) bool {
	if p.payload == "" {
		return false
	}

	return p.isJavaScriptContent(contentType) || p.isHTMLContent(contentType)
}

// PrependToBuffer prepends payload to buffer for streaming responses
func (p *PayloadInjector) PrependToBuffer(buf *bytes.Buffer, contentType string) {
	if p.payload == "" || !p.isJavaScriptContent(contentType) {
		return
	}

	// Create new buffer with payload prepended
	newBuf := bytes.NewBuffer(make([]byte, 0, len(p.payload)+buf.Len()))
	newBuf.WriteString(p.payload)
	newBuf.Write(buf.Bytes())

	// Replace original buffer content
	buf.Reset()
	buf.Write(newBuf.Bytes())
}
