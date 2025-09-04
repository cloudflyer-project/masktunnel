package masktunnel

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"fmt"
	"io"
	"strings"

	"github.com/andybalholm/brotli"
)

// parseContentEncodings parses a Content-Encoding header into a normalized slice.
func parseContentEncodings(header string) []string {
	if header == "" {
		return nil
	}
	parts := strings.Split(header, ",")
	encs := make([]string, 0, len(parts))
	for _, p := range parts {
		e := strings.ToLower(strings.TrimSpace(p))
		if e != "" {
			encs = append(encs, e)
		}
	}
	return encs
}

func decodeOnce(encoding string, data []byte) ([]byte, error) {
	switch encoding {
	case "identity", "none":
		return data, nil
	case "gzip":
		gr, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		defer gr.Close()
		var buf bytes.Buffer
		if _, err := io.Copy(&buf, gr); err != nil {
			return nil, err
		}
		return buf.Bytes(), nil
	case "deflate":
		fr := flate.NewReader(bytes.NewReader(data))
		defer fr.Close()
		var buf bytes.Buffer
		if _, err := io.Copy(&buf, fr); err != nil {
			return nil, err
		}
		return buf.Bytes(), nil
	case "br":
		br := brotli.NewReader(bytes.NewReader(data))
		var buf bytes.Buffer
		if _, err := io.Copy(&buf, br); err != nil {
			return nil, err
		}
		return buf.Bytes(), nil
	default:
		return nil, fmt.Errorf("unsupported content-encoding: %s", encoding)
	}
}

func encodeOnce(encoding string, data []byte) ([]byte, error) {
	var buf bytes.Buffer
	switch encoding {
	case "identity", "none":
		return data, nil
	case "gzip":
		gw := gzip.NewWriter(&buf)
		if _, err := gw.Write(data); err != nil {
			_ = gw.Close()
			return nil, err
		}
		if err := gw.Close(); err != nil {
			return nil, err
		}
		return buf.Bytes(), nil
	case "deflate":
		fw, err := flate.NewWriter(&buf, flate.DefaultCompression)
		if err != nil {
			return nil, err
		}
		if _, err := fw.Write(data); err != nil {
			_ = fw.Close()
			return nil, err
		}
		if err := fw.Close(); err != nil {
			return nil, err
		}
		return buf.Bytes(), nil
	case "br":
		bw := brotli.NewWriter(&buf)
		if _, err := bw.Write(data); err != nil {
			_ = bw.Close()
			return nil, err
		}
		if err := bw.Close(); err != nil {
			return nil, err
		}
		return buf.Bytes(), nil
	default:
		return nil, fmt.Errorf("unsupported content-encoding: %s", encoding)
	}
}

// decodeWithEncodings applies decoders in reverse order (per RFC semantics).
func decodeWithEncodings(data []byte, encs []string) ([]byte, error) {
	if len(encs) == 0 {
		return data, nil
	}
	var err error
	for i := len(encs) - 1; i >= 0; i-- {
		data, err = decodeOnce(encs[i], data)
		if err != nil {
			return nil, err
		}
	}
	return data, nil
}

// encodeWithEncodings applies encoders in forward order.
func encodeWithEncodings(data []byte, encs []string) ([]byte, error) {
	if len(encs) == 0 {
		return data, nil
	}
	var err error
	for i := 0; i < len(encs); i++ {
		data, err = encodeOnce(encs[i], data)
		if err != nil {
			return nil, err
		}
	}
	return data, nil
}

// injectWithReencode safely decodes by Content-Encoding, injects payload, and re-encodes.
// Returns the processed body and whether injection was applied.
func injectWithReencode(injector *PayloadInjector, body []byte, contentType, contentEncodingHeader string) ([]byte, bool, error) {
	encs := parseContentEncodings(contentEncodingHeader)
	decoded, err := decodeWithEncodings(body, encs)
	if err != nil {
		return nil, false, err
	}
	// Perform injection on decoded body
	injected := injector.InjectIntoResponse(decoded, contentType)
	// If injector made no change, still return true as we passed through the logic
	reencoded, err := encodeWithEncodings(injected, encs)
	if err != nil {
		return nil, false, err
	}
	return reencoded, true, nil
}
