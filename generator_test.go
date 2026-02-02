package masktunnel

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestCertFilesPersistCA(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "cert.pem")
	keyFile := filepath.Join(dir, "key.pem")

	cm1, err := NewCertManagerFromFiles(certFile, keyFile)
	if err != nil {
		t.Fatalf("failed to create cert manager: %v", err)
	}
	ca1 := cm1.GetCACertPEM()
	if len(ca1) == 0 {
		t.Fatalf("expected non-empty CA pem")
	}
	if _, err := os.Stat(certFile); err != nil {
		t.Fatalf("expected cert file to exist: %v", err)
	}
	if _, err := os.Stat(keyFile); err != nil {
		t.Fatalf("expected key file to exist: %v", err)
	}

	cm2, err := NewCertManagerFromFiles(certFile, keyFile)
	if err != nil {
		t.Fatalf("failed to reload cert manager: %v", err)
	}
	ca2 := cm2.GetCACertPEM()

	if !bytes.Equal(ca1, ca2) {
		t.Fatalf("expected CA to persist across restarts")
	}
}

func TestNewCertManagerFromFilesRequiresBothPaths(t *testing.T) {
	_, err := NewCertManagerFromFiles("", "")
	if err == nil {
		t.Fatalf("expected error when both paths are empty")
	}

	_, err = NewCertManagerFromFiles("/tmp/cert.pem", "")
	if err == nil {
		t.Fatalf("expected error when key path is empty")
	}

	_, err = NewCertManagerFromFiles("", "/tmp/key.pem")
	if err == nil {
		t.Fatalf("expected error when cert path is empty")
	}
}
