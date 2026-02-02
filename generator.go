package masktunnel

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// CertManager manages certificate generation for MITM
type CertManager struct {
	caCert *x509.Certificate
	caKey  *rsa.PrivateKey
	cache  map[string]*tls.Certificate
	mu     sync.RWMutex
}

// NewCertManager creates a new certificate manager
func NewCertManager() (*CertManager, error) {
	cm := &CertManager{
		cache: make(map[string]*tls.Certificate),
	}

	err := cm.generateCA()
	if err != nil {
		return nil, err
	}

	return cm, nil
}

// NewCertManagerFromFiles creates a certificate manager and loads the CA
// certificate/key from disk when possible. If files are missing, it generates
// a new CA and persists it to the provided paths.
func NewCertManagerFromFiles(certFile, keyFile string) (*CertManager, error) {
	cm := &CertManager{
		cache: make(map[string]*tls.Certificate),
	}

	if certFile == "" || keyFile == "" {
		return nil, errors.New("cert file and key file must both be provided")
	}

	if err := cm.loadCAFromFiles(certFile, keyFile); err == nil {
		return cm, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	if err := cm.generateCA(); err != nil {
		return nil, err
	}
	if err := cm.saveCAToFiles(certFile, keyFile); err != nil {
		return nil, err
	}

	return cm, nil
}

// generateCA generates a CA certificate and key
func (cm *CertManager) generateCA() error {
	// Generate CA private key
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	// Create CA certificate template
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:  []string{"MaskTunnel CA"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{""},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	// Generate CA certificate
	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return err
	}

	// Parse CA certificate
	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		return err
	}

	cm.caCert = caCert
	cm.caKey = caKey

	return nil
}

func (cm *CertManager) loadCAFromFiles(certFile, keyFile string) error {
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return err
	}
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return err
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return errors.New("failed to decode CA certificate PEM")
	}
	caCert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return err
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return errors.New("failed to decode CA private key PEM")
	}

	var caKey *rsa.PrivateKey
	switch keyBlock.Type {
	case "RSA PRIVATE KEY":
		k, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
		if err != nil {
			return err
		}
		caKey = k
	case "PRIVATE KEY":
		kAny, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if err != nil {
			return err
		}
		k, ok := kAny.(*rsa.PrivateKey)
		if !ok {
			return errors.New("unsupported CA private key type")
		}
		caKey = k
	default:
		return errors.New("unsupported CA private key PEM type")
	}

	cm.caCert = caCert
	cm.caKey = caKey
	return nil
}

func (cm *CertManager) saveCAToFiles(certFile, keyFile string) error {
	if cm == nil || cm.caCert == nil || cm.caKey == nil {
		return errors.New("CA not initialized")
	}

	if err := os.MkdirAll(filepath.Dir(certFile), 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(keyFile), 0o755); err != nil {
		return err
	}

	certOut := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cm.caCert.Raw})
	keyOut := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(cm.caKey)})

	if err := os.WriteFile(certFile, certOut, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(keyFile, keyOut, 0o600); err != nil {
		return err
	}

	return nil
}

// GetCertificate returns a certificate for the given hostname
func (cm *CertManager) GetCertificate(hostname string) (*tls.Certificate, error) {
	cm.mu.RLock()
	if cert, exists := cm.cache[hostname]; exists {
		cm.mu.RUnlock()
		return cert, nil
	}
	cm.mu.RUnlock()

	cm.mu.Lock()
	defer cm.mu.Unlock()

	// Double check
	if cert, exists := cm.cache[hostname]; exists {
		return cert, nil
	}

	// Generate new certificate
	cert, err := cm.generateCertificate(hostname)
	if err != nil {
		return nil, err
	}

	cm.cache[hostname] = cert
	return cert, nil
}

// generateCertificate generates a certificate for the given hostname
func (cm *CertManager) generateCertificate(hostname string) (*tls.Certificate, error) {
	// Generate private key for the certificate
	certKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	// Create certificate template
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			Organization: []string{"MaskTunnel"},
			CommonName:   hostname,
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(1, 0, 0),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{},
		DNSNames:    []string{hostname},
	}

	// Add IP if hostname is an IP address
	if ip := net.ParseIP(hostname); ip != nil {
		template.IPAddresses = append(template.IPAddresses, ip)
	}

	// Generate certificate
	certDER, err := x509.CreateCertificate(rand.Reader, template, cm.caCert, &certKey.PublicKey, cm.caKey)
	if err != nil {
		return nil, err
	}

	// Create TLS certificate
	cert := &tls.Certificate{
		Certificate: [][]byte{certDER, cm.caCert.Raw},
		PrivateKey:  certKey,
	}

	return cert, nil
}

// GetCACert returns the DER-encoded CA certificate bytes.
func (cm *CertManager) GetCACert() []byte {
	if cm == nil || cm.caCert == nil {
		return nil
	}
	return cm.caCert.Raw
}

// GetCACertDER returns the DER-encoded CA certificate bytes.
func (cm *CertManager) GetCACertDER() []byte {
	return cm.GetCACert()
}

// GetCACertPEM returns the PEM-encoded CA certificate.
func (cm *CertManager) GetCACertPEM() []byte {
	if cm == nil || cm.caCert == nil {
		return nil
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cm.caCert.Raw})
}
