package masktunnel

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
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

// GetCACert returns the CA certificate in PEM format
func (cm *CertManager) GetCACert() []byte {
	return cm.caCert.Raw
}
