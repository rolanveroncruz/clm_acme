package http01

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
)

func ExtractPemContents(filePath string) (*x509.Certificate, error) {
	// 1. Read the file content
	certPEM, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file:: %w", err)
	}

	// 2. Decode the PEM block
	// The Decode function returns the next PEM encoded block found in the data.
	// We only expect one block for a single certificate file.
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("failed to find a valid PEM certificate block")
	}

	// 3. Parse the DER-encoded certificate
	// The decoded bytes (block.Bytes) are the DER format of the X.509 certificate.
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}
	return cert, nil
}

func PrintCertInfo(cert *x509.Certificate) {
	log.Printf("Issuer: %s", cert.Issuer)
	log.Printf("Subject: %s", cert.Subject)
	log.Printf("Not Before: %s", cert.NotBefore)
	log.Printf("Not After: %s", cert.NotAfter)
}

// IsValidPrivateKey checks if a PEM file contains a parsable private key.
func IsValidPrivateKey(filePath string) error {
	// 1. Read the file content
	keyPEM, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read file:: %w", err)
	}

	// 2. Decode the PEM block
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return fmt.Errorf("failed to find a valid PEM private key block")
	}

	// NOTE: A private key PEM block can be labeled "PRIVATE KEY", 'RSA PRIVATE KEY', or 'EC PRIVATE KEY'.

	// 3.Attempt to parse the key
	var parseErrors []error

	// Try parsing as PKCS#8 (a common, general private key format)
	if _, err := x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
		return nil // Success! (Modern format: RSA, EC, etc.)
	} else {
		parseErrors = append(parseErrors, fmt.Errorf("PKCS#8 parse error: %w", err))
	}

	// Try parsing as PKCS#1 RSA  (Traditional format: 'RSA PRIVATE KEY')
	if _, err := x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
		return nil // Success!!!! (Traditional RSA format)
	} else {
		parseErrors = append(parseErrors, fmt.Errorf("PKCS#1 (RSA) parse error: %w", err))
	}
	// Try parsing as EC Private KEY (Traditional format: 'EC PRIVATE KEY')
	if _, err := x509.ParseECPrivateKey(block.Bytes); err != nil {
		return nil // Success!!!! (EC format)
	} else {
		parseErrors = append(parseErrors, fmt.Errorf("EC parse error: %w", err))
	}

	return fmt.Errorf("failed to parse private key: %v", parseErrors)
}
