package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"os"

	"github.com/go-acme/lego/v4/providers/dns/cloudflare"
	"github.com/joho/godotenv"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
	"ph.certs.com/clm_acme/http01"
)

// MyUser implements lego/v4/registration.User interface by defining methods to
// retrieve the user's email address, registration, and private key.
type MyUser struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
}

func (u *MyUser) GetEmail() string {
	return u.Email
}
func (u *MyUser) GetRegistration() *registration.Resource {
	return u.Registration
}
func (u *MyUser) GetPrivateKey() crypto.PrivateKey {
	return u.key
}

func initUser(email string) (*MyUser, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}
	return &MyUser{
		Email: email,
		key:   privateKey,
	}, nil
}

func main() {
	loadDotenvErr := godotenv.Load()
	if loadDotenvErr != nil {
		log.Fatal("Error loading .env file")
	}

	AcmeDirGs := os.Getenv("ACME_DIR_GS")
	//const AcmeDirLetsEncrypt = "https://acme-staging-v02.api.letsencrypt.org/directory"

	// The two things below come from GS Atlas Portal ->API Credentials
	// 02-11-26acmetest MAC and key.
	AcmeHmacKey := os.Getenv("ACME_HMAC_KEY")
	AcmeKeyId := os.Getenv("ACME_KEY_ID")
	// Create a user. New accounts need an email and private key to start.

	log.Println("* Starting ACME account registration with EAB...")

	// 1. Initialize ACME User
	AcmeEmailAcct := os.Getenv("ACME_EMAIL_ACCT")
	user, err := initUser(AcmeEmailAcct)
	if err != nil {
		log.Fatalf("Error creating user: %v", err)
	}

	certPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Error creating cert private key: %v", err)
	}

	// 2.Configure the client.
	config := lego.NewConfig(user)

	config.CADirURL = AcmeDirGs
	config.Certificate.KeyType = certcrypto.RSA2048

	// 4. Create the client.
	client, err := lego.NewClient(config)
	if err != nil {
		log.Fatal(err)
	}

	// 5.Register the account with EAB
	log.Printf("** Attempting to register account with EAB.")
	eabOptions := registration.RegisterEABOptions{
		TermsOfServiceAgreed: true,
		Kid:                  AcmeKeyId,
		HmacEncoded:          AcmeHmacKey,
	}
	reg, err := client.Registration.RegisterWithExternalAccountBinding(eabOptions)
	if err != nil {
		log.Fatal(err)
	}
	user.Registration = reg
	log.Printf("*** Account Registered.")

	// 6. Prepare for the DNS Challenge.
	cfConfig := cloudflare.NewDefaultConfig()
	cfConfig.AuthToken = os.Getenv("CF_AUTH_TOKEN")
	dnsProvider, err := cloudflare.NewDNSProviderConfig(cfConfig)
	if err != nil {
		log.Fatalf("Failed to create Cloudflare DNS provider: %v", err)
	}
	err = client.Challenge.SetDNS01Provider(dnsProvider)
	if err != nil {
		log.Fatalf("Failed to set dns provider: %v", err)
	}

	// C. Use ObtainForCSRRequest instead of ObtainRequest
	log.Println("***** Saving CSR.")
	err = SaveCSRToFile("test.rolanvc.dev", certPrivateKey, "certs/test.rolanvc.dev.csr")
	if err != nil {
		log.Printf("Error Saving CSR: %s", err)
	}
	log.Println("**** Calling certificate.ObtainRequest.")
	request := certificate.ObtainRequest{
		Domains:    []string{"test.rolanvc.dev"},
		Bundle:     true,
		PrivateKey: certPrivateKey,
	}

	// D. Use ObtainForCSR instead of Obtain
	log.Println("****** calling certificate.Obtain.")
	certificates, err := client.Certificate.Obtain(request)
	if err != nil {
		log.Fatal(err)
	}

	// The above replaces the below.
	// Step 2.
	//log.Println("**** Calling certificate.ObtainRequest.")
	//request := certificate.ObtainRequest{
	//	Domains: []string{"rolanvc.dev"},
	//	Bundle:  true,
	//}
	//// Step 3.
	//log.Println("***** Retrieving certificate(s).")
	//certificates, err := client.Certificate.Obtain(request)
	//if err != nil {
	//	log.Fatal(err)
	//}

	// Each certificate comes back with the cert bytes, the bytes of the client's
	// private key, and a certificate URL. SAVE THESE TO DISK.
	log.Println("Received certificate. Saving component files to file.")
	saveFolder := "./certs"
	log.Printf("Creating Directory:%s", saveFolder)
	err = os.MkdirAll(saveFolder, 0755)
	if err != nil {
		log.Printf("Error Creating Directory: %s", err)
		return
	}

	log.Printf("Saving Private Key as %s/%s-private_key.pem", saveFolder, certificates.Domain)
	privateKeyFile := fmt.Sprintf("%s/%s-private_key.pem", saveFolder, certificates.Domain)
	pkErr := os.WriteFile(privateKeyFile, certificates.PrivateKey, 0644)
	if pkErr != nil {
		log.Printf("Error Saving File: %s", pkErr)
	}
	err = http01.IsValidPrivateKey(privateKeyFile)
	if err != nil {
		log.Printf("Error Validating Private Key: %s", err)
		return
	}

	log.Printf("Saving Certificate File as %s/%s-cert.pem\n", saveFolder, certificates.Domain)
	certFile := fmt.Sprintf("%s/%s-cert.pem", saveFolder, certificates.Domain)
	certErr := os.WriteFile(certFile, certificates.Certificate, 0644)
	if certErr != nil {
		log.Printf("Error Saving File: %s", certErr)
		return
	}
	certDetails, err := http01.ExtractPemContents(certFile)
	if err != nil {
		log.Printf("Error Extracting Certificate Details: %s", err)
	}
	http01.PrintCertInfo(certDetails)

	log.Printf("Saving Issuer's Certificate File as %s /%s-ca_cert.pem", saveFolder, certificates.Domain)
	caCertFile := fmt.Sprintf("%s/%s-ca_cert.pem", saveFolder, certificates.Domain)
	CaCertErr := os.WriteFile(caCertFile, certificates.IssuerCertificate, 0644)
	if CaCertErr != nil {
		fmt.Println(CaCertErr)
		return
	}
	caCertDetails, err := http01.ExtractPemContents(caCertFile)
	if err != nil {
		log.Printf("Error Extracting Certificate Details: %s", err)
	}
	http01.PrintCertInfo(caCertDetails)
	log.Printf("Done.\n")

}

// SaveCSRToFile generates a CSR based on the provided domain and private key,
// then saves it to a .csr file for manual inspection.
func SaveCSRToFile(domain string, privateKey crypto.PrivateKey, filePath string) error {
	// 1. Create the CSR Template
	// This mimics the basic structure Lego uses
	template := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: domain,
		},
		DNSNames: []string{domain},
	}

	// 2. Generate the CSR bytes
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, privateKey)
	if err != nil {
		return fmt.Errorf("failed to create CSR: %w", err)
	}

	// 3. PEM encode the CSR
	pemBlock := &pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrBytes,
	}

	// 4. Write to disk
	err = os.WriteFile(filePath, pem.EncodeToMemory(pemBlock), 0644)
	if err != nil {
		return fmt.Errorf("failed to write CSR to file: %w", err)
	}

	fmt.Printf("Successfully saved CSR to: %s\n", filePath)
	return nil
}
