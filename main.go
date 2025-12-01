package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"log"
	"os"

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
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate prvate key: %w", err)
	}
	return &MyUser{
		Email: email,
		key:   privateKey,
	}, nil
}

func main() {
	const GsApiKey = "097800373d35ad9a"
	const GsSecret = "3d857f0945ea94ff4e99c71634de94b8f3ae78ed"
	const AcmeEmailAcct = "rolanvc@certs.com.ph"
	const AcmeDirGs = "https://emea.acme.atlas.globalsign.com/directory"
	//const AcmeDirLetsEncrypt = "https://acme-staging-v02.api.letsencrypt.org/directory"
	const AcmeHmacKey = "Cp8CvFsCZGRESO83wuC7CrvAPA75XGVMVHRicKiI75KmcIz9H_6-OYXxsnzaRzkmtvxQRPL8cG2KDz4k5wZkkwmNBLBAavSWxMbL9QE0LRjn_Pb7UV1YYsKCtl0c-Sk_xELLrj31ypJmS_4YgCiI60LOEr6Ev5sALrcikD3v_II"
	const AcmeKeyId = "097800373d35ad9a"
	// Create a user. New accounts need an email and private key to start.

	log.Println("Starting ACME account registration with EAB...")

	// 1. Initialize ACME User
	user, err := initUser(AcmeEmailAcct)
	if err != nil {
		log.Fatalf("Error creating user: %v", err)
	}

	// 2.Configure the client.
	config := lego.NewConfig(user)

	// This CA URL is configured for a local dev instance of Boulder running in Docker in a VM.
	// config.CADirURL = "http://192.168.99.100:4000/directory"
	///config.CADirURL = "https://acme-staging-v02.api.letsencrypt.org/directory"

	// Set the ACME CA URL.
	// The next line is for LetsEncrypt
	// config.CADirURL =
	// The next line is for GlobalSign
	config.CADirURL = AcmeDirGs
	config.Certificate.KeyType = certcrypto.RSA2048

	// 4. Create the client.
	client, err := lego.NewClient(config)
	if err != nil {
		log.Fatal(err)
	}

	// 5.Register the account with EAB
	log.Printf("Attempting to register account with EAB.")
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
	log.Printf("Account Registered.")

	// We create an http01 challenge provider which has custom behavior.
	http01Provider, err := http01.NewProviderHttp01RolanvcDev("rolanvc.dev", "")
	if err != nil {
		panic(err)
	}
	err = client.Challenge.SetHTTP01Provider(http01Provider)

	//err = client.Challenge.SetTLSALPN01Provider(tlsalpn01.NewProviderServer("", ""))
	//if err != nil {
	//	log.Fatal(err)
	//}

	/*
		log.Println("Calling client.Registration.Register.")
		reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			log.Fatal(err)
		}
	*/
	user.Registration = reg

	// Step 2.
	log.Println("Calling certificate.ObtainRequest.")
	request := certificate.ObtainRequest{
		Domains: []string{"rolanvc.dev"},
		Bundle:  true,
	}
	// Step 3.
	log.Println("Retrieving certificate(s).")
	certificates, err := client.Certificate.Obtain(request)
	if err != nil {
		log.Fatal(err)
	}

	// Each certificate comes back with the cert bytes, the bytes of the client's
	// private key, and a certificate URL. SAVE THESE TO DISK.
	log.Println("Received certificate. Saving component files to file.")
	log.Printf("Saving Private Key as certs/%s-private_key.pem", certificates.Domain)
	privateKeyFile := fmt.Sprintf("certs/%s-private_key.pem", certificates.Domain)
	pkErr := os.WriteFile(privateKeyFile, certificates.PrivateKey, 0644)
	if pkErr != nil {
		log.Printf("Error Saving File: %s", pkErr)
	}
	err = http01.IsValidPrivateKey(privateKeyFile)
	if err != nil {
		log.Printf("Error Validating Private Key: %s", err)
		return
	}

	log.Printf("Saving Certificate File as certs/%s-cert.pem\n", certificates.Domain)
	certFile := fmt.Sprintf("certs/%s-cert.pem", certificates.Domain)
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

	log.Printf("Saving Issuer's Certificate File as certs/%s-ca_cert.pem", certificates.Domain)
	caCertFile := fmt.Sprintf("certs/%s-ca_cert.pem", certificates.Domain)
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

	log.Printf("Trying to upload Files...")

	/*
		uploadErr := http01.UploadFileToClient(http01Provider.Host+http01Provider.Port, privateKeyFile)
		if uploadErr != nil {
			return
		}
		uploadErr = http01.UploadFileToClient(http01Provider.Host+http01Provider.Port, certFile)
		if uploadErr != nil {
			return
		}
		uploadErr = http01.UploadFileToClient(http01Provider.Host+http01Provider.Port, caCertFile)
		if uploadErr != nil {
			return
		}
	*/

}
