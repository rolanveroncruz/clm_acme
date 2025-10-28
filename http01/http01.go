/*
In this file we provide a Provider interface for the Htp01 test.
*/

package http01

import (
	"fmt"
	"log"
	"time"
)

type Provider interface {
	Present(domain, token, keyAuth string) error
	CleanUp(domain, token, keyAuth string) error
}

type ProviderHttp01RolanvcDev struct {
	Host string
	Port string
}

func NewProviderHttp01RolanvcDev(host string, port string) (*ProviderHttp01RolanvcDev, error) {
	return &ProviderHttp01RolanvcDev{Host: host, Port: port}, nil
}

// Present with parameters domain, token, and keyAuth is called by Lego to instruct the solver to make the
// key authorization available at the correct URL on the domain server.
func (p *ProviderHttp01RolanvcDev) Present(domain, token, keyAuth string) error {
	hostAndPort := p.Host + p.Port

	// Step 1. Login
	log.Printf("Attempting Login at %s", hostAndPort)
	jwtToken, err := Login(hostAndPort)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Login Successful")

	// Step 2. PutPair
	log.Println("Attempting PutPair")
	putPairErr := PutPair(hostAndPort, jwtToken, token, keyAuth)
	if putPairErr != nil {
		log.Fatal(putPairErr)
	}
	log.Println("PutPair Successful")
	log.Println("Sleeping for 2 seconds")
	time.Sleep(2 * time.Second)

	// Step 3. Check it is accessible.
	log.Println("Checking HTTP-01 Challenge")
	authStr01, getAuthErr := GetAuthString(p.Host, token)
	if getAuthErr != nil {
		log.Fatal(getAuthErr)
	}
	if keyAuth != authStr01 {
		return fmt.Errorf("KeyAuth does not match Auth String\n")
	}
	log.Printf("*** KeyAuth matches Auth String ***\n")
	return nil

}

// CleanUp is called by Lego to remove the key authorization after the challenge is completed.
func (p *ProviderHttp01RolanvcDev) CleanUp(domain, token, keyAuth string) error {
	return nil
}
