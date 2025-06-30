package http01

import (
	"fmt"
	"log"
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

func (p *ProviderHttp01RolanvcDev) Present(domain, token, keyAuth string) error {
	hostAndPort := p.Host + p.Port
	jwtToken, err := Login(hostAndPort)
	if err != nil {
		log.Fatal(err)
	}
	putPairErr := PutPair(hostAndPort, jwtToken, token, keyAuth)
	if putPairErr != nil {
		log.Fatal(putPairErr)
	}
	authStr01, getAuthErr := GetAuthString(p.Host, token)
	if getAuthErr != nil {
		log.Fatal(getAuthErr)
	}
	fmt.Printf("Token: %s\n", token)
	fmt.Printf("Key Auth: %s\n", keyAuth)
	fmt.Printf("Auth String: %s\n", authStr01)
	if keyAuth != authStr01 {
		return fmt.Errorf("KeyAuth does not match Auth String\n")
	}
	fmt.Printf("KeyAuth matches Auth String\n")
	return nil

}

func (p *ProviderHttp01RolanvcDev) CleanUp(domain, token, keyAuth string) error {
	return nil
}
