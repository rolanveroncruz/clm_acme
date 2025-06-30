package http01

import (
	"fmt"
	"testing"
)

func Test_GetAuthString(t *testing.T) {
	authString, err := GetAuthString("rolanvc.dev", "flash")
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(authString)
}

func Test_LoginAndUpload(t *testing.T) {
	host := "localhost"
	port := ":5002"
	hostAndPort := host + port
	_, loginErr := Login(hostAndPort)
	if loginErr != nil {
		return
	}
	certFile := "../certs/rolanvc.dev-cert.pem"
	err01 := UploadFileToClient(hostAndPort, certFile)
	if err01 != nil {
		fmt.Printf("Error uploading %s:%s\n", certFile, err01)
	}
	pkFile := "../certs/rolanvc.dev-private_key.pem"
	err02 := UploadFileToClient(hostAndPort, pkFile)
	if err02 != nil {
		fmt.Printf("Error uploading %s:%s\n", certFile, err02)

	}
	cacertFile := "../certs/rolanvc.dev-cacert.pem"
	err03 := UploadFileToClient(hostAndPort, cacertFile)
	if err03 != nil {
		fmt.Printf("Error uploading %s:%s\n", certFile, err03)
	}

}
