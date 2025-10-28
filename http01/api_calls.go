/*
This file provides the api functions for the http01 test.
*/
package http01

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
)

var JWToken string

// Login logs in to hostAndPort and returns the JWT token.
func Login(hostAndPort string) (string, error) {

	type LoginResponse struct {
		Email string `json:"email"`
		Name  string `json:"name"`
		Token string `json:"token"`
	}

	loginURL := fmt.Sprintf("http://%s/acme/login", hostAndPort)
	loginData := []byte(`{"email":"admin@certs.com.ph", "password": "<PASSWORD>"}`)

	bodyReader := bytes.NewReader(loginData)
	req, err := http.NewRequest("POST", loginURL, bodyReader)
	if err != nil {
		log.Println("Error creating http request", err)
		return "", err
	}
	req.Header.Add("Content-Type", "application/json")

	client := http.DefaultClient
	response, doErr := client.Do(req)
	if doErr != nil {
		log.Println("Error doing http request", doErr)
		return "", err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			fmt.Println("Error closing body", err)
		}

	}(response.Body)
	if response.StatusCode != 200 {
		log.Println("Error response from http request", response.Status)
		return "", err
	}

	var loginResponse LoginResponse
	if err := json.NewDecoder(response.Body).Decode(&loginResponse); err != nil {
		return "", err
	}
	JWToken = loginResponse.Token
	return loginResponse.Token, nil
}

// PutPair PUTS the authString and token pair to the clm_client
func PutPair(hostAndPort string, authToken string, token string, authString string) error {
	type PutPairResponse struct {
		Status  int8   `json:"status"`
		Message string `json:"message"`
	}
	log.Printf("%s token: %s", getFunctionName(), token)
	log.Printf("%s authString: %s", getFunctionName(), authString)
	putPairURL := fmt.Sprintf("http://%s/acme/.well-known/acme-challenge/put-pair", hostAndPort)
	putPairData := []byte(fmt.Sprintf(`{"token":"%s","authstring":"%s"}`, token, authString))

	bodyReader := bytes.NewReader(putPairData)
	req, err := http.NewRequest(http.MethodPut, putPairURL, bodyReader)
	if err != nil {
		log.Printf("%s:Error creating http request:%s\n", getFunctionName(), err)
		return err
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", authToken))

	client := http.DefaultClient
	response, doErr := client.Do(req)
	if doErr != nil {
		log.Println("Error doing http request", doErr)
		return err
	}

	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			fmt.Println("Error closing body", err)
		}

	}(response.Body)

	if response.StatusCode != 200 {
		fmt.Println("Error response from http request", response.Status)
		return err
	}

	var putPairResponse PutPairResponse
	if err := json.NewDecoder(response.Body).Decode(&putPairResponse); err != nil {
		return err
	}
	if putPairResponse.Status != 0 {
		fmt.Println("Error response from http request", putPairResponse.Status)
	}
	return nil
}

// GetAuthString retrieves the authString, given the token. We use this to check it is all well.
func GetAuthString(host string, token string) (string, error) {
	getAuthStringURL := fmt.Sprintf("http://%s/.well-known/acme-challenge/%s", host, token)
	log.Printf("%s: GET '%s'\n", getFunctionName(), getAuthStringURL)

	req, err := http.NewRequest(http.MethodGet, getAuthStringURL, nil)
	if err != nil {
		log.Println("Error creating http request", err)
		return "", err
	}

	client := http.DefaultClient
	response, doErr := client.Do(req)
	if doErr != nil {
		log.Println("Error doing http request", doErr)
		return "", err
	}

	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			fmt.Println("Error closing body", err)
		}

	}(response.Body)

	if response.StatusCode != 200 {
		log.Printf("%s: Error response from http request: %s\n", getFunctionName(), response.Status)
		return "", err
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return "", err
	}
	bodyString := string(body)
	return bodyString, nil

}

func UploadFileToClient(hostAndPort string, filePath string) error {
	targetURL := fmt.Sprintf("http://%s/upload", hostAndPort)
	// 1. Open the file
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("error opening file: %w", err)
	}
	defer file.Close()

	// 2. Create a buffer to write our multipart form data
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	// 3. Create a form file field. The second argument "myFile" must match
	//    the key the server expects in r.FormFile("myFile").
	part, err := writer.CreateFormFile("myFile", filepath.Base(filePath))
	if err != nil {
		return fmt.Errorf("error creating form file: %w", err)
	}

	// 4. Copy the file content to the form file field
	_, err = io.Copy(part, file)
	if err != nil {
		return fmt.Errorf("error copying file content to form: %w", err)
	}

	// 5. Close the multipart writer to finalize the form data
	err = writer.Close()
	if err != nil {
		return fmt.Errorf("error closing multipart writer: %w", err)
	}

	// 6. Create the HTTP request
	req, err := http.NewRequest("POST", targetURL, body)
	if err != nil {
		return fmt.Errorf("error creating HTTP request: %w", err)
	}

	// 7. Set the Content-Type header with the boundary generated by multipart.Writer
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", JWToken))

	// 8. Send the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("error sending request: %w", err)
	}
	defer resp.Body.Close()

	// 9. Read and print the response from the server
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("error reading response body: %w", err)
	}

	fmt.Printf("Server Response (%s): %s\n", resp.Status, string(responseBody))

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned non-OK status: %s", resp.Status)
	}

	return nil
}
