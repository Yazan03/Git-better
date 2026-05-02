// VULN: CWE-798 — AWS credentials hardcoded as package-level constants
package main

import (
	"fmt"
	"net/http"
)

const (
	AWSAccessKeyID     = "AKIAIOSFODNN7EXAMPLE"
	AWSSecretAccessKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	APIKey             = "sk-proj-xK9mN2pL8qR4tY7wZ3vJ6hU1cA0dF5gB"
)

func makeRequest(endpoint string) {
	req, _ := http.NewRequest("GET", endpoint, nil)
	req.Header.Set("Authorization", "Bearer "+APIKey)
	req.Header.Set("X-AWS-Access-Key", AWSAccessKeyID)
	http.DefaultClient.Do(req)
	fmt.Println("done")
}
