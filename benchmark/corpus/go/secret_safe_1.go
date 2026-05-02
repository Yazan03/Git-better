// SAFE: credentials read from environment variables at runtime
package main

import (
	"fmt"
	"net/http"
	"os"
)

func makeRequest(endpoint string) {
	apiKey := os.Getenv("API_KEY")
	if apiKey == "" {
		fmt.Fprintln(os.Stderr, "API_KEY not set")
		return
	}
	req, _ := http.NewRequest("GET", endpoint, nil)
	req.Header.Set("Authorization", "Bearer "+apiKey)
	http.DefaultClient.Do(req)
}
