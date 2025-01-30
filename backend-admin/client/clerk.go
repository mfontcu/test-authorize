package clientx

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
)

type ClerkClient struct {
	client *http.Client
	host   string
}

type Clerk struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

func NewClerkClient(client *http.Client, host string) *ClerkClient {
	return &ClerkClient{
		client,
		host,
	}
}

func (c ClerkClient) GetClerks() ([]Clerk, error) {
	log.Println("From backend-admin to backend-clerk")

	res, err := c.client.Get(c.host + "/clerk")
	if err != nil {
		return nil, fmt.Errorf("failed to get response from clerk service, err: %v", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get response from clerk service, status code: %v", res.StatusCode)
	}

	var clerk []Clerk
	err = json.NewDecoder(res.Body).Decode(&clerk)
	if err != nil {
		return nil, fmt.Errorf("failed to decode response, err: %v", err)
	}

	return clerk, nil
}
