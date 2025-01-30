package clientx

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
)

type ClientClient struct {
	client *http.Client
	host   string
}

type Client struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

func NewClientClient(client *http.Client, host string) *ClientClient {
	return &ClientClient{
		client,
		host,
	}
}

func (c ClientClient) GetClients() ([]Client, error) {
	log.Println("From backend-admin to backend-client")

	res, err := c.client.Get(c.host + "/client")
	if err != nil {
		return nil, fmt.Errorf("failed to get response from client service, err: %v", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get response from client service, status code: %v", res.StatusCode)
	}

	var clients []Client
	err = json.NewDecoder(res.Body).Decode(&clients)
	if err != nil {
		return nil, fmt.Errorf("failed to decode response, err: %v", err)
	}

	return clients, nil
}
