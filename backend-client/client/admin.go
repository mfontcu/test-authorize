package clientx

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
)

type AdminClient struct {
	client *http.Client
	host   string
}

type Admin struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

func NewAdminClient(client *http.Client, host string) *AdminClient {
	return &AdminClient{
		client,
		host,
	}
}

func (c AdminClient) GetAdmins() ([]Admin, error) {
	log.Println("From backend-admin to backend-admin")

	res, err := c.client.Get(c.host + "/admin")
	if err != nil {
		return nil, fmt.Errorf("failed to get response from admin service, err: %v", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get response from admin service, status code: %v", res.StatusCode)
	}

	var admin []Admin
	err = json.NewDecoder(res.Body).Decode(&admin)
	if err != nil {
		return nil, fmt.Errorf("failed to decode response, err: %v", err)
	}

	return admin, nil
}
