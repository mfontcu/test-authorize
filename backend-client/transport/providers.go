package transportx

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/Nerzal/gocloak/v13"
	"github.com/golang-jwt/jwt/v5"
)

// KeycloakProvider implements the authentication.Provider interface for Keycloak.
type KeycloakProvider struct {
	client    *gocloak.GoCloak
	realm     string
	publicKey *rsa.PublicKey
	mu        sync.RWMutex
}

// NewKeycloakProvider creates a new KeycloakProvider.
func NewKeycloakProvider(keycloakURL, realm string) (*KeycloakProvider, error) {
	client := gocloak.NewClient(keycloakURL)

	provider := &KeycloakProvider{
		client: client,
		realm:  realm,
	}

	// Load the public key for the first time
	err := provider.refreshPublicKey()
	if err != nil {
		return nil, err
	}

	// Initialize the key rotation process
	go provider.startKeyRotation(5 * time.Minute)

	return provider, nil
}

// Authenticate validates a token using the public key from Keycloak.
func (k *KeycloakProvider) Authenticate(ctx context.Context, tokenString string) (context.Context, error) {
	k.mu.RLock()
	publicKey := k.publicKey
	k.mu.RUnlock()

	if publicKey == nil {
		return nil, fmt.Errorf("clave pública no disponible")
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return publicKey, nil
	})
	if err != nil || !token.Valid {
		return nil, fmt.Errorf("token inválido o expirado")
	}

	return ctx, nil
}

// refreshPublicKey updates the public key from Keycloak.
func (k *KeycloakProvider) refreshPublicKey() error {
	ctx := context.Background()

	// Obatain the public key from Keycloak
	certs, err := k.client.GetCerts(ctx, k.realm)
	if err != nil || len(*certs.Keys) == 0 {
		return fmt.Errorf("error obteniendo la clave pública de Keycloak: %w", err)
	}

	// Get the first key
	key := (*certs.Keys)[0]

	// Convert the Keycloak key to an *rsa.PublicKey
	publicKey, err := convertKeycloakCertToRSAPublicKey(key)
	if err != nil {
		return fmt.Errorf("error al convertir la clave pública de Keycloak: %w", err)
	}

	// Save the public key
	k.mu.Lock()
	k.publicKey = publicKey
	k.mu.Unlock()

	return nil
}

// startKeyRotation updates the public key from Keycloak periodically.
func (k *KeycloakProvider) startKeyRotation(interval time.Duration) {
	for {
		time.Sleep(interval)
		err := k.refreshPublicKey()
		if err != nil {
			fmt.Println("Error actualizando clave pública:", err)
		}
	}
}

// convertKeycloakCertToRSAPublicKey converts a Keycloak certificate to an *rsa.PublicKey.
func convertKeycloakCertToRSAPublicKey(cert gocloak.CertResponseKey) (*rsa.PublicKey, error) {
	if cert.N == nil || cert.E == nil {
		return nil, fmt.Errorf("certificado RSA inválido: falta N o E")
	}

	// Decode `N` (modulus) from base64 URL-safe
	nBytes, err := base64.RawURLEncoding.DecodeString(*cert.N)
	if err != nil {
		return nil, fmt.Errorf("error decodificando N: %w", err)
	}
	n := new(big.Int).SetBytes(nBytes)

	// Decode `E` (exponent) from base64 URL-safe
	eBytes, err := base64.RawURLEncoding.DecodeString(*cert.E)
	if err != nil {
		return nil, fmt.Errorf("error decodificando E: %w", err)
	}

	// Convert `E` to an integer
	e := 0
	for _, b := range eBytes {
		e = e<<8 + int(b)
	}

	// Build the RSA public key
	publicKey := &rsa.PublicKey{
		N: n,
		E: e,
	}

	return publicKey, nil
}
