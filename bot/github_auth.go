package main

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// GitHub Apps authenticate using a JWT (JSON Web Token) signed with the
// app's private key. GitHub verifies this JWT using the PUBLIC key it
// already has on file for your app — this proves the request genuinely
// comes from you, without ever sending your private key over the network.

const githubAppID = "4226913" // your App ID

// loadPrivateKey reads the .pem file and parses it into an RSA private key
// object that the JWT library can use to sign tokens.
func loadPrivateKey(path string) (*rsa.PrivateKey, error) {
	keyBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading key file: %w", err)
	}

	key, err := jwt.ParseRSAPrivateKeyFromPEM(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("parsing RSA key: %w", err)
	}

	return key, nil
}

// generateAppJWT creates a short-lived JWT that identifies THIS APP
// (not any specific installation) to GitHub's API. This JWT is used
// for exactly one purpose: exchanging it for an installation-specific
// access token in the next step.
func generateAppJWT(privateKeyPath string) (string, error) {
	privateKey, err := loadPrivateKey(privateKeyPath)
	if err != nil {
		return "", err
	}

	now := time.Now()

	// GitHub Apps JWTs require these exact claims:
	//   iat (issued at)  — must NOT be in the future; we back it off by 60s
	//                       to tolerate small clock drift between our
	//                       machine and GitHub's servers
	//   exp (expiration) — GitHub REJECTS JWTs valid for more than 10 minutes
	//   iss (issuer)     — must be your App ID
	claims := jwt.RegisteredClaims{
		IssuedAt:  jwt.NewNumericDate(now.Add(-60 * time.Second)),
		ExpiresAt: jwt.NewNumericDate(now.Add(9 * time.Minute)),
		Issuer:    githubAppID,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	signedToken, err := token.SignedString(privateKey)
	if err != nil {
		return "", fmt.Errorf("signing JWT: %w", err)
	}

	return signedToken, nil
}

// InstallationTokenResponse is GitHub's response body from the
// installation access token exchange endpoint.
type InstallationTokenResponse struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

// getInstallationToken exchanges the App JWT for a token scoped to a
// specific installation (i.e. whichever repo/org installed the app).
// This token is what actually gets used for repo-level API calls like
// fetching the tarball and posting Check Runs.
func getInstallationToken(appJWT string, installationID int64) (*InstallationTokenResponse, error) {
	url := fmt.Sprintf("https://api.github.com/app/installations/%d/access_tokens", installationID)

	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+appJWT)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// GitHub returns 201 Created on success — NOT 200.
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, body)
	}

	var tokenResp InstallationTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}
	return &tokenResp, nil
}