package main

import (
	"fmt"
	"io"
	"net/http"
	"time"
)

// fetchTarball downloads the repo's source at a given ref (commit SHA,
// branch, or tag) as a gzipped tarball, authenticated with an installation
// access token. GitHub responds with a redirect to a signed codeload URL —
// Go's http.Client follows redirects by default, so a plain client.Do
// handles that transparently.
//
// Caller is responsible for closing the returned ReadCloser.
func fetchTarball(installToken, owner, repo, ref string) (io.ReadCloser, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/tarball/%s", owner, repo, ref)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("building tarball request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+installToken)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching tarball: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return nil, fmt.Errorf("unexpected status %d fetching tarball: %s", resp.StatusCode, body)
	}

	return resp.Body, nil
}