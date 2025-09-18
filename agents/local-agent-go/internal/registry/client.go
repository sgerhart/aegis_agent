package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
)

type Client struct {
	base   string
	hostID string
	http   *http.Client
}

type Assignment struct {
	ArtifactID   string `json:"artifact_id"`
	BundleURL    string `json:"bundle_url,omitempty"`
	Checksum     string `json:"checksum,omitempty"`
	Signature    string `json:"signature,omitempty"`
	SignatureAlg string `json:"signature_algorithm,omitempty"`
	KeyID        string `json:"key_id,omitempty"`
}

type AssignmentsResponse struct {
	Artifacts []Assignment `json:"artifacts"`
	Total     int          `json:"total"`
}

func NewClient(base, hostID string) *Client {
	return &Client{
		base:   base,
		hostID: hostID,
		http:   &http.Client{},
	}
}

func (c *Client) FetchAssignments(ctx context.Context) ([]Assignment, error) {
	url := fmt.Sprintf("%s/artifacts/for-host/%s", c.base, c.hostID)
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 404 {
		return []Assignment{}, nil
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("registry %s: %s", url, resp.Status)
	}
	var response AssignmentsResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode registry response: %w", err)
	}
	return response.Artifacts, nil
}

func (c *Client) DownloadBundle(ctx context.Context, assignment Assignment, destDir string) (string, error) {
	if assignment.BundleURL == "" {
		return "", fmt.Errorf("no bundle URL provided for artifact %s", assignment.ArtifactID)
	}

	// Create destination directory if it doesn't exist
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create destination directory: %w", err)
	}

	// Create the request
	req, err := http.NewRequestWithContext(ctx, "GET", assignment.BundleURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	// Download the bundle
	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to download bundle: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("failed to download bundle: %s", resp.Status)
	}

	// Determine file extension from content type or URL
	ext := ".tar.gz"
	if resp.Header.Get("Content-Type") == "application/zip" {
		ext = ".zip"
	}

	// Create destination file
	destPath := filepath.Join(destDir, assignment.ArtifactID+ext)
	file, err := os.Create(destPath)
	if err != nil {
		return "", fmt.Errorf("failed to create destination file: %w", err)
	}
	defer file.Close()

	// Copy the response body to the file
	_, err = io.Copy(file, resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to write bundle to file: %w", err)
	}

	return destPath, nil
}
