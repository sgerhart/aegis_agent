package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
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
	
	// Log the request details
	log.Printf("[registry] Making request to: %s", url)
	log.Printf("[registry] Host ID: %s", c.hostID)
	log.Printf("[registry] Base URL: %s", c.base)
	
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		log.Printf("[registry] Failed to create request: %v", err)
		return nil, err
	}
	
	// Log request headers
	log.Printf("[registry] Request headers: %v", req.Header)
	
	resp, err := c.http.Do(req)
	if err != nil {
		log.Printf("[registry] Request failed: %v", err)
		return nil, err
	}
	defer resp.Body.Close()
	
	// Log response details
	log.Printf("[registry] Response status: %s", resp.Status)
	log.Printf("[registry] Response headers: %v", resp.Header)
	
	if resp.StatusCode == 404 {
		log.Printf("[registry] No assignments found (404)")
		return []Assignment{}, nil
	}
	if resp.StatusCode != 200 {
		log.Printf("[registry] Registry error: %s", resp.Status)
		return nil, fmt.Errorf("registry %s: %s", url, resp.Status)
	}
	
	// Read the response body to check format
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("[registry] Failed to read response body: %v", err)
		return nil, fmt.Errorf("failed to read registry response: %w", err)
	}
	
	// Log raw response body
	log.Printf("[registry] Raw response body: %s", string(body))
	log.Printf("[registry] Response body length: %d bytes", len(body))
	
	// Try to decode as AssignmentsResponse first
	var response AssignmentsResponse
	if err := json.Unmarshal(body, &response); err == nil {
		log.Printf("[registry] Successfully decoded as AssignmentsResponse: %+v", response)
		return response.Artifacts, nil
	}
	
	// If that fails, try to decode as direct array
	var assignments []Assignment
	if err := json.Unmarshal(body, &assignments); err == nil {
		log.Printf("[registry] Successfully decoded as direct array: %+v", assignments)
		return assignments, nil
	}
	
	log.Printf("[registry] Failed to decode response as either format")
	return nil, fmt.Errorf("failed to decode registry response: %w", err)
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
