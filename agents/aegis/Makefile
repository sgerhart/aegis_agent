# Aegis Agent Makefile
.PHONY: build build-linux-arm64 clean test run deploy help

# Default target
.DEFAULT_GOAL := build

# Build the agent for current platform
build:
	@echo "Building Aegis Agent for $(shell go env GOOS)/$(shell go env GOARCH)..."
	go build -ldflags="-s -w" -o aegis-agent ./cmd/aegis/main_core.go
	@echo "Build complete: aegis-agent"

# Build for Linux ARM64
build-linux-arm64:
	@echo "Building Aegis Agent for linux/arm64..."
	GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -o aegis-agent-linux-arm64 ./cmd/aegis/main_core.go
	@echo "Build complete: aegis-agent-linux-arm64"

# Build for Linux AMD64
build-linux-amd64:
	@echo "Building Aegis Agent for linux/amd64..."
	GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o aegis-agent-linux-amd64 ./cmd/aegis/main_core.go
	@echo "Build complete: aegis-agent-linux-amd64"

# Build for macOS ARM64
build-darwin-arm64:
	@echo "Building Aegis Agent for darwin/arm64..."
	GOOS=darwin GOARCH=arm64 go build -ldflags="-s -w" -o aegis-agent-darwin-arm64 ./cmd/aegis/main_core.go
	@echo "Build complete: aegis-agent-darwin-arm64"

# Build for macOS AMD64
build-darwin-amd64:
	@echo "Building Aegis Agent for darwin/amd64..."
	GOOS=darwin GOARCH=amd64 go build -ldflags="-s -w" -o aegis-agent-darwin-amd64 ./cmd/aegis/main_core.go
	@echo "Build complete: aegis-agent-darwin-amd64"

# Build all platforms
build-all: build-linux-arm64 build-linux-amd64 build-darwin-arm64 build-darwin-amd64
	@echo "All builds complete"

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	rm -f aegis-agent*
	rm -f *.log
	rm -f .DS_Store
	@echo "Clean complete"

# Run the agent locally
run:
	@echo "Starting Aegis Agent..."
	./aegis-agent --agent-id "test-agent-$(shell date +%s)" --backend-url "ws://localhost:8080/ws/agent" --log-level debug

# Test build
test:
	@echo "Testing build..."
	go build -o aegis-agent ./cmd/aegis/main_core.go
	@echo "Test build successful"

# Deploy to Linux ARM64 host
deploy-arm64:
	@echo "Deploying to Linux ARM64..."
	@if [ -z "$(HOST)" ]; then echo "Usage: make deploy-arm64 HOST=user@host"; exit 1; fi
	scp aegis-agent-linux-arm64 $(HOST):/tmp/aegis-agent
	ssh $(HOST) "chmod +x /tmp/aegis-agent"

# Run tests
test-modules:
	@echo "Testing module control..."
	python3 ../../test_module_control.py

# Help
help:
	@echo "Available targets:"
	@echo "  build              - Build for current platform"
	@echo "  build-linux-arm64  - Build for Linux ARM64"
	@echo "  build-linux-amd64  - Build for Linux AMD64"
	@echo "  build-darwin-arm64 - Build for macOS ARM64"
	@echo "  build-darwin-amd64 - Build for macOS AMD64"
	@echo "  build-all          - Build for all platforms"
	@echo "  clean              - Clean build artifacts"
	@echo "  run                - Run the agent locally"
	@echo "  test               - Test build"
	@echo "  deploy-arm64       - Deploy to Linux ARM64 (HOST=user@host)"
	@echo "  test-modules       - Test module control functionality"
	@echo "  help               - Show this help"
