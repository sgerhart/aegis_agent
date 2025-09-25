# Aegis Agent Makefile
.PHONY: build clean test run

# Build the agent
build:
	@echo "Building Aegis Agent..."
	go build -ldflags="-s -w" -o aegis-agent ./cmd/aegis/main_core.go
	@echo "Build complete: aegis-agent"

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	rm -f aegis-agent
	@echo "Clean complete"

# Run the agent
run:
	@echo "Starting Aegis Agent..."
	./aegis-agent --agent-id "test-agent-$(shell date +%s)" --backend-url "ws://localhost:8080/ws/agent" --log-level debug

# Test build
test:
	@echo "Testing build..."
	go build -o aegis-agent ./cmd/aegis/main_core.go
	@echo "Test build successful"

# Help
help:
	@echo "Available targets:"
	@echo "  build  - Build the agent"
	@echo "  clean  - Clean build artifacts"
	@echo "  run    - Run the agent"
	@echo "  test   - Test build"
	@echo "  help   - Show this help"
