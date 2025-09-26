# Aegis Agent Build System
# Optimized for size, performance, and security

# Build configuration
GO_VERSION := $(shell go version | cut -d' ' -f3)
BUILD_TIME := $(shell date -u '+%Y-%m-%d_%H:%M:%S')
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
VERSION := 1.0.0

# Build flags for optimization
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.buildTime=$(BUILD_TIME) -X main.gitCommit=$(GIT_COMMIT)
BUILD_FLAGS := -ldflags="$(LDFLAGS)" -trimpath -buildmode=pie

# Optimization flags
OPTIMIZE_FLAGS := -a -installsuffix cgo -tags netgo

# Target directories
BIN_DIR := bin
DIST_DIR := dist

# Binary names
CORE_BINARY := aegis-agent-core
FULL_BINARY := aegis-agent-full

# Build targets
.PHONY: all clean core full test lint optimize strip compress

# Default target
all: clean core

# Core agent build (minimal)
core:
	@echo "🔨 Building core agent..."
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 go build $(BUILD_FLAGS) $(OPTIMIZE_FLAGS) \
		-o $(BIN_DIR)/$(CORE_BINARY) \
		./cmd/aegis/main_core.go
	@echo "✅ Core agent built: $(BIN_DIR)/$(CORE_BINARY)"

# Full agent build (with all features)
full:
	@echo "🔨 Building full agent..."
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 go build $(BUILD_FLAGS) $(OPTIMIZE_FLAGS) \
		-o $(BIN_DIR)/$(FULL_BINARY) \
		./cmd/aegis/main.go
	@echo "✅ Full agent built: $(BIN_DIR)/$(FULL_BINARY)"

# Test build
test:
	@echo "🧪 Running tests..."
	go test -v ./...

# Lint code
lint:
	@echo "🔍 Linting code..."
	golangci-lint run

# Optimize binaries
optimize: core
	@echo "⚡ Optimizing binaries..."
	@if command -v strip >/dev/null 2>&1; then \
		strip $(BIN_DIR)/$(CORE_BINARY); \
		echo "✅ Binary stripped"; \
	else \
		echo "⚠️  strip not available, skipping"; \
	fi

# Compress binaries (optional)
compress: optimize
	@echo "🗜️  Compressing binaries..."
	@if command -v upx >/dev/null 2>&1; then \
		upx --best $(BIN_DIR)/$(CORE_BINARY); \
		echo "✅ Binary compressed with UPX"; \
	else \
		echo "⚠️  UPX not available, skipping compression"; \
	fi

# Create distribution packages
dist: compress
	@echo "📦 Creating distribution packages..."
	@mkdir -p $(DIST_DIR)
	
	# Core agent package
	@mkdir -p $(DIST_DIR)/core
	@cp $(BIN_DIR)/$(CORE_BINARY) $(DIST_DIR)/core/
	@cp configs/*.json $(DIST_DIR)/core/ 2>/dev/null || true
	@cp examples/*.json $(DIST_DIR)/core/ 2>/dev/null || true
	@echo "#!/bin/bash\nsudo ./$(CORE_BINARY) --agent-id=\$${1:-agent-001} --log-level=info" > $(DIST_DIR)/core/run.sh
	@chmod +x $(DIST_DIR)/core/run.sh
	@tar -czf $(DIST_DIR)/aegis-agent-core-$(VERSION).tar.gz -C $(DIST_DIR) core/
	@echo "✅ Core package created: $(DIST_DIR)/aegis-agent-core-$(VERSION).tar.gz"
	
	# Full agent package (if built)
	@if [ -f $(BIN_DIR)/$(FULL_BINARY) ]; then \
		mkdir -p $(DIST_DIR)/full; \
		cp $(BIN_DIR)/$(FULL_BINARY) $(DIST_DIR)/full/; \
		cp configs/*.json $(DIST_DIR)/full/ 2>/dev/null || true; \
		cp examples/*.json $(DIST_DIR)/full/ 2>/dev/null || true; \
		echo "#!/bin/bash\nsudo ./$(FULL_BINARY) --agent-id=\$${1:-agent-001} --log-level=info" > $(DIST_DIR)/full/run.sh; \
		chmod +x $(DIST_DIR)/full/run.sh; \
		tar -czf $(DIST_DIR)/aegis-agent-full-$(VERSION).tar.gz -C $(DIST_DIR) full/; \
		echo "✅ Full package created: $(DIST_DIR)/aegis-agent-full-$(VERSION).tar.gz"; \
	fi

# Size analysis
size:
	@echo "📊 Binary size analysis..."
	@if [ -f $(BIN_DIR)/$(CORE_BINARY) ]; then \
		echo "Core agent size:"; \
		ls -lh $(BIN_DIR)/$(CORE_BINARY); \
		echo "Core agent size (bytes):"; \
		wc -c $(BIN_DIR)/$(CORE_BINARY); \
	fi
	@if [ -f $(BIN_DIR)/$(FULL_BINARY) ]; then \
		echo "Full agent size:"; \
		ls -lh $(BIN_DIR)/$(FULL_BINARY); \
		echo "Full agent size (bytes):"; \
		wc -c $(BIN_DIR)/$(FULL_BINARY); \
	fi

# Memory usage analysis
memcheck: core
	@echo "🧠 Memory usage analysis..."
	@if command -v valgrind >/dev/null 2>&1; then \
		echo "Running valgrind memory check..."; \
		valgrind --tool=memcheck --leak-check=full --show-leak-kinds=all $(BIN_DIR)/$(CORE_BINARY) --help; \
	else \
		echo "⚠️  Valgrind not available, skipping memory check"; \
	fi

# Performance benchmark
benchmark: core
	@echo "🏃 Performance benchmark..."
	go test -bench=. -benchmem ./...

# Security scan
security:
	@echo "🔒 Security scan..."
	@if command -v gosec >/dev/null 2>&1; then \
		gosec ./...; \
	else \
		echo "⚠️  gosec not available, install with: go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest"; \
	fi

# Clean build artifacts
clean:
	@echo "🧹 Cleaning build artifacts..."
	@rm -rf $(BIN_DIR) $(DIST_DIR)
	@go clean -cache
	@echo "✅ Build artifacts cleaned"

# Install dependencies
deps:
	@echo "📦 Installing dependencies..."
	go mod download
	go mod tidy
	@echo "✅ Dependencies installed"

# Development build (with debug info)
dev: deps
	@echo "🔧 Building development version..."
	@mkdir -p $(BIN_DIR)
	go build -o $(BIN_DIR)/$(CORE_BINARY)-dev ./cmd/aegis/main_core.go
	@echo "✅ Development build created: $(BIN_DIR)/$(CORE_BINARY)-dev"

# Production build (fully optimized)
prod: clean deps test lint core optimize
	@echo "🚀 Production build complete!"
	@make size

# Help
help:
	@echo "Aegis Agent Build System"
	@echo ""
	@echo "Available targets:"
	@echo "  all        - Build core agent (default)"
	@echo "  core       - Build core agent only"
	@echo "  full       - Build full agent with all features"
	@echo "  test       - Run tests"
	@echo "  lint       - Lint code"
	@echo "  optimize   - Build and optimize binaries"
	@echo "  compress   - Build, optimize, and compress binaries"
	@echo "  dist       - Create distribution packages"
	@echo "  size       - Show binary size analysis"
	@echo "  memcheck   - Run memory usage analysis"
	@echo "  benchmark  - Run performance benchmarks"
	@echo "  security   - Run security scan"
	@echo "  clean      - Clean build artifacts"
	@echo "  deps       - Install dependencies"
	@echo "  dev        - Build development version"
	@echo "  prod       - Build production version (fully optimized)"
	@echo "  help       - Show this help"
	@echo ""
	@echo "Build configuration:"
	@echo "  Version: $(VERSION)"
	@echo "  Go version: $(GO_VERSION)"
	@echo "  Build time: $(BUILD_TIME)"
	@echo "  Git commit: $(GIT_COMMIT)"
