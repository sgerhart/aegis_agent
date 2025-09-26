#!/bin/bash

# Aegis Agent Build Script
# Optimized build system for multiple targets and platforms

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${SCRIPT_DIR}/bin"
DIST_DIR="${SCRIPT_DIR}/dist"
VERSION="1.0.0"
BUILD_TIME=$(date -u '+%Y-%m-%d_%H:%M:%S')
GIT_COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")

# Build flags
LDFLAGS="-s -w -X main.version=${VERSION} -X main.buildTime=${BUILD_TIME} -X main.gitCommit=${GIT_COMMIT}"

# Print colored output
print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

# Clean build directories
clean() {
    print_info "Cleaning build directories..."
    rm -rf "${BUILD_DIR}" "${DIST_DIR}"
    mkdir -p "${BUILD_DIR}" "${DIST_DIR}"
    print_success "Build directories cleaned"
}

# Build core agent
build_core() {
    local platform=$1
    local arch=$2
    local output_name="aegis-agent-core-${platform}-${arch}"
    
    print_info "Building core agent for ${platform}/${arch}..."
    
    GOOS="${platform}" GOARCH="${arch}" CGO_ENABLED=0 go build \
        -ldflags="${LDFLAGS}" \
        -trimpath \
        -buildmode=pie \
        -a -installsuffix cgo \
        -o "${BUILD_DIR}/${output_name}" \
        ./cmd/aegis/main_core.go
    
    # Strip binary if strip is available
    if command -v strip >/dev/null 2>&1; then
        strip "${BUILD_DIR}/${output_name}"
        print_info "Binary stripped"
    fi
    
    # Get binary size
    local size=$(ls -lh "${BUILD_DIR}/${output_name}" | awk '{print $5}')
    print_success "Core agent built: ${output_name} (${size})"
}

# Build full agent
build_full() {
    local platform=$1
    local arch=$2
    local output_name="aegis-agent-full-${platform}-${arch}"
    
    print_info "Building full agent for ${platform}/${arch}..."
    
    GOOS="${platform}" GOARCH="${arch}" CGO_ENABLED=0 go build \
        -ldflags="${LDFLAGS}" \
        -trimpath \
        -buildmode=pie \
        -a -installsuffix cgo \
        -o "${BUILD_DIR}/${output_name}" \
        ./cmd/aegis/main.go
    
    # Strip binary if strip is available
    if command -v strip >/dev/null 2>&1; then
        strip "${BUILD_DIR}/${output_name}"
        print_info "Binary stripped"
    fi
    
    # Get binary size
    local size=$(ls -lh "${BUILD_DIR}/${output_name}" | awk '{print $5}')
    print_success "Full agent built: ${output_name} (${size})"
}

# Compress binary with UPX
compress_binary() {
    local binary_path=$1
    local output_path=$2
    
    if command -v upx >/dev/null 2>&1; then
        print_info "Compressing binary with UPX..."
        upx --best -o "${output_path}" "${binary_path}"
        print_success "Binary compressed"
    else
        print_warning "UPX not available, copying without compression"
        cp "${binary_path}" "${output_path}"
    fi
}

# Create distribution package
create_package() {
    local platform=$1
    local arch=$2
    local package_name="aegis-agent-${VERSION}-${platform}-${arch}"
    local package_dir="${DIST_DIR}/${package_name}"
    
    print_info "Creating distribution package: ${package_name}"
    
    # Create package directory
    mkdir -p "${package_dir}"
    
    # Copy binaries
    cp "${BUILD_DIR}/aegis-agent-core-${platform}-${arch}" "${package_dir}/aegis-agent-core"
    if [ -f "${BUILD_DIR}/aegis-agent-full-${platform}-${arch}" ]; then
        cp "${BUILD_DIR}/aegis-agent-full-${platform}-${arch}" "${package_dir}/aegis-agent-full"
    fi
    
    # Copy configuration files
    if [ -d "configs" ]; then
        cp -r configs/* "${package_dir}/" 2>/dev/null || true
    fi
    
    # Copy examples
    if [ -d "examples" ]; then
        cp -r examples/* "${package_dir}/" 2>/dev/null || true
    fi
    
    # Create run scripts
    cat > "${package_dir}/run-core.sh" << EOF
#!/bin/bash
# Aegis Agent Core - Run Script

AGENT_ID=\${1:-agent-001}
LOG_LEVEL=\${2:-info}

echo "Starting Aegis Core Agent..."
echo "Agent ID: \${AGENT_ID}"
echo "Log Level: \${LOG_LEVEL}"

sudo ./aegis-agent-core \\
    --agent-id="\${AGENT_ID}" \\
    --log-level="\${LOG_LEVEL}" \\
    --interval="30s"
EOF
    
    chmod +x "${package_dir}/run-core.sh"
    
    # Create README
    cat > "${package_dir}/README.md" << EOF
# Aegis Agent ${VERSION}

## Quick Start

### Core Agent (Recommended)
\`\`\`bash
./run-core.sh [agent-id] [log-level]
\`\`\`

### Manual Start
\`\`\`bash
sudo ./aegis-agent-core --agent-id="agent-001" --log-level="info"
\`\`\`

## Configuration

- Agent ID: Unique identifier for this agent
- Log Level: debug, info, warn, error
- Update Interval: How often to check for updates

## Requirements

- Linux kernel 5.4+ (for eBPF)
- Root privileges (for eBPF operations)
- Network connectivity (for backend communication)

## Build Information

- Version: ${VERSION}
- Build Time: ${BUILD_TIME}
- Git Commit: ${GIT_COMMIT}
- Platform: ${platform}/${arch}
EOF
    
    # Create tar.gz package
    cd "${DIST_DIR}"
    tar -czf "${package_name}.tar.gz" "${package_name}"
    cd "${SCRIPT_DIR}"
    
    print_success "Package created: ${DIST_DIR}/${package_name}.tar.gz"
}

# Build all platforms
build_all() {
    local platforms=("linux" "darwin")
    local arches=("amd64" "arm64")
    
    print_info "Building for all platforms..."
    
    for platform in "${platforms[@]}"; do
        for arch in "${arches[@]}"; do
            build_core "${platform}" "${arch}"
            # build_full "${platform}" "${arch}"  # Uncomment when full agent is ready
        done
    done
    
    print_success "All platforms built"
}

# Package all platforms
package_all() {
    local platforms=("linux" "darwin")
    local arches=("amd64" "arm64")
    
    print_info "Creating packages for all platforms..."
    
    for platform in "${platforms[@]}"; do
        for arch in "${arches[@]}"; do
            create_package "${platform}" "${arch}"
        done
    done
    
    print_success "All packages created"
}

# Size analysis
analyze_size() {
    print_info "Analyzing binary sizes..."
    
    if [ -d "${BUILD_DIR}" ]; then
        echo "Binary sizes:"
        ls -lh "${BUILD_DIR}"/* | awk '{print $5, $9}' | sort -hr
        echo ""
        echo "Total size:"
        du -sh "${BUILD_DIR}"
    else
        print_warning "No build directory found. Run build first."
    fi
}

# Show help
show_help() {
    echo "Aegis Agent Build Script"
    echo ""
    echo "Usage: $0 [command] [options]"
    echo ""
    echo "Commands:"
    echo "  clean       - Clean build directories"
    echo "  core        - Build core agent for current platform"
    echo "  full        - Build full agent for current platform"
    echo "  all         - Build for all platforms"
    echo "  package     - Create distribution packages"
    echo "  size        - Analyze binary sizes"
    echo "  help        - Show this help"
    echo ""
    echo "Options:"
    echo "  --platform  - Target platform (linux, darwin)"
    echo "  --arch      - Target architecture (amd64, arm64)"
    echo ""
    echo "Examples:"
    echo "  $0 core"
    echo "  $0 all"
    echo "  $0 package"
    echo "  $0 --platform linux --arch arm64 core"
}

# Main execution
main() {
    case "${1:-help}" in
        "clean")
            clean
            ;;
        "core")
            clean
            build_core "${2:-$(go env GOOS)}" "${3:-$(go env GOARCH)}"
            analyze_size
            ;;
        "full")
            clean
            build_full "${2:-$(go env GOOS)}" "${3:-$(go env GOARCH)}"
            analyze_size
            ;;
        "all")
            clean
            build_all
            analyze_size
            ;;
        "package")
            package_all
            ;;
        "size")
            analyze_size
            ;;
        "help"|*)
            show_help
            ;;
    esac
}

# Run main function with all arguments
main "$@"
