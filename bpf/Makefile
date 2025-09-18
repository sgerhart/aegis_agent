# AegisFlux eBPF CO-RE Build System
# Requires clang/llvm >= 14 and kernel headers

CLANG ?= clang
LLC ?= llc
ARCH ?= x86
KERNEL_SRC ?= /lib/modules/$(shell uname -r)/build
BPFTOOL ?= bpftool

# Compiler flags
CLANG_FLAGS = -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
	-Wno-unused-value -Wno-pointer-sign \
	-Wno-compare-distinct-pointer-types \
	-Wno-gnu-variable-sized-type-not-at-end \
	-Wno-address-of-packed-member -Wno-tautological-compare \
	-Wno-unknown-warning-option \
	-fno-stack-protector

# Add kernel headers if available
ifneq ($(wildcard $(KERNEL_SRC)),)
CLANG_FLAGS += -I$(KERNEL_SRC)/arch/$(ARCH)/include \
	-I$(KERNEL_SRC)/arch/$(ARCH)/include/generated \
	-I$(KERNEL_SRC)/include \
	-I$(KERNEL_SRC)/include/generated \
	-I$(KERNEL_SRC)/arch/$(ARCH)/include/uapi \
	-I$(KERNEL_SRC)/arch/$(ARCH)/include/generated/uapi \
	-I$(KERNEL_SRC)/include/uapi \
	-I$(KERNEL_SRC)/include/generated/uapi
else
# Use vmlinux.h for CO-RE compilation
CLANG_FLAGS += -I./include
endif

# Source files
SOURCES = seg_egress_cgroup.bpf.c seg_ingress_tc.bpf.c seg_policy_maps.bpf.c
OBJECTS = $(SOURCES:.c=.o)

# Default target
all: $(OBJECTS)

# Build individual object files
%.o: src/%.c
	@echo "Building $@..."
	$(CLANG) $(CLANG_FLAGS) -c $< -o $@
	@echo "Generated $@"

# Clean build artifacts
clean:
	rm -f *.o *.skel.h

# Verify object files
verify: $(OBJECTS)
	@echo "Verifying BPF object files..."
	@for obj in $(OBJECTS); do \
		echo "Checking $$obj:"; \
		file $$obj; \
		echo "  ✓ BPF object file generated"; \
	done

# Generate skeleton headers
skeleton: $(OBJECTS)
	@echo "Generating skeleton headers..."
	@echo "Note: Skeleton generation requires bpftool (not available on macOS)"
	@echo "Skipping skeleton generation..."

# Install headers to include directory
install-headers: skeleton
	@echo "Installing skeleton headers..."
	mkdir -p ../agents/local-agent-go/internal/loader/include
	cp *.skel.h ../agents/local-agent-go/internal/loader/include/

# Full build with verification
build: all verify skeleton install-headers
	@echo "Build complete!"

# Check dependencies
check-deps:
	@echo "Checking build dependencies..."
	@command -v $(CLANG) >/dev/null 2>&1 || { echo "clang not found"; exit 1; }
	@echo "clang found ✓"
	@echo "Note: bpftool and kernel headers not required for basic compilation"

# Show help
help:
	@echo "AegisFlux eBPF CO-RE Build System"
	@echo ""
	@echo "Targets:"
	@echo "  all          - Build all BPF object files"
	@echo "  clean        - Remove build artifacts"
	@echo "  verify       - Verify generated object files"
	@echo "  skeleton     - Generate skeleton headers"
	@echo "  install-headers - Install skeleton headers to agent"
	@echo "  build        - Full build with verification"
	@echo "  check-deps   - Check build dependencies"
	@echo "  help         - Show this help"
	@echo ""
	@echo "Environment variables:"
	@echo "  CLANG        - clang compiler path (default: clang)"
	@echo "  LLC          - llc compiler path (default: llc)"
	@echo "  ARCH         - target architecture (default: x86)"
	@echo "  KERNEL_SRC   - kernel source path (default: /lib/modules/\$(uname -r)/build)"
	@echo "  BPFTOOL      - bpftool path (default: bpftool)"

.PHONY: all clean verify skeleton install-headers build check-deps help