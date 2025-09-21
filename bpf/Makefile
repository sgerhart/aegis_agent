# AEGIS eBPF Agent Build System
# Builds eBPF programs for enforcement, observability, and telemetry

CLANG ?= clang
LLVM_STRIP ?= llvm-strip
BPFTOOL ?= bpftool

# Architecture detection
ARCH := $(shell uname -m | sed 's/x86_64/x86_64/' | sed 's/aarch64/arm64/')

# Directories
SRC_DIR := src
BPF_DIR := bpf
VMLINUX_DIR := include

# eBPF source files
ENFORCEMENT_SRC := $(SRC_DIR)/aegis_enforcer.bpf.c
OBSERVABILITY_SRC := $(SRC_DIR)/aegis_observer.bpf.c
ADVANCED_MAPS_SRC := $(SRC_DIR)/aegis_advanced_maps.bpf.c
PROCESS_TRACKER_SRC := $(SRC_DIR)/aegis_process_tracker.bpf.c

# eBPF object files
ENFORCEMENT_OBJ := $(BPF_DIR)/aegis_enforcer.o
OBSERVABILITY_OBJ := $(BPF_DIR)/aegis_observer.o
ADVANCED_MAPS_OBJ := $(BPF_DIR)/aegis_advanced_maps.o
PROCESS_TRACKER_OBJ := $(BPF_DIR)/aegis_process_tracker.o

# All targets
ALL_OBJS := $(ENFORCEMENT_OBJ) $(OBSERVABILITY_OBJ) $(ADVANCED_MAPS_OBJ) $(PROCESS_TRACKER_OBJ)

# Compiler flags
CFLAGS := -g -O2 -Wall -Werror
CFLAGS += -target bpf
CFLAGS += -D__TARGET_ARCH_$(ARCH)
CFLAGS += -I$(VMLINUX_DIR)
CFLAGS += -I/usr/include
CFLAGS += -I/usr/include/$(shell uname -m)-linux-gnu

# Default target
.PHONY: all clean install check-deps vmlinux

all: check-deps $(ALL_OBJS)

# Create vmlinux.h if it doesn't exist
vmlinux:
	@echo "Generating vmlinux.h for $(ARCH)..."
	@mkdir -p $(VMLINUX_DIR)
	@if [ ! -f $(VMLINUX_DIR)/vmlinux.h ]; then \
		$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX_DIR)/vmlinux.h; \
	fi

# Check dependencies
check-deps:
	@echo "Checking eBPF build dependencies..."
	@command -v $(CLANG) >/dev/null 2>&1 || { echo "clang not found"; exit 1; }
	@command -v $(BPFTOOL) >/dev/null 2>&1 || { echo "bpftool not found"; exit 1; }
	@test -f /usr/include/linux/bpf.h || { echo "linux headers not found"; exit 1; }
	@test -f /usr/include/bpf/bpf_helpers.h || { echo "libbpf-dev not found"; exit 1; }
	@echo "✅ All dependencies found"

# Create directories
$(BPF_DIR):
	mkdir -p $(BPF_DIR)

# Build enforcement eBPF program
$(ENFORCEMENT_OBJ): $(ENFORCEMENT_SRC) | $(BPF_DIR) vmlinux
	@echo "Building AEGIS enforcement eBPF program..."
	$(CLANG) $(CFLAGS) -c $< -o $@
	@echo "✅ Built $@"

# Build observability eBPF program  
$(OBSERVABILITY_OBJ): $(OBSERVABILITY_SRC) | $(BPF_DIR) vmlinux
	@echo "Building AEGIS observability eBPF program..."
	$(CLANG) $(CFLAGS) -c $< -o $@
	@echo "✅ Built $@"

# Build advanced maps eBPF program
$(ADVANCED_MAPS_OBJ): $(ADVANCED_MAPS_SRC) | $(BPF_DIR) vmlinux
	@echo "Building AEGIS advanced maps eBPF program..."
	$(CLANG) $(CFLAGS) -c $< -o $@
	@echo "✅ Built $@"

# Build process tracker eBPF program
$(PROCESS_TRACKER_OBJ): $(PROCESS_TRACKER_SRC) | $(BPF_DIR) vmlinux
	@echo "Building AEGIS process tracker eBPF program..."
	$(CLANG) $(CFLAGS) -c $< -o $@
	@echo "✅ Built $@"

# Install to target system (used by deployment scripts)
install: all
	@echo "Installing AEGIS eBPF programs..."
	@mkdir -p /opt/aegis/ebpf
	cp $(ALL_OBJS) /opt/aegis/ebpf/
	@echo "✅ Installed eBPF programs to /opt/aegis/ebpf/"

# Clean build artifacts
clean:
	rm -rf $(BPF_DIR)/*.o
	rm -rf $(VMLINUX_DIR)/vmlinux.h
	@echo "✅ Cleaned build artifacts"

# Show build info
info:
	@echo "AEGIS eBPF Build Configuration:"
	@echo "  Architecture: $(ARCH)"
	@echo "  Clang: $(CLANG)"
	@echo "  BPFTool: $(BPFTOOL)"
	@echo "  Source Dir: $(SRC_DIR)"
	@echo "  Object Dir: $(BPF_DIR)"
	@echo "  Targets: $(ALL_OBJS)"

# Help target
help:
	@echo "AEGIS eBPF Build System"
	@echo ""
	@echo "Targets:"
	@echo "  all        - Build all eBPF programs"
	@echo "  clean      - Clean build artifacts"
	@echo "  install    - Install to /opt/aegis/ebpf/"
	@echo "  check-deps - Verify build dependencies"
	@echo "  vmlinux    - Generate vmlinux.h"
	@echo "  info       - Show build configuration"
	@echo "  help       - Show this help"