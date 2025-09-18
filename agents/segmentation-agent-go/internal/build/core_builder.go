package build

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// COREBuilder handles CO-RE eBPF program compilation
type COREBuilder struct {
	clangPath    string
	bpftoolPath  string
	btfPath      string
	outputDir    string
	includePaths []string
}

// BuildConfig contains build configuration
type BuildConfig struct {
	SourceFile   string
	OutputFile   string
	ProgramType  string
	AttachType   string
	CFlags       []string
	IncludePaths []string
}

// BuildResult contains build output information
type BuildResult struct {
	ObjectFile   string
	BTFPath      string
	ProgramType  string
	AttachType   string
	BuildTime    time.Duration
	Size         int64
	Error        error
}

// NewCOREBuilder creates a new CO-RE builder
func NewCOREBuilder(clangPath, bpftoolPath, btfPath, outputDir string) *COREBuilder {
	return &COREBuilder{
		clangPath:   clangPath,
		bpftoolPath: bpftoolPath,
		btfPath:     btfPath,
		outputDir:   outputDir,
		includePaths: []string{
			"/usr/include",
			"/usr/include/x86_64-linux-gnu",
			"/usr/src/linux-headers-$(uname -r)/include",
		},
	}
}

// BuildProgram compiles an eBPF program using CO-RE
func (b *COREBuilder) BuildProgram(ctx context.Context, config BuildConfig) (*BuildResult, error) {
	start := time.Now()
	
	// Ensure output directory exists
	if err := os.MkdirAll(b.outputDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create output directory: %w", err)
	}

	// Generate object file path
	objFile := filepath.Join(b.outputDir, config.OutputFile)
	btfFile := strings.TrimSuffix(objFile, ".o") + ".btf"

	// Build C flags
	cflags := []string{
		"-g",                    // Debug info for BTF
		"-O2",                   // Optimization
		"-target", "bpf",        // BPF target
		"-c",                    // Compile only
		"-o", objFile,           // Output file
	}

	// Add include paths
	for _, incPath := range b.includePaths {
		cflags = append(cflags, "-I", incPath)
	}
	for _, incPath := range config.IncludePaths {
		cflags = append(cflags, "-I", incPath)
	}

	// Add custom C flags
	cflags = append(cflags, config.CFlags...)

	// Add source file
	cflags = append(cflags, config.SourceFile)

	// Run clang
	cmd := exec.CommandContext(ctx, b.clangPath, cflags...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return &BuildResult{Error: err}, fmt.Errorf("clang compilation failed: %w", err)
	}

	// Generate BTF from object file
	if err := b.generateBTF(ctx, objFile, btfFile); err != nil {
		return &BuildResult{Error: err}, fmt.Errorf("BTF generation failed: %w", err)
	}

	// Get file size
	stat, err := os.Stat(objFile)
	if err != nil {
		return &BuildResult{Error: err}, fmt.Errorf("failed to stat object file: %w", err)
	}

	buildTime := time.Since(start)

	return &BuildResult{
		ObjectFile:  objFile,
		BTFPath:     btfFile,
		ProgramType: config.ProgramType,
		AttachType:  config.AttachType,
		BuildTime:   buildTime,
		Size:        stat.Size(),
	}, nil
}

// generateBTF creates BTF from object file using bpftool
func (b *COREBuilder) generateBTF(ctx context.Context, objFile, btfFile string) error {
	cmd := exec.CommandContext(ctx, b.bpftoolPath, "gen", "skeleton", objFile)
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("bpftool gen skeleton failed: %w", err)
	}

	// Write skeleton to file
	skeletonFile := strings.TrimSuffix(objFile, ".o") + ".skel.h"
	if err := os.WriteFile(skeletonFile, output, 0644); err != nil {
		return fmt.Errorf("failed to write skeleton file: %w", err)
	}

	// Generate BTF dump
	btfCmd := exec.CommandContext(ctx, b.bpftoolPath, "btf", "dump", "file", objFile)
	btfOutput, err := btfCmd.Output()
	if err != nil {
		return fmt.Errorf("bpftool btf dump failed: %w", err)
	}

	if err := os.WriteFile(btfFile, btfOutput, 0644); err != nil {
		return fmt.Errorf("failed to write BTF file: %w", err)
	}

	return nil
}

// BuildTemplate compiles a template eBPF program
func (b *COREBuilder) BuildTemplate(ctx context.Context, templateName string, params map[string]interface{}) (*BuildResult, error) {
	templatePath := filepath.Join("ebpf/templates", templateName+".c")
	
	// Check if template exists
	if _, err := os.Stat(templatePath); os.IsNotExist(err) {
		return nil, fmt.Errorf("template %s not found", templateName)
	}

	// Generate output filename
	outputFile := fmt.Sprintf("%s_%d.o", templateName, time.Now().Unix())

	config := BuildConfig{
		SourceFile:  templatePath,
		OutputFile:  outputFile,
		ProgramType: "xdp", // Default, can be overridden
		AttachType:  "xdp",
		CFlags:      []string{},
	}

	// Apply template parameters as C defines
	for key, value := range params {
		define := fmt.Sprintf("-D%s=%v", strings.ToUpper(key), value)
		config.CFlags = append(config.CFlags, define)
	}

	return b.BuildProgram(ctx, config)
}

// ListTemplates returns available eBPF templates
func (b *COREBuilder) ListTemplates() ([]string, error) {
	templatesDir := "ebpf/templates"
	entries, err := os.ReadDir(templatesDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read templates directory: %w", err)
	}

	var templates []string
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".c") {
			templates = append(templates, strings.TrimSuffix(entry.Name(), ".c"))
		}
	}

	return templates, nil
}

// ValidateBuildEnvironment checks if required tools are available
func (b *COREBuilder) ValidateBuildEnvironment() error {
	// Check clang
	if _, err := exec.LookPath(b.clangPath); err != nil {
		return fmt.Errorf("clang not found at %s: %w", b.clangPath, err)
	}

	// Check bpftool
	if _, err := exec.LookPath(b.bpftoolPath); err != nil {
		return fmt.Errorf("bpftool not found at %s: %w", b.bpftoolPath, err)
	}

	// Check BTF availability
	btfCmd := exec.Command(b.bpftoolPath, "btf", "dump", "file", "/sys/kernel/btf/vmlinux")
	if err := btfCmd.Run(); err != nil {
		return fmt.Errorf("BTF not available: %w", err)
	}

	return nil
}

// GetBuildInfo returns build environment information
func (b *COREBuilder) GetBuildInfo() map[string]interface{} {
	info := map[string]interface{}{
		"clang_path":   b.clangPath,
		"bpftool_path": b.bpftoolPath,
		"btf_path":     b.btfPath,
		"output_dir":   b.outputDir,
		"include_paths": b.includePaths,
	}

	// Get clang version
	if clangVersion, err := exec.Command(b.clangPath, "--version").Output(); err == nil {
		info["clang_version"] = strings.TrimSpace(string(clangVersion))
	}

	// Get bpftool version
	if bpftoolVersion, err := exec.Command(b.bpftoolPath, "version").Output(); err == nil {
		info["bpftool_version"] = strings.TrimSpace(string(bpftoolVersion))
	}

	return info
}
