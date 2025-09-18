package loader

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// Loader handles eBPF program loading and management
type Loader struct {
	programs map[string]*ebpf.Program
	links    map[string]interface{}
}

// ProgramInfo represents information about a loaded eBPF program
type ProgramInfo struct {
	Name        string    `json:"name"`
	Type        string    `json:"type"`
	AttachType  string    `json:"attach_type,omitempty"`
	LoadedAt    time.Time `json:"loaded_at"`
	ProgramID   uint32    `json:"program_id"`
	IsLoaded    bool      `json:"is_loaded"`
	Error       string    `json:"error,omitempty"`
}

// NewLoader creates a new eBPF loader
func NewLoader() *Loader {
	return &Loader{
		programs: make(map[string]*ebpf.Program),
		links:    make(map[string]interface{}),
	}
}

// LoadProgram loads an eBPF program from a bundle file
func (l *Loader) LoadProgram(ctx context.Context, bundlePath, programName string) (*ProgramInfo, error) {
	// Check if bundle file exists
	if _, err := os.Stat(bundlePath); os.IsNotExist(err) {
		return nil, fmt.Errorf("bundle file not found: %s", bundlePath)
	}

	// Determine file type and load accordingly
	ext := filepath.Ext(bundlePath)
	var spec *ebpf.CollectionSpec
	var err error

	switch ext {
	case ".o", ".elf":
		// Load from ELF object file
		spec, err = ebpf.LoadCollectionSpec(bundlePath)
		if err != nil {
			return nil, fmt.Errorf("failed to load ELF collection spec: %w", err)
		}
	case ".tar.gz", ".tgz":
		// Extract and load from tarball
		spec, err = l.loadFromTarball(ctx, bundlePath, programName)
		if err != nil {
			return nil, fmt.Errorf("failed to load from tarball: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported bundle format: %s", ext)
	}

	// Load the collection
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("failed to load collection: %w", err)
	}
	defer coll.Close()

	// Find the specific program
	program, ok := coll.Programs[programName]
	if !ok {
		return nil, fmt.Errorf("program %s not found in collection", programName)
	}

	// Store the program
	l.programs[programName] = program

	// Create program info
	info := &ProgramInfo{
		Name:     programName,
		Type:     program.Type().String(),
		LoadedAt: time.Now(),
		IsLoaded: true,
	}

	return info, nil
}

// AttachProgram attaches a loaded program to a hook point
func (l *Loader) AttachProgram(ctx context.Context, programName, attachType, target string) error {
	program, ok := l.programs[programName]
	if !ok {
		return fmt.Errorf("program %s not loaded", programName)
	}

	// For now, we'll just store the program without actual attachment
	// In a real implementation, you would use the appropriate link types
	linkName := fmt.Sprintf("%s_%s", programName, attachType)
	
	// Create a mock link (in real implementation, this would be a proper link)
	mockLink := &mockLink{program: program}
	l.links[linkName] = mockLink

	return nil
}

// mockLink is a placeholder for link functionality
type mockLink struct {
	program *ebpf.Program
}

func (m *mockLink) Close() error {
	return nil
}

func (m *mockLink) Info() (*link.Info, error) {
	return &link.Info{}, nil
}

func (m *mockLink) Pin(string) error {
	return nil
}

func (m *mockLink) Unpin() error {
	return nil
}

func (m *mockLink) Update(*ebpf.Program) error {
	return nil
}

func (m *mockLink) isLink() {}

// UnloadProgram unloads a program and its attachments
func (l *Loader) UnloadProgram(ctx context.Context, programName string) error {
	// Close all links for this program
	for linkName, link := range l.links {
		if len(linkName) > len(programName) && linkName[:len(programName)] == programName {
			if closeable, ok := link.(interface{ Close() error }); ok {
				closeable.Close()
			}
			delete(l.links, linkName)
		}
	}

	// Remove the program
	if program, ok := l.programs[programName]; ok {
		program.Close()
		delete(l.programs, programName)
	}

	return nil
}

// GetProgramInfo returns information about a loaded program
func (l *Loader) GetProgramInfo(programName string) *ProgramInfo {
	program, ok := l.programs[programName]
	if !ok {
		return &ProgramInfo{
			Name:     programName,
			IsLoaded: false,
			Error:    "program not loaded",
		}
	}

	return &ProgramInfo{
		Name:     programName,
		Type:     program.Type().String(),
		LoadedAt: time.Now(), // This should be stored when loaded
		IsLoaded: true,
	}
}

// ListPrograms returns information about all loaded programs
func (l *Loader) ListPrograms() []ProgramInfo {
	var programs []ProgramInfo
	for name := range l.programs {
		programs = append(programs, *l.GetProgramInfo(name))
	}
	return programs
}

// Close closes all loaded programs and links
func (l *Loader) Close() error {
	// Close all links
	for _, link := range l.links {
		if closeable, ok := link.(interface{ Close() error }); ok {
			closeable.Close()
		}
	}
	l.links = make(map[string]interface{})

	// Close all programs
	for _, program := range l.programs {
		program.Close()
	}
	l.programs = make(map[string]*ebpf.Program)

	return nil
}

// loadFromTarball extracts and loads eBPF programs from a tarball
func (l *Loader) loadFromTarball(ctx context.Context, bundlePath, programName string) (*ebpf.CollectionSpec, error) {
	// This is a simplified implementation
	// In a real implementation, you would:
	// 1. Extract the tarball
	// 2. Find the eBPF object file
	// 3. Load the collection spec
	// 4. Clean up extracted files
	
	// For now, return an error indicating this needs to be implemented
	return nil, fmt.Errorf("tarball loading not yet implemented")
}
