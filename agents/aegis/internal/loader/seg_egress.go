package loader

import (
	"fmt"
	"os"

	"github.com/cilium/ebpf/link"
)

// AttachConnect4 attaches a cgroup/connect4 program to a given cgroup path.
func AttachConnect4(cgroupPath string, objPath string) (link.Link, error) {
	cg, err := os.Open(cgroupPath)
	if err != nil { return nil, fmt.Errorf("open cgroup: %w", err) }
	// NOTE: In production, load the eBPF program from objPath and pass its FD.
	// Here we only show the attach call placeholder.
	var progFd int = -1 // TODO: load program and set fd
	lk, err := link.AttachCgroup(link.CgroupOptions{
		Path: cgroupPath,
		Attach: link.AttachCGroupInet4Connect,
		ProgFD: progFd,
	})
	if err != nil { return nil, fmt.Errorf("attach connect4: %w", err) }
	_ = cg.Close()
	return lk, nil
}
