package loader

import (
	"fmt"

	"github.com/cilium/ebpf/link"
)

// AttachTCIngress attaches a tc classifier program to the given iface index.
func AttachTCIngress(ifaceIndex int, objPath string) (link.Link, error) {
	// TODO: ensure clsact qdisc exists (use netlink) then attach classifier
	var progFd int = -1 // TODO: load program and set fd
	lk, err := link.AttachTC(link.TCOptions{
		Interface: ifaceIndex,
		AttachPoint: link.ingress,
		ProgFD: progFd,
	})
	if err != nil { return nil, fmt.Errorf("attach tc ingress: %w", err) }
	return lk, nil
}
