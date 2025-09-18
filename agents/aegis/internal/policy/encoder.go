package policy

import (
	"fmt"
	"net"
	"strings"

	"github.com/cilium/ebpf"
)

// Map names expected to be pinned by BPF progs
const (
	PinBase        = "/sys/fs/bpf/aegis"
	PinPolicyEdges = PinBase + "/policy_edges"
	PinAllowLPM4   = PinBase + "/allow_lpm4"
	PinMeta        = PinBase + "/meta" // optional versioning
)

type Edge struct {
	ServiceID uint32
	Proto     string // "tcp"/"udp"/"any"
	Port      uint16 // 0=any
	DstCIDR   string // e.g. 10.0.0.0/24 or 10.0.0.5/32
}

type AllowCIDR struct {
	CIDR  string
	Proto string
	Port  uint16
}

// Encode and write edges into the policy_edges hash map.
// The eBPF key matches seg_egress_cgroup.bpf.c struct layout.
func WriteEdges(edges []Edge) error {
	m, err := ebpf.LoadPinnedMap(PinPolicyEdges, nil)
	if err != nil { return fmt.Errorf("open policy_edges: %w", err) }
	defer m.Close()
	for _, e := range edges {
		if strings.Contains(e.DstCIDR, ":") { continue } // skip v6 in this MVP
		_, ipnet, err := net.ParseCIDR(e.DstCIDR)
		if err != nil { return fmt.Errorf("bad cidr %s: %w", e.DstCIDR, err) }
		// take the network address; for /32 dst this equals host
		daddr := ipnet.IP.To4()
		if daddr == nil { continue }
		key := struct{
			Svid  uint32
			Proto uint8
			Dport uint16
			Daddr uint32
		}{ ServiceIDToSvid(e.ServiceID), protoNum(e.Proto), htons(e.Port), ipToU32(daddr) }
		val := struct{ Allow uint32 }{ Allow: 1 }
		if err := m.Update(&key, &val, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update edge %v: %w", e, err)
		}
	}
	return nil
}

func WriteAllowCIDRs(allows []AllowCIDR) error {
	m, err := ebpf.LoadPinnedMap(PinAllowLPM4, nil)
	if err != nil { return fmt.Errorf("open allow_lpm4: %w", err) }
	defer m.Close()
	for _, a := range allows {
		ip, ipnet, err := net.ParseCIDR(a.CIDR)
		if err != nil { return fmt.Errorf("bad cidr %s: %w", a.CIDR, err) }
		ones, _ := ipnet.Mask.Size()
		key := struct{
			Prefixlen uint32
			Addr     uint32
		}{ Prefixlen: uint32(ones), Addr: ipToU32(ip.To4()) }
		val := struct{
			Dport uint16
			Proto uint8
			Pad   uint8
		}{ Dport: htons(a.Port), Proto: protoNum(a.Proto) }
		if err := m.Update(&key, &val, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("update allow %v: %w", a, err)
		}
	}
	return nil
}

// Helpers

func ServiceIDToSvid(s uint32) uint32 { return s }

func protoNum(p string) uint8 {
	switch strings.ToLower(p) {
	case "tcp": return 6
	case "udp": return 17
	default: return 0
	}
}

func htons(v uint16) uint16 { return (v<<8)&0xff00 | v>>8 }

func ipToU32(b []byte) uint32 {
	if len(b) != 4 { return 0 }
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}
