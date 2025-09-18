package capability

import (
	"context"
	"os"
	"runtime"
)

type Result struct {
	Kernel       string `json:"kernel"`
	BTFAvailable bool   `json:"btf_available"`
	BPFFeatures  []string `json:"bpf_features"`
	HasTC        bool   `json:"tc"`
	HasCgroup    bool   `json:"cgroup_connect"`
	HasLSM       bool   `json:"lsm_bpf"`
}

type Probe struct{}

func New() *Probe {
	return &Probe{}
}

func (p *Probe) ProbeCapabilities(ctx context.Context) (*Result, error) {
	res := probeSystem()
	return &res, nil
}

func (p *Probe) PublishCapabilities(ctx context.Context, tel interface{}, hostID string) error {
	// Mock implementation
	return nil
}

func probeSystem() Result {
	res := Result{ 
		Kernel: runtime.GOOS + "/" + runtime.GOARCH,
		BPFFeatures: []string{},
	}
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err == nil { 
		res.BTFAvailable = true 
		res.BPFFeatures = append(res.BPFFeatures, "btf")
	}
	if _, err := os.Stat("/sbin/tc"); err == nil { 
		res.HasTC = true 
		res.BPFFeatures = append(res.BPFFeatures, "tc")
	}
	if _, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); err == nil { 
		res.HasCgroup = true 
		res.BPFFeatures = append(res.BPFFeatures, "cgroup")
	}
	if b, err := os.ReadFile("/sys/kernel/security/lsm"); err == nil { 
		res.HasLSM = (len(b) > 0)
		if res.HasLSM {
			res.BPFFeatures = append(res.BPFFeatures, "lsm")
		}
	}
	return res
}
