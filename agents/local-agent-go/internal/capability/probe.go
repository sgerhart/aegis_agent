package capability

import (
	"os"
	"runtime"
)

type Result struct {
	Kernel       string `json:"kernel"`
	BTF          bool   `json:"btf"`
	HasTC        bool   `json:"tc"`
	HasCgroup    bool   `json:"cgroup_connect"`
	HasLSM       bool   `json:"lsm_bpf"`
}

func Probe() Result {
	res := Result{ Kernel: runtime.GOOS + "/" + runtime.GOARCH }
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err == nil { res.BTF = true }
	if _, err := os.Stat("/sbin/tc"); err == nil { res.HasTC = true }
	if _, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); err == nil { res.HasCgroup = true }
	if b, err := os.ReadFile("/sys/kernel/security/lsm"); err == nil { res.HasLSM = (len(b) > 0) }
	return res
}
