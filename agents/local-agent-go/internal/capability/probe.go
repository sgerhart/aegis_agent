package capability

import (
    "os"
    "runtime"
)

type Result struct {
    Kernel    string `json:"kernel"`
    BTF       bool   `json:"btf"`
    HasTC     bool   `json:"tc"`
    HasCgroup bool   `json:"cgroup_connect"`
}

func Probe() Result {
    res := Result{Kernel: runtime.GOOS + "/" + runtime.GOARCH}
    if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err == nil { res.BTF = true }
    if _, err := os.Stat("/sbin/tc"); err == nil { res.HasTC = true }
    if _, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); err == nil { res.HasCgroup = true }
    return res
}
