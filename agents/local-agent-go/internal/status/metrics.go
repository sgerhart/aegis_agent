package status

import "sync/atomic"

var cpu atomic.Value // float64

func SetCPU(p float64){ cpu.Store(p) }
func GetCPU() float64 {
	v := cpu.Load()
	if v == nil { return 0 }
	return v.(float64)
}
