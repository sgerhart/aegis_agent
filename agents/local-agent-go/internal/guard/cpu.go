package guard

import "time"

type CPUWatcher struct {
	Max float64       // percentage threshold
	Win time.Duration // sampling window
}

func (c *CPUWatcher) Sample() float64 {
	// TODO: implement real sampling (e.g., /proc/stat diff)
	return 0.0
}
