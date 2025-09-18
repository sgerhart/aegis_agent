package policy
const (
	PinBase        = "/sys/fs/bpf/aegis"
	PinIdentities  = PinBase + "/identities"
	PinPolicyEdges = PinBase + "/policy_edges"
	PinAllowLPM4   = PinBase + "/allow_lpm4"
	PinConntrack   = PinBase + "/ct"
	PinCounters    = PinBase + "/counters"
	PinMeta        = PinBase + "/meta"
)
