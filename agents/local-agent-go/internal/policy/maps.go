package policy

const (
    PinBase        = "/sys/fs/bpf/aegis"
    PinPolicyEdges = PinBase + "/policy_edges"
    PinAllowLPM4   = PinBase + "/allow_lpm4"
)
