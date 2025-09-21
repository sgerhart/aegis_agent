package ebpf

// MapManagerInterface defines the common interface for map managers
type MapManagerInterface interface {
	WritePolicyEdge(edgeID uint32, edge PolicyEdge) error
	WriteAllowCIDR(cidr AllowCIDR) error
	SetMode(mode uint32) error
	GetMode() (uint32, error)
	ClearPolicyEdges() error
	ClearAllowCIDRs() error
	Close() error
}

// Ensure all types implement the interface
var _ MapManagerInterface = (*MapManager)(nil)
var _ MapManagerInterface = (*MockMapManager)(nil)
var _ MapManagerInterface = (*AdvancedMapManager)(nil)

