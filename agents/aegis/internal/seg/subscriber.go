package seg

import (
	"context"
	"encoding/json"
	"log"

	"agents/aegis/internal/policy"
	"github.com/nats-io/nats.go"
)

type MapSnapshot struct {
	Version    int               `json:"version"`
	ServiceID  uint32            `json:"service_id"`
	Edges      []struct{DstCIDR, Proto string; Port int} `json:"edges"`
	AllowCIDRs []struct{CIDR, Proto string; Port int}     `json:"allow_cidrs"`
	TTLSeconds int               `json:"ttl_seconds"`
	Meta       map[string]string `json:"meta,omitempty"`
}

func StartSubscriber(ctx context.Context, nc *nats.Conn, subject string) error {
	if nc == nil { return nil }
	sub, err := nc.Subscribe(subject, func(m *nats.Msg){
		var snap MapSnapshot
		if err := json.Unmarshal(m.Data, &snap); err != nil { log.Printf("[seg] bad payload: %v", err); return }
		if err := ApplySnapshot(snap); err != nil { log.Printf("[seg] apply: %v", err) }
	})
	if err != nil { return err }
	go func(){ <-ctx.Done(); _ = sub.Unsubscribe(); _ = nc.Drain() }()
	return nil
}

func ApplySnapshot(s MapSnapshot) error {
	log.Printf("[seg] APPLY snapshot v=%d svc=%d edges=%d ingress=%d", s.Version, s.ServiceID, len(s.Edges), len(s.AllowCIDRs))
	// Convert to encoder types
	edges := make([]policy.Edge, 0, len(s.Edges))
	for _, e := range s.Edges {
		edges = append(edges, policy.Edge{ServiceID: s.ServiceID, Proto: e.Proto, Port: uint16(e.Port), DstCIDR: e.DstCIDR})
	}
	allows := make([]policy.AllowCIDR, 0, len(s.AllowCIDRs))
	for _, a := range s.AllowCIDRs {
		allows = append(allows, policy.AllowCIDR{CIDR: a.CIDR, Proto: a.Proto, Port: uint16(a.Port)})
	}
	if err := policy.WriteEdges(edges); err != nil { return err }
	if err := policy.WriteAllowCIDRs(allows); err != nil { return err }
	return nil
}
