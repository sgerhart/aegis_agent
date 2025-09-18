package seg

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/nats-io/nats.go"
	"agents/local-agent-go/internal/policy"
)

// MapSnapshot represents a snapshot of policy maps
type MapSnapshot struct {
	Timestamp   time.Time         `json:"timestamp"`
	PolicyEdges []policy.PolicyEdge `json:"policy_edges"`
	AllowCIDRs  []policy.AllowCIDR  `json:"allow_cidrs"`
	Metadata    map[string]string `json:"metadata"`
}

// Subscriber handles NATS subscription for policy updates
type Subscriber struct {
	nc           *nats.Conn
	policyWriter *policy.Writer
	subject      string
}

// NewSubscriber creates a new policy subscriber
func NewSubscriber(nc *nats.Conn, policyWriter *policy.Writer, subject string) *Subscriber {
	return &Subscriber{
		nc:           nc,
		policyWriter: policyWriter,
		subject:      subject,
	}
}

// Start begins listening for policy updates
func (s *Subscriber) Start(ctx context.Context) error {
	log.Printf("[seg_subscriber] Starting policy subscriber on subject: %s", s.subject)
	
	// Subscribe to policy updates
	sub, err := s.nc.Subscribe(s.subject, s.handleMessage)
	if err != nil {
		return fmt.Errorf("failed to subscribe to %s: %w", s.subject, err)
	}
	defer sub.Unsubscribe()

	// Wait for context cancellation
	<-ctx.Done()
	log.Printf("[seg_subscriber] Policy subscriber stopped")
	return nil
}

// handleMessage processes incoming policy update messages
func (s *Subscriber) handleMessage(msg *nats.Msg) {
	log.Printf("[seg_subscriber] Received policy update message")
	
	var snapshot MapSnapshot
	if err := json.Unmarshal(msg.Data, &snapshot); err != nil {
		log.Printf("[seg_subscriber] Failed to unmarshal policy snapshot: %v", err)
		return
	}

	// Apply the snapshot to the eBPF maps
	if err := s.ApplySnapshot(context.Background(), &snapshot); err != nil {
		log.Printf("[seg_subscriber] Failed to apply policy snapshot: %v", err)
		return
	}

	log.Printf("[seg_subscriber] Successfully applied policy snapshot with %d edges and %d CIDRs", 
		len(snapshot.PolicyEdges), len(snapshot.AllowCIDRs))
}

// ApplySnapshot applies a policy snapshot to the eBPF maps
func (s *Subscriber) ApplySnapshot(ctx context.Context, snapshot *MapSnapshot) error {
	log.Printf("[seg_subscriber] Applying policy snapshot with %d edges and %d CIDRs", 
		len(snapshot.PolicyEdges), len(snapshot.AllowCIDRs))

	// Write policy edges to the eBPF map
	if len(snapshot.PolicyEdges) > 0 {
		if err := s.policyWriter.WriteEdges(ctx, snapshot.PolicyEdges); err != nil {
			return fmt.Errorf("failed to write policy edges: %w", err)
		}
		log.Printf("[seg_subscriber] Wrote %d policy edges", len(snapshot.PolicyEdges))
	}

	// Write allow CIDRs to the eBPF map
	if len(snapshot.AllowCIDRs) > 0 {
		if err := s.policyWriter.WriteAllowCIDRs(ctx, snapshot.AllowCIDRs); err != nil {
			return fmt.Errorf("failed to write allow CIDRs: %w", err)
		}
		log.Printf("[seg_subscriber] Wrote %d allow CIDRs", len(snapshot.AllowCIDRs))
	}

	// Update metadata
	if snapshot.Metadata != nil {
		if err := s.policyWriter.WriteMetadata(ctx, snapshot.Metadata); err != nil {
			log.Printf("[seg_subscriber] Failed to write metadata: %v", err)
		}
	}

	log.Printf("[seg_subscriber] Successfully applied policy snapshot")
	return nil
}

// PublishTestSnapshot publishes a test snapshot for testing
func (s *Subscriber) PublishTestSnapshot(ctx context.Context) error {
	testSnapshot := &MapSnapshot{
		Timestamp: time.Now(),
		PolicyEdges: []policy.PolicyEdge{
			{
				ID:         1,
				SrcIP:      0xC0A80100, // 192.168.1.0
				DstIP:      0xC0A80200, // 192.168.2.0
				SrcMask:    0xFFFFFF00, // 255.255.255.0
				DstMask:    0xFFFFFF00, // 255.255.255.0
				SrcPort:    80,
				DstPort:    443,
				Protocol:   6, // TCP
				Action:     1, // ALLOW
				Priority:   10,
				ProcessUID: 1000,
				ProcessGID: 1000,
				Timestamp:  uint64(time.Now().Unix()),
			},
		},
		AllowCIDRs: []policy.AllowCIDR{
			{
				PrefixLen: 24,
				IP:        0xC0A80100, // 192.168.1.0/24
				Action:    1,          // ALLOW
				Priority:  5,
				Timestamp: uint64(time.Now().Unix()),
			},
		},
		Metadata: map[string]string{
			"source":    "test",
			"version":   "1.0",
			"timestamp": time.Now().Format(time.RFC3339),
		},
	}

	data, err := json.Marshal(testSnapshot)
	if err != nil {
		return fmt.Errorf("failed to marshal test snapshot: %w", err)
	}

	if err := s.nc.Publish(s.subject, data); err != nil {
		return fmt.Errorf("failed to publish test snapshot: %w", err)
	}

	log.Printf("[seg_subscriber] Published test snapshot to %s", s.subject)
	return nil
}
