package capability

import (
	"encoding/json"
	"time"
	"github.com/nats-io/nats.go"
)

func Publish(nc *nats.Conn, hostID string, res Result) error {
	if nc == nil { return nil }
	payload := map[string]any{"host_id":hostID, "capability":res, "ts": time.Now().UTC().Format(time.RFC3339)}
	b, _ := json.Marshal(payload)
	return nc.Publish("agent.capability", b)
}
