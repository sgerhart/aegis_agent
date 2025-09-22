package communication

// CommunicationChannels defines the communication channels
type CommunicationChannels struct {
	// Agent to Backend channels
	PolicyUpdates    string
	AnomalyAlerts    string
	ThreatMatches    string
	ProcessEvents    string
	DependencyData   string
	TestResults      string
	RollbackStatus   string
	Heartbeat        string
	Status           string
	Logs             string
	
	// Backend to Agent channels
	PolicyCommands   string
	InvestigationReq string
	ThreatIntel      string
	ProcessPolicies  string
	TestCommands     string
	RollbackCommands string
}

// SecureMessage represents an encrypted message
type SecureMessage struct {
	ID        string            `json:"id"`
	Type      MessageType       `json:"type"`
	Channel   string            `json:"channel"`
	Payload   string            `json:"payload"`      // Encrypted
	Timestamp int64             `json:"timestamp"`
	Nonce     string            `json:"nonce"`
	Signature string            `json:"signature"`
	Headers   map[string]string `json:"headers"`
}

// MessageType represents the type of message
type MessageType string

const (
	MessageTypeRequest  MessageType = "request"
	MessageTypeResponse MessageType = "response"
	MessageTypeEvent    MessageType = "event"
	MessageTypeHeartbeat MessageType = "heartbeat"
	MessageTypeAck      MessageType = "ack"
)

