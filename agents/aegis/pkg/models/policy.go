package models

import "time"

// Policy represents a security policy
type Policy struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Type        string                 `json:"type"`
	Priority    int                    `json:"priority"`
	Enabled     bool                   `json:"enabled"`
	Rules       []Rule                 `json:"rules"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
}

// Rule represents a policy rule
type Rule struct {
	ID         string                 `json:"id"`
	Action     string                 `json:"action"`
	Priority   int                    `json:"priority"`
	Conditions []Condition            `json:"conditions"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
}

// Condition represents a policy condition
type Condition struct {
	Field    string      `json:"field"`
	Operator string      `json:"operator"`
	Value    interface{} `json:"value"`
}

// AgentStatus represents the status of an agent
type AgentStatus struct {
	AgentID     string                 `json:"agent_id"`
	Status      string                 `json:"status"`
	LastUpdate  time.Time              `json:"last_update"`
	PolicyCount int                    `json:"policy_count"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}
