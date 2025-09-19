# Actions API Backend

The Actions API backend provides agent registration and management capabilities for the AegisFlux system.

## Features

- **Agent Registration**: Two-phase registration process with signature verification
- **Agent Management**: List, get, and manage agent metadata
- **Label Management**: Add/remove labels from agents
- **Note Management**: Add notes to agents
- **Rich Metadata**: Support for capabilities, platform info, and network details

## API Endpoints

### Registration

#### POST /agents/register/init
Initialize agent registration with rich metadata.

**Request Body:**
```json
{
  "org_id": "acme-corp",
  "host_id": "ab1bca3c59a4433c9a68f5fb415ae934",
  "agent_pubkey": "base64-encoded-public-key",
  "machine_id_hash": "sha256-hash-of-machine-id",
  "agent_version": "1.0.0",
  "capabilities": {
    "ebpf": true,
    "tc": true,
    "cgroup": true
  },
  "platform": {
    "os": "linux",
    "arch": "aarch64",
    "kernel": "6.8.0-83-generic"
  },
  "network": {
    "ifaces": {
      "addrs": ["192.168.193.128", "fe80::1234:5678:9abc:def0"]
    }
  }
}
```

**Response:**
```json
{
  "registration_id": "uuid-here",
  "nonce": "base64-encoded-nonce",
  "server_time": "2025-09-19T12:00:00Z"
}
```

#### POST /agents/register/complete
Complete agent registration with signature verification.

**Request Body:**
```json
{
  "registration_id": "uuid-here",
  "host_id": "ab1bca3c59a4433c9a68f5fb415ae934",
  "signature": "base64-encoded-signature"
}
```

**Response:**
```json
{
  "agent_uid": "agent-uuid-here",
  "bootstrap_token": "bootstrap-token-here"
}
```

### Agent Management

#### GET /agents
List all agents with optional filtering.

**Query Parameters:**
- `label`: Filter by label (exact match)
- `hostname`: Filter by hostname (exact match)
- `host_id`: Filter by host ID (exact match)
- `ip`: Filter by IP address (searches in network.ifaces.addrs)

**Example:**
```bash
curl "http://localhost:8083/agents?label=production&ip=192.168.193.128"
```

**Response:**
```json
{
  "agents": [
    {
      "agent_uid": "agent-uuid-here",
      "org_id": "acme-corp",
      "host_id": "ab1bca3c59a4433c9a68f5fb415ae934",
      "hostname": "testhost-1",
      "machine_id_hash": "sha256-hash",
      "agent_version": "1.0.0",
      "capabilities": {
        "ebpf": true,
        "tc": true,
        "cgroup": true
      },
      "platform": {
        "os": "linux",
        "arch": "aarch64",
        "kernel": "6.8.0-83-generic"
      },
      "network": {
        "ifaces": {
          "addrs": ["192.168.193.128", "fe80::1234:5678:9abc:def0"]
        }
      },
      "labels": ["production", "web-server"],
      "note": "Primary web server",
      "public_key": "base64-encoded-public-key",
      "registered_at": "2025-09-19T12:00:00Z",
      "last_seen_at": "2025-09-19T12:00:00Z"
    }
  ],
  "total": 1
}
```

#### GET /agents/{agent_uid}
Get specific agent details.

**Example:**
```bash
curl "http://localhost:8083/agents/agent-uuid-here"
```

**Response:**
```json
{
  "agent_uid": "agent-uuid-here",
  "org_id": "acme-corp",
  "host_id": "ab1bca3c59a4433c9a68f5fb415ae934",
  "hostname": "testhost-1",
  "machine_id_hash": "sha256-hash",
  "agent_version": "1.0.0",
  "capabilities": {
    "ebpf": true,
    "tc": true,
    "cgroup": true
  },
  "platform": {
    "os": "linux",
    "arch": "aarch64",
    "kernel": "6.8.0-83-generic"
  },
  "network": {
    "ifaces": {
      "addrs": ["192.168.193.128", "fe80::1234:5678:9abc:def0"]
    }
  },
  "labels": ["production", "web-server"],
  "note": "Primary web server",
  "public_key": "base64-encoded-public-key",
  "registered_at": "2025-09-19T12:00:00Z",
  "last_seen_at": "2025-09-19T12:00:00Z"
}
```

#### PUT /agents/{agent_uid}/labels
Update agent labels.

**Request Body:**
```json
{
  "add": ["production", "web-server"],
  "remove": ["staging"]
}
```

**Example:**
```bash
curl -X PUT "http://localhost:8083/agents/agent-uuid-here/labels" \
  -H "Content-Type: application/json" \
  -d '{"add": ["production", "web-server"], "remove": ["staging"]}'
```

**Response:**
Returns the updated agent object (same as GET /agents/{agent_uid}).

#### PUT /agents/{agent_uid}/note
Update agent note.

**Request Body:**
```json
{
  "note": "Updated note about this agent"
}
```

**Example:**
```bash
curl -X PUT "http://localhost:8083/agents/agent-uuid-here/note" \
  -H "Content-Type: application/json" \
  -d '{"note": "Primary web server in production"}'
```

**Response:**
Returns the updated agent object (same as GET /agents/{agent_uid}).

## Running the Server

### Build and Run
```bash
cd backend/actions-api
go mod tidy
go run cmd/server/main.go
```

### With Custom Address
```bash
go run cmd/server/main.go -addr :8083
```

### Docker
```bash
# Build
docker build -t actions-api .

# Run
docker run -p 8083:8083 actions-api
```

## Example Usage

### 1. Register an Agent
```bash
# Step 1: Initialize registration
curl -X POST "http://localhost:8083/agents/register/init" \
  -H "Content-Type: application/json" \
  -d '{
    "org_id": "acme-corp",
    "host_id": "ab1bca3c59a4433c9a68f5fb415ae934",
    "agent_pubkey": "base64-public-key-here",
    "machine_id_hash": "sha256-hash-of-machine-id",
    "agent_version": "1.0.0",
    "capabilities": {
      "ebpf": true,
      "tc": true,
      "cgroup": true
    },
    "platform": {
      "os": "linux",
      "arch": "aarch64",
      "kernel": "6.8.0-83-generic"
    },
    "network": {
      "ifaces": {
        "addrs": ["192.168.193.128"]
      }
    }
  }'

# Step 2: Complete registration (with signature)
curl -X POST "http://localhost:8083/agents/register/complete" \
  -H "Content-Type: application/json" \
  -d '{
    "registration_id": "uuid-from-step-1",
    "host_id": "ab1bca3c59a4433c9a68f5fb415ae934",
    "signature": "base64-signature-here"
  }'
```

### 2. List All Agents
```bash
curl "http://localhost:8083/agents"
```

### 3. Filter Agents
```bash
# By label
curl "http://localhost:8083/agents?label=production"

# By IP address
curl "http://localhost:8083/agents?ip=192.168.193.128"

# By hostname
curl "http://localhost:8083/agents?hostname=testhost-1"
```

### 4. Manage Agent Labels
```bash
# Add labels
curl -X PUT "http://localhost:8083/agents/agent-uuid-here/labels" \
  -H "Content-Type: application/json" \
  -d '{"add": ["production", "web-server"]}'

# Remove labels
curl -X PUT "http://localhost:8083/agents/agent-uuid-here/labels" \
  -H "Content-Type: application/json" \
  -d '{"remove": ["staging"]}'
```

### 5. Update Agent Note
```bash
curl -X PUT "http://localhost:8083/agents/agent-uuid-here/note" \
  -H "Content-Type: application/json" \
  -d '{"note": "Primary web server in production"}'
```

## Error Responses

The API returns standard HTTP status codes:

- `200 OK`: Success
- `400 Bad Request`: Invalid request data
- `404 Not Found`: Resource not found
- `409 Conflict`: Agent already registered
- `410 Gone`: Registration expired
- `401 Unauthorized`: Invalid signature
- `405 Method Not Allowed`: Invalid HTTP method

Error responses include a JSON body with error details:
```json
{
  "error": "Agent not found"
}
```

## Storage

Currently uses in-memory storage. All data is lost when the server restarts. For production use, consider implementing persistent storage with a database.

