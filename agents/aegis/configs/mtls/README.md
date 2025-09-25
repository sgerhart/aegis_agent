# mTLS Configuration

This directory contains the mTLS certificates and keys for secure communication between the agent and the registry.

## Files

- `agent.key` - Agent private key (PEM format)
- `agent.crt` - Agent certificate (PEM format)  
- `ca.crt` - Certificate Authority certificate (PEM format)

## Generation

To generate these certificates, use the following commands:

```bash
# Generate CA private key
openssl genrsa -out ca.key 4096

# Generate CA certificate
openssl req -new -x509 -days 365 -key ca.key -out ca.crt -subj "/CN=AegisCA"

# Generate agent private key
openssl genrsa -out agent.key 4096

# Generate agent certificate signing request
openssl req -new -key agent.key -out agent.csr -subj "/CN=aegis-agent"

# Sign agent certificate with CA
openssl x509 -req -days 365 -in agent.csr -CA ca.crt -CAkey ca.key -out agent.crt -CAcreateserial
```

## Security

- Keep private keys secure and never commit them to version control
- Use proper file permissions (600 for private keys, 644 for certificates)
- Rotate certificates regularly
- Use strong key sizes (4096 bits recommended)


