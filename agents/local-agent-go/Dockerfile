# Build stage
FROM golang:1.23-alpine AS build
WORKDIR /src

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags='-w -s -extldflags "-static"' \
    -o /out/aegisflux-agent ./cmd/agent

# Runtime stage
FROM alpine:3.20

# Install runtime dependencies
RUN apk add --no-cache \
    ca-certificates \
    tzdata \
    && rm -rf /var/cache/apk/*

# Create non-root user
RUN addgroup -g 1000 agent && \
    adduser -D -u 1000 -G agent agent

# Create necessary directories
RUN mkdir -p /opt/aegisflux/bin \
    /opt/aegisflux/bundles \
    /var/log/aegisflux \
    && chown -R agent:agent /opt/aegisflux \
    && chown -R agent:agent /var/log/aegisflux

# Copy binary
COPY --from=build /out/aegisflux-agent /opt/aegisflux/bin/aegisflux-agent
RUN chmod +x /opt/aegisflux/bin/aegisflux-agent

# Set working directory
WORKDIR /opt/aegisflux

# Switch to non-root user
USER agent

# Expose health check port
EXPOSE 7070

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:7070/healthz || exit 1

# Default environment variables
ENV AGENT_HTTP_ADDR=:7070 \
    AGENT_POLL_INTERVAL=10s \
    AGENT_BUNDLES_DIR=/opt/aegisflux/bundles \
    AGENT_HOST_ID=host-unknown \
    AGENT_REGISTRY_URL=http://localhost:8090 \
    NATS_URL=nats://localhost:4222

# Entry point
ENTRYPOINT ["/opt/aegisflux/bin/aegisflux-agent"]
