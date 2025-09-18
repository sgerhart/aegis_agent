# Build stage
FROM golang:1.23-alpine AS build

WORKDIR /src

# Install build dependencies
RUN apk add --no-cache \
    git \
    ca-certificates \
    tzdata \
    clang \
    llvm \
    linux-headers \
    bpftool \
    iproute2 \
    iptables

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the agent
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags='-w -s -extldflags "-static"' \
    -o /out/segmentation-agent ./cmd/agent

# Build eBPF programs
RUN mkdir -p /out/ebpf
RUN clang -O2 -target bpf -c ebpf/templates/xdp_segmentation.c -o /out/ebpf/xdp_segmentation.o
RUN clang -O2 -target bpf -c ebpf/templates/tc_ingress.c -o /out/ebpf/tc_ingress.o
RUN clang -O2 -target bpf -c ebpf/templates/cgroup_connect4.c -o /out/ebpf/cgroup_connect4.o
RUN clang -O2 -target bpf -c ebpf/templates/cgroup_connect6.c -o /out/ebpf/cgroup_connect6.o

# Runtime stage
FROM alpine:3.20

# Install runtime dependencies
RUN apk add --no-cache \
    ca-certificates \
    tzdata \
    iproute2 \
    iptables \
    bpftool \
    && rm -rf /var/cache/apk/*

# Create user and directories
RUN addgroup -g 1000 agent && \
    adduser -D -u 1000 -G agent agent

RUN mkdir -p /opt/segmentation/bin \
    /opt/segmentation/ebpf \
    /opt/segmentation/policies \
    /var/log/segmentation \
    && chown -R agent:agent /opt/segmentation \
    && chown -R agent:agent /var/log/segmentation

# Copy binaries and eBPF programs
COPY --from=build /out/segmentation-agent /opt/segmentation/bin/segmentation-agent
COPY --from=build /out/ebpf/*.o /opt/segmentation/ebpf/

RUN chmod +x /opt/segmentation/bin/segmentation-agent

WORKDIR /opt/segmentation
USER agent

# Expose HTTP port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/healthz || exit 1

# Environment variables
ENV AGENT_HTTP_ADDR=:8080 \
    AGENT_POLL_INTERVAL=30s \
    AGENT_HOST_ID=segmentation-host \
    NATS_URL=nats://localhost:4222 \
    CLANG_PATH=clang \
    BPFTOOL_PATH=bpftool \
    BTF_PATH=/sys/kernel/btf/vmlinux \
    BUILD_OUTPUT_DIR=/opt/segmentation/ebpf

ENTRYPOINT ["/opt/segmentation/bin/segmentation-agent"]
