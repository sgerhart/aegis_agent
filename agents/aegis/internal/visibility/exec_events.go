package visibility

import (
	"encoding/binary"
	"fmt"
	"log"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
)

// ExecEvent represents an exec event from eBPF
type ExecEvent struct {
	PID       uint32    `json:"pid"`
	PPID      uint32    `json:"ppid"`
	UID       uint32    `json:"uid"`
	GID       uint32    `json:"gid"`
	Exe       string    `json:"exe"`
	Args      []string  `json:"args"`
	Timestamp time.Time `json:"timestamp"`
}

// ExecEventConsumer consumes exec events from eBPF ring buffer
type ExecEventConsumer struct {
	ringBuffer *ringbuf.Reader
	eventChan  chan ExecEvent
	stopChan   chan struct{}
	running    bool
}

// NewExecEventConsumer creates a new exec event consumer
func NewExecEventConsumer() (*ExecEventConsumer, error) {
	// Load the eBPF program that generates exec events
	// This would be a separate eBPF program that traces execve syscalls
	spec, err := ebpf.LoadCollectionSpec("/opt/aegis-agent/bpf/bpf/exec_trace.o")
	if err != nil {
		return nil, fmt.Errorf("failed to load exec trace program: %w", err)
	}

	var coll ebpf.Collection
	if err := spec.LoadAndAssign(&coll, nil); err != nil {
		return nil, fmt.Errorf("failed to load exec trace collection: %w", err)
	}

	// Get the ring buffer map
	ringBufferMap := coll.Maps["exec_events"]
	if ringBufferMap == nil {
		return nil, fmt.Errorf("exec_events map not found")
	}

	// Create ring buffer reader
	ringBuffer, err := ringbuf.NewReader(ringBufferMap)
	if err != nil {
		return nil, fmt.Errorf("failed to create ring buffer reader: %w", err)
	}

	return &ExecEventConsumer{
		ringBuffer: ringBuffer,
		eventChan:  make(chan ExecEvent, 1000),
		stopChan:   make(chan struct{}),
		running:    false,
	}, nil
}

// Start starts consuming exec events
func (eec *ExecEventConsumer) Start() error {
	if eec.running {
		return fmt.Errorf("exec event consumer already running")
	}

	eec.running = true
	go eec.consumeEvents()
	
	log.Printf("[visibility] Started exec event consumer")
	return nil
}

// Stop stops consuming exec events
func (eec *ExecEventConsumer) Stop() error {
	if !eec.running {
		return fmt.Errorf("exec event consumer not running")
	}

	close(eec.stopChan)
	eec.running = false
	
	log.Printf("[visibility] Stopped exec event consumer")
	return nil
}

// GetEventChannel returns the event channel
func (eec *ExecEventConsumer) GetEventChannel() <-chan ExecEvent {
	return eec.eventChan
}

// consumeEvents consumes events from the ring buffer
func (eec *ExecEventConsumer) consumeEvents() {
	for {
		select {
		case <-eec.stopChan:
			return
		default:
			record, err := eec.ringBuffer.Read()
			if err != nil {
				if err == ringbuf.ErrClosed {
					return
				}
				log.Printf("[visibility] Error reading exec event: %v", err)
				continue
			}

			event, err := eec.parseExecEvent(record.RawSample)
			if err != nil {
				log.Printf("[visibility] Error parsing exec event: %v", err)
				continue
			}

			select {
			case eec.eventChan <- event:
			case <-eec.stopChan:
				return
			default:
				// Channel full, drop event
				log.Printf("[visibility] Dropped exec event (channel full)")
			}
		}
	}
}

// parseExecEvent parses an exec event from raw eBPF data
func (eec *ExecEventConsumer) parseExecEvent(data []byte) (ExecEvent, error) {
	if len(data) < 16 {
		return ExecEvent{}, fmt.Errorf("invalid exec event data length")
	}

	// Parse the eBPF event structure
	// This is a simplified parser - the actual structure would depend on the eBPF program
	pid := binary.LittleEndian.Uint32(data[0:4])
	ppid := binary.LittleEndian.Uint32(data[4:8])
	uid := binary.LittleEndian.Uint32(data[8:12])
	gid := binary.LittleEndian.Uint32(data[12:16])

	// Parse executable path (null-terminated string)
	exeEnd := 16
	for i := 16; i < len(data) && data[i] != 0; i++ {
		exeEnd = i + 1
	}
	exe := string(data[16:exeEnd])

	// Parse arguments (simplified - would need more complex parsing in practice)
	args := []string{exe} // First arg is the executable

	event := ExecEvent{
		PID:       pid,
		PPID:      ppid,
		UID:       uid,
		GID:       gid,
		Exe:       exe,
		Args:      args,
		Timestamp: time.Now(),
	}

	return event, nil
}

// Close closes the exec event consumer
func (eec *ExecEventConsumer) Close() error {
	if eec.running {
		if err := eec.Stop(); err != nil {
			return err
		}
	}

	if eec.ringBuffer != nil {
		return eec.ringBuffer.Close()
	}

	return nil
}

// MockExecEventConsumer creates a mock exec event consumer for testing
func MockExecEventConsumer() *ExecEventConsumer {
	return &ExecEventConsumer{
		ringBuffer: nil,
		eventChan:  make(chan ExecEvent, 1000),
		stopChan:   make(chan struct{}),
		running:    false,
	}
}

// GenerateMockEvents generates mock exec events for testing
func (eec *ExecEventConsumer) GenerateMockEvents() {
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				// Generate a mock exec event
				event := ExecEvent{
					PID:       uint32(time.Now().Unix() % 10000),
					PPID:      1,
					UID:       1000,
					GID:       1000,
					Exe:       "/usr/bin/example",
					Args:      []string{"/usr/bin/example", "--arg1", "value1"},
					Timestamp: time.Now(),
				}

				select {
				case eec.eventChan <- event:
				case <-eec.stopChan:
					return
				default:
					// Channel full, drop event
				}
			case <-eec.stopChan:
				return
			}
		}
	}()
}
