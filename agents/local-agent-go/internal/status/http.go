package status

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/cilium/ebpf"
)

type Status struct {
	Loaded       map[string]time.Time // artifact_id -> expires_at
	ActiveGen    int64                // current active generation
	Generations  map[int64][]string   // generation -> artifact_ids
	mu           sync.RWMutex
}

type Verifier interface {
	GetLastError() (string, time.Time)
}

type Loader interface {
	GetAttachedHooks() []AttachedHook
	GetPinnedMaps() map[string]string
	GetGeneration() int64
}

type SegEgressLoader interface {
	GetAttachedPrograms() []string
	GetMaps() map[string]*ebpf.Map
}

type SegIngressLoader interface {
	GetAttachedPrograms() []string
	GetMaps() map[string]*ebpf.Map
}

type CPUWatcher interface {
	GetStats() map[string]interface{}
	GetWatchedArtifacts() []string
}

type AttachedHook struct {
	ProgramName string    `json:"program_name"`
	HookType    string    `json:"hook_type"`
	Target      string    `json:"target"`
	AttachedAt  time.Time `json:"attached_at"`
	Status      string    `json:"status"`
}

func New() *Status { 
	return &Status{
		Loaded:      map[string]time.Time{},
		ActiveGen:   1,
		Generations: map[int64][]string{},
	}
}

func (s *Status) TrackLoaded(id string, exp time.Time) { 
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Loaded[id] = exp
}

func (s *Status) GetActiveGeneration() int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.ActiveGen
}

func (s *Status) IncrementGeneration() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ActiveGen++
	return s.ActiveGen
}

func (s *Status) AddToGeneration(artifactID string, gen int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Generations[gen] == nil {
		s.Generations[gen] = []string{}
	}
	s.Generations[gen] = append(s.Generations[gen], artifactID)
}

func (s *Status) RemoveFromGeneration(artifactID string, gen int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if artifacts, exists := s.Generations[gen]; exists {
		for i, id := range artifacts {
			if id == artifactID {
				s.Generations[gen] = append(artifacts[:i], artifacts[i+1:]...)
				break
			}
		}
	}
}

func (s *Status) GetGenerationArtifacts(gen int64) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.Generations[gen]
}

func (s *Status) RollbackToPreviousGeneration() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	if s.ActiveGen <= 1 {
		return []string{} // No previous generation to rollback to
	}
	
	prevGen := s.ActiveGen - 1
	artifacts := s.Generations[prevGen]
	
	// Remove current generation artifacts from loaded
	for _, artifactID := range s.Generations[s.ActiveGen] {
		delete(s.Loaded, artifactID)
	}
	
	// Add previous generation artifacts back to loaded
	for _, artifactID := range artifacts {
		s.Loaded[artifactID] = time.Now().Add(30 * time.Minute) // Reset expiry
	}
	
	// Decrement active generation
	s.ActiveGen = prevGen
	
	return artifacts
}

func RegisterHandlers(mux *http.ServeMux, s *Status, verifier Verifier, segEgressLoader SegEgressLoader, segIngressLoader SegIngressLoader, cpuWatcher CPUWatcher){
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request){
		w.Header().Set("content-type","application/json"); w.Write([]byte(`{"ok":true}`))
	})
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request){
		w.Header().Set("content-type","application/json")
		
		statusData := map[string]any{
			"loaded": s.Loaded, 
			"cpu_pct": GetCPU(),
			"active_gen": s.GetActiveGeneration(),
		}
		
		// Add verifier error if available
		if verifier != nil {
			lastError, lastErrorTime := verifier.GetLastError()
			if lastError != "" {
				statusData["last_verifier_error"] = lastError
				statusData["last_verifier_error_time"] = lastErrorTime.Format(time.RFC3339)
			}
		}
		
		// Add segmentation loader information
		if segEgressLoader != nil {
			statusData["egress_attached_programs"] = segEgressLoader.GetAttachedPrograms()
			if maps := segEgressLoader.GetMaps(); maps != nil {
				statusData["egress_maps"] = len(maps)
			}
		}
		
		if segIngressLoader != nil {
			statusData["ingress_attached_programs"] = segIngressLoader.GetAttachedPrograms()
			if maps := segIngressLoader.GetMaps(); maps != nil {
				statusData["ingress_maps"] = len(maps)
			}
		}
		
		// Add CPU watcher information
		if cpuWatcher != nil {
			statusData["cpu_watcher"] = cpuWatcher.GetStats()
			statusData["watched_artifacts"] = cpuWatcher.GetWatchedArtifacts()
		}
		
		_ = json.NewEncoder(w).Encode(statusData)
	})
}
