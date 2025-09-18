package status

import (
	"encoding/json"
	"net/http"
	"time"
)

type Status struct {
	Loaded map[string]time.Time // artifact_id -> expires_at
}

type Verifier interface {
	GetLastError() (string, time.Time)
}

type Loader interface {
	GetAttachedHooks() []AttachedHook
	GetPinnedMaps() map[string]string
	GetGeneration() int64
}

type AttachedHook struct {
	ProgramName string    `json:"program_name"`
	HookType    string    `json:"hook_type"`
	Target      string    `json:"target"`
	AttachedAt  time.Time `json:"attached_at"`
	Status      string    `json:"status"`
}

func New() *Status { return &Status{Loaded: map[string]time.Time{}} }

func (s *Status) TrackLoaded(id string, exp time.Time){ s.Loaded[id] = exp }

func RegisterHandlers(mux *http.ServeMux, s *Status, verifier Verifier, loader Loader){
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request){
		w.Header().Set("content-type","application/json"); w.Write([]byte(`{"ok":true}`))
	})
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request){
		w.Header().Set("content-type","application/json")
		
		statusData := map[string]any{
			"loaded": s.Loaded, 
			"cpu_pct": GetCPU(),
		}
		
		// Add verifier error if available
		if verifier != nil {
			lastError, lastErrorTime := verifier.GetLastError()
			if lastError != "" {
				statusData["last_verifier_error"] = lastError
				statusData["last_verifier_error_time"] = lastErrorTime.Format(time.RFC3339)
			}
		}
		
		// Add loader information if available
		if loader != nil {
			statusData["attached_hooks"] = loader.GetAttachedHooks()
			statusData["pinned_maps"] = loader.GetPinnedMaps()
			statusData["generation"] = loader.GetGeneration()
		}
		
		_ = json.NewEncoder(w).Encode(statusData)
	})
}
