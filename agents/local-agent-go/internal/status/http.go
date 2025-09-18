package status

import (
	"encoding/json"
	"net/http"
	"time"
)

type Status struct {
	Loaded map[string]time.Time
}

func New() *Status {
	return &Status{Loaded: map[string]time.Time{}}
}

func (s *Status) TrackLoaded(id string, expiresAt time.Time) {
	s.Loaded[id] = expiresAt
}

func RegisterHandlers(mux *http.ServeMux, s *Status) {
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		w.Write([]byte(`{"ok":true}`))
	})
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"loaded": s.Loaded,
		})
	})
}
