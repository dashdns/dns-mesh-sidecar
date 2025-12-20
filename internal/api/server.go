package api

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
)

type BlocklistUpdateRequest struct {
	Blocklist []string `json:"blocklist"`
}

type Server struct {
	port           string
	verbose        bool
	updateChannel  chan []string
}

func NewServer(port string, verbose bool, updateChannel chan []string) *Server {
	return &Server{
		port:          port,
		verbose:       verbose,
		updateChannel: updateChannel,
	}
}

func (s *Server) Start() error {
	http.HandleFunc("/api/blocklist", s.handleBlocklistUpdate)

	if s.verbose {
		log.Printf("API server starting on %s", s.port)
	}

	return http.ListenAndServe(s.port, nil)
}

func (s *Server) handleBlocklistUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req BlocklistUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("Invalid JSON: %v", err), http.StatusBadRequest)
		return
	}

	if len(req.Blocklist) == 0 {
		http.Error(w, "Blocklist cannot be empty", http.StatusBadRequest)
		return
	}

	if s.verbose {
		log.Printf("Received blocklist update request with %d entries", len(req.Blocklist))
	}

	s.updateChannel <- req.Blocklist

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "success",
		"message": "Blocklist updated successfully",
		"count":   len(req.Blocklist),
	})
}
