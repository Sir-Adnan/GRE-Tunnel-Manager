package httpapi

import (
	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/control"
	"net/http"
)

// These routes inherit session, CSRF, Origin and no-store checks. Larger bodies
// are limited to recovery; normal operation limits remain unchanged.
func (s *Server) backupRoutes(w http.ResponseWriter, r *http.Request) {
	select {
	case s.backupGate <- struct{}{}:
		defer func() { <-s.backupGate }()
	default:
		failure(w, 503, "another recovery request is running; wait for it to finish")
		return
	}
	if r.Method != "POST" {
		failure(w, 405, "use POST")
		return
	}
	action := ""
	switch r.URL.Path {
	case "/api/backups/export":
		action = "backup-export"
	case "/api/backups/review":
		action = "backup-review"
	case "/api/backups/restore":
		action = "backup-restore"
	default:
		failure(w, 404, "not found")
		return
	}
	var input control.BackupInput
	if !decodeLimit(w, r, &input, 32*1024*1024) {
		return
	}
	request := control.Request{Action: action, Backup: input}
	if action != "backup-restore" {
		s.forward(w, r, request)
		return
	}
	job, e := s.Jobs.Start(request)
	if e != nil {
		failure(w, 409, e.Error())
		return
	}
	reply(w, 202, job)
}
