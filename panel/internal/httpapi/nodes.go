package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/control"
	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/nodes"
)

func (s *Server) nodeRoutes(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/api/nodes" && r.Method == "GET" {
		out := nodes.Listing{Protocol: nodes.Protocol, Nodes: []nodes.View{}}
		if s.Nodes != nil {
			out = s.Nodes.Views()
		}
		local := nodes.View{ID: "local", Name: "Controller", Local: true, Status: "degraded", Protocol: nodes.Protocol, Capabilities: []string{"inventory.read"}, Failure: &nodes.Problem{Code: "inventory_unavailable", Message: "Local inventory could not be read"}}
		if s.Nodes != nil {
			local.Capabilities = append(local.Capabilities, control.NodeOperationCapability)
		}
		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()
		raw, e := s.Client.Do(ctx, control.Request{Action: "inventory"})
		if e == nil {
			var inv control.Inventory
			if json.Unmarshal(raw, &inv) == nil {
				now := time.Now()
				local.Status = "online"
				local.LastSeen = &now
				local.Observed = &now
				local.Inventory = raw
				local.Name = inv.Host.Hostname
				local.Version = inv.Version
				local.Failure = nil
			}
		}
		out.Nodes = append([]nodes.View{local}, out.Nodes...)
		reply(w, 200, out)
		return
	}
	if s.Nodes == nil {
		failure(w, 409, "Remote nodes are optional; configure the Controller to enroll agents")
		return
	}
	if r.URL.Path == "/api/nodes/traffic" && r.Method == "GET" {
		out, e := s.Nodes.Traffic(r.URL.Query().Get("id"))
		if e != nil {
			failure(w, 404, "Node not found")
			return
		}
		reply(w, 200, out)
		return
	}
	if r.URL.Path == "/api/nodes/pairs" {
		if r.Method == "GET" {
			reply(w, 200, s.Nodes.Pairs())
			return
		}
		if r.Method == "POST" {
			var in nodes.PairRequest
			if !decode(w, r, &in) {
				return
			}
			out, e := s.Nodes.CreatePair(in)
			if e != nil {
				failure(w, 409, e.Error())
				return
			}
			reply(w, 202, out)
			return
		}
	}
	if r.URL.Path == "/api/nodes/pairs/decision" && r.Method == "POST" {
		var in struct {
			ID       string `json:"id"`
			Revision string `json:"revision"`
			Decision string `json:"decision"`
		}
		if !decode(w, r, &in) {
			return
		}
		out, e := s.Nodes.PairDecision(in.ID, in.Revision, in.Decision)
		if e != nil {
			failure(w, 409, e.Error())
			return
		}
		reply(w, 200, out)
		return
	}
	if r.URL.Path == "/api/nodes/invitations" && r.Method == "POST" {
		var in struct {
			Name string `json:"name"`
		}
		if !decode(w, r, &in) {
			return
		}
		out, e := s.Nodes.Invite(in.Name)
		if e != nil {
			failure(w, 409, e.Error())
			return
		}
		reply(w, 201, out)
		return
	}
	if r.URL.Path == "/api/nodes/revoke" && r.Method == "POST" {
		var in struct {
			ID       string `json:"id"`
			Revision string `json:"revision"`
		}
		if !decode(w, r, &in) {
			return
		}
		if e := s.Nodes.Revoke(in.ID, in.Revision); e != nil {
			failure(w, 409, e.Error())
			return
		}
		reply(w, 200, map[string]bool{"ok": true})
		return
	}
	failure(w, 404, "not found")
}
