package control

import (
	"encoding/json"
	"errors"
	"os"
	"regexp"
)

// OrderInput saves one list's order (drag and drop). Order is presentation
// only: it never changes configuration or the order rules are applied in.
type OrderInput struct {
	List string   `json:"list"`
	IDs  []string `json:"ids"`
}

// orderLists are the lists people can reorder.
var orderLists = map[string]bool{"connections": true, "gre": true, "reverse": true, "nodes": true, "overview": true}

var orderID = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,64}$`)

const maxOrder = 1024

func (o *Operations) readOrder() map[string][]string {
	out := map[string][]string{}
	data, e := os.ReadFile(o.orderPath)
	if e != nil {
		return out
	}
	var saved map[string][]string
	if json.Unmarshal(data, &saved) != nil {
		return out
	}
	for list, ids := range saved {
		if orderLists[list] && validOrder(ids) {
			out[list] = ids
		}
	}
	return out
}

func validOrder(ids []string) bool {
	if len(ids) > maxOrder {
		return false
	}
	seen := map[string]bool{}
	for _, id := range ids {
		if !orderID.MatchString(id) || seen[id] {
			return false
		}
		seen[id] = true
	}
	return true
}

// order serves ui-order (all lists) and ui-order-save (one list).
func (m *Manager) order(r Request) (any, error) {
	o := m.Ops
	if o == nil || o.orderPath == "" {
		return map[string][]string{}, nil
	}
	o.orderMu.Lock()
	defer o.orderMu.Unlock()
	lists := o.readOrder()
	if r.Action == "ui-order" {
		return lists, nil
	}
	in := r.Order
	if !orderLists[in.List] || !validOrder(in.IDs) {
		return nil, errors.New("invalid list order")
	}
	if len(in.IDs) == 0 {
		delete(lists, in.List)
	} else {
		lists[in.List] = in.IDs
	}
	data, e := json.Marshal(lists)
	if e != nil {
		return nil, e
	}
	if e := writePrivate(o.orderPath, data); e != nil {
		return nil, e
	}
	return lists, nil
}
