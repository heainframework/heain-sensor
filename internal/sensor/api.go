package sensor

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/heainframework/heain-sdk/heain"
)

// App-plane API (mTLS, served by heain-sdk). Device and rule management is
// declared public, so heain-gateway may expose it to sensor-admins (P5):
//
//	POST   /v1/devices {id, name, type, metrics, commands, readers, controllers} -> {device, key}  (admin)
//	GET    /v1/devices   GET /v1/devices/{id}                                         (admin, or a reader of it)
//	POST   /v1/devices/{id}/rotate   POST /v1/devices/{id}/revoke   DELETE /v1/devices/{id}  (admin)
//	GET    /v1/devices/{id}/readings?metric=&from=&to=&limit=                         (admin, readers)
//	PUT    /v1/rules/{id} {device, kind, metric, op, value, for, severity, notify} -> P5   (admin)
//	DELETE /v1/rules/{id} -> P5                                                       (admin)
//	GET    /v1/rules   GET /v1/alerts                                                 (admin)
//	POST   /v1/devices/{id}/commands {name, args, ttl_s}                              (controllers, admin)
//	GET    /v1/commands/{id}                                                          (who sent it, admin)

func reply(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, code int, c, msg string) {
	reply(w, code, map[string]any{"error": map[string]any{"code": c, "message": msg}})
}

func answer(w http.ResponseWriter, code int, v any, err error) {
	switch {
	case err == nil:
		reply(w, code, v)
	case errors.Is(err, ErrNotFound):
		fail(w, http.StatusNotFound, "not_found", err.Error())
	case errors.Is(err, ErrInvalid):
		fail(w, http.StatusBadRequest, "bad_request", err.Error())
	case errors.Is(err, ErrConflict):
		fail(w, http.StatusConflict, "conflict", err.Error())
	case errors.Is(err, ErrForbidden):
		fail(w, http.StatusForbidden, "forbidden", err.Error())
	default:
		fail(w, http.StatusServiceUnavailable, "unavailable", err.Error())
	}
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil && !errors.Is(err, io.EOF) {
		fail(w, http.StatusBadRequest, "bad_request", "body: "+err.Error())
		return false
	}
	return true
}

func who(r *http.Request) Who {
	app, _, _ := strings.Cut(heain.Caller(r.Context()), ".")
	w := Who{App: app}
	if u := heain.UserOf(r.Context()); u != nil {
		w.User, w.Roles, w.Person = u.ID, u.Roles, true
	}
	return w
}

func (w Who) name() string {
	if w.Person {
		return w.User
	}
	return w.App
}

// Register adds the endpoints to the app's server.
func (e *Engine) Register(srv *heain.Server) error {
	for pat, h := range map[string]http.HandlerFunc{
		"POST /v1/devices":               e.register,
		"GET /v1/devices":                e.list,
		"GET /v1/devices/{id}":           e.get,
		"POST /v1/devices/{id}/rotate":   e.rotate,
		"POST /v1/devices/{id}/revoke":   e.revoke,
		"DELETE /v1/devices/{id}":        e.del,
		"GET /v1/devices/{id}/readings":  e.readings,
		"PUT /v1/rules/{id}":             e.putRule,
		"DELETE /v1/rules/{id}":          e.delRule,
		"GET /v1/rules":                  e.rules,
		"GET /v1/alerts":                 e.alerts,
		"GET /v1/notices":                e.notices,
		"POST /v1/devices/{id}/commands": e.command,
		"GET /v1/commands/{id}":          e.getCommand,
	} {
		if err := srv.HandleFunc(pat, h); err != nil {
			return err
		}
	}
	return nil
}

func (e *Engine) mustAdmin(w http.ResponseWriter, r *http.Request) (Who, bool) {
	x := who(r)
	if !e.admin(x) {
		fail(w, http.StatusForbidden, "forbidden", "needs the "+AdminRole+" role (or an admin app)")
		return x, false
	}
	return x, true
}

func (e *Engine) register(w http.ResponseWriter, r *http.Request) {
	x, ok := e.mustAdmin(w, r)
	if !ok {
		return
	}
	var q DeviceInput
	if !decode(w, r, &q) {
		return
	}
	d, key, err := e.RegisterDevice(r.Context(), q, x.name())
	answer(w, http.StatusCreated, map[string]any{"device": d, "key": key, "note": "the key is shown once; put it on the device"}, err)
}

func (e *Engine) list(w http.ResponseWriter, r *http.Request) {
	x := who(r)
	out := []Device{}
	for _, d := range e.Store.Devices() {
		if e.MayRead(d, x) {
			out = append(out, d)
		}
	}
	reply(w, http.StatusOK, map[string]any{"devices": out, "trust": Trust})
}

func (e *Engine) get(w http.ResponseWriter, r *http.Request) {
	d, err := e.Store.Device(r.PathValue("id"))
	if err == nil && !e.MayRead(d, who(r)) {
		err = ErrNotFound
	}
	answer(w, http.StatusOK, map[string]any{"device": d, "trust": Trust}, err)
}

func (e *Engine) rotate(w http.ResponseWriter, r *http.Request) {
	x, ok := e.mustAdmin(w, r)
	if !ok {
		return
	}
	d, key, err := e.Rotate(r.Context(), r.PathValue("id"), x.name())
	answer(w, http.StatusOK, map[string]any{"device": d.ID, "key_version": d.KeyVersion, "key": key}, err)
}

func (e *Engine) revoke(w http.ResponseWriter, r *http.Request) {
	x, ok := e.mustAdmin(w, r)
	if !ok {
		return
	}
	d, err := e.Revoke(r.Context(), r.PathValue("id"), x.name())
	answer(w, http.StatusOK, map[string]any{"device": d.ID, "revoked": d.Revoked}, err)
}

func (e *Engine) del(w http.ResponseWriter, r *http.Request) {
	x, ok := e.mustAdmin(w, r)
	if !ok {
		return
	}
	err := e.Delete(r.Context(), r.PathValue("id"), x.name())
	answer(w, http.StatusOK, map[string]any{"deleted": true, "crypto_shredded": true}, err)
}

func (e *Engine) readings(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	now := e.Now()
	from, to := now.Add(-24*time.Hour), now.Add(time.Minute)
	if v := q.Get("from"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			fail(w, http.StatusBadRequest, "bad_request", "from: RFC 3339")
			return
		}
		from = t
	}
	if v := q.Get("to"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			fail(w, http.StatusBadRequest, "bad_request", "to: RFC 3339")
			return
		}
		to = t
	}
	limit, _ := strconv.Atoi(q.Get("limit"))
	rs, err := e.Query(r.Context(), who(r), r.PathValue("id"), q.Get("metric"), from, to, limit)
	answer(w, http.StatusOK, map[string]any{"device": r.PathValue("id"), "metric": q.Get("metric"), "trust": Trust, "readings": rs}, err)
}

func (e *Engine) putRule(w http.ResponseWriter, r *http.Request) {
	x, ok := e.mustAdmin(w, r)
	if !ok {
		return
	}
	var s RuleSpec
	if !decode(w, r, &s) {
		return
	}
	rule, err := e.ProposeRule(r.Context(), r.PathValue("id"), &s, false, x.name())
	answer(w, http.StatusAccepted, rule, err)
}

func (e *Engine) delRule(w http.ResponseWriter, r *http.Request) {
	x, ok := e.mustAdmin(w, r)
	if !ok {
		return
	}
	rule, err := e.ProposeRule(r.Context(), r.PathValue("id"), nil, true, x.name())
	answer(w, http.StatusAccepted, rule, err)
}

func (e *Engine) rules(w http.ResponseWriter, r *http.Request) {
	if _, ok := e.mustAdmin(w, r); ok {
		reply(w, http.StatusOK, map[string]any{"rules": e.Store.Rules()})
	}
}

func (e *Engine) alerts(w http.ResponseWriter, r *http.Request) {
	if _, ok := e.mustAdmin(w, r); ok {
		reply(w, http.StatusOK, map[string]any{"alerts": e.Store.Alerts(), "trust": Trust})
	}
}

// notices: alert notices heain-notify has not taken yet (v1.1).
func (e *Engine) notices(w http.ResponseWriter, r *http.Request) {
	if _, ok := e.mustAdmin(w, r); ok {
		reply(w, http.StatusOK, map[string]any{"pending": e.Pending()})
	}
}

func (e *Engine) command(w http.ResponseWriter, r *http.Request) {
	var q struct {
		Name string         `json:"name"`
		Args map[string]any `json:"args"`
		TTL  int            `json:"ttl_s"`
	}
	if !decode(w, r, &q) {
		return
	}
	c, err := e.SendCommand(r.Context(), who(r), r.PathValue("id"), q.Name, q.Args, time.Duration(q.TTL)*time.Second)
	answer(w, http.StatusAccepted, c, err)
}

func (e *Engine) getCommand(w http.ResponseWriter, r *http.Request) {
	c, err := e.Store.Cmd(r.PathValue("id"))
	x := who(r)
	if err == nil && !e.admin(x) && c.By != x.name() {
		err = ErrNotFound
	}
	answer(w, http.StatusOK, c, err)
}
