// Package sensor is heain-sensor's engine (author decisions 2026-10-07):
// devices outside the trust boundary (ESP32-class) post signed batches of
// readings over HTTPS (a key per device, HMAC-SHA256, a sequence number
// against replay); readings are stored sealed per device, marked
// untrusted_source, and read by apps by their rights; alert rules (changed
// through P5) tell people through heain-notify and record formal events in
// core; apps queue commands that devices pick up, risky ones after P5.
package sensor

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/heainframework/heain-sdk/heain"
)

// Trust is how every value from a device is marked (spec 01 §2, spec 00 §3).
const Trust = "untrusted_source"

// AdminRole manages devices and rules (through heain-gateway).
const AdminRole = "sensor-admin"

var (
	idRe   = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)
	nameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,62}$`)
)

// Errors the API maps to status codes.
var (
	ErrInvalid   = errors.New("invalid")
	ErrConflict  = errors.New("conflict")
	ErrForbidden = errors.New("forbidden")
	ErrAuth      = errors.New("device authentication failed")
)

func invalid(f string, a ...any) error { return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(f, a...)) }
func conflict(f string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrConflict, fmt.Sprintf(f, a...))
}

// Platform is what the engine needs from heain-core (through heain-sdk).
type Platform interface {
	Propose(ctx context.Context, p heain.Proposal) (heain.PolicyResult, error)
	PolicyStatus(ctx context.Context, actionID string) (heain.PolicyResult, error)
	Call(ctx context.Context, cs heain.CallSpec) (int, error)
	Audit(ctx context.Context, capability, outcome string, d map[string]any) error
}

// Config tunes the engine.
type Config struct {
	AdminCallers []string
	NotifyApp    string        // default heain-notify
	Retention    time.Duration // readings older than this are removed (default 30 days)
	MaxSkew      time.Duration // a reading's time may be this far from now (default 10 min)
	RatePerMin   int           // posts per device per minute (default 120)
	CommandTTL   time.Duration // default 1 hour
	PollEvery    time.Duration
	NoticeMaxAge time.Duration // v1.1: a notice heain-notify never took is given up after this (default 24 h)
}

// Engine is heain-sensor.
type Engine struct {
	Cfg   Config
	Store *Store
	Plat  Platform
	Logf  func(string, ...any)
	Now   func() time.Time

	mu       sync.Mutex // devices (seq), alerts, commands, rules
	rate     map[string][]time.Time
	authFail map[string]time.Time // last audited authentication failure per device
	last     time.Time
}

// New prepares an engine.
func New(e *Engine) *Engine {
	if e.Now == nil {
		e.Now = time.Now
	}
	if e.Logf == nil {
		e.Logf = func(string, ...any) {}
	}
	c := &e.Cfg
	if c.NotifyApp == "" {
		c.NotifyApp = "heain-notify"
	}
	if c.Retention <= 0 {
		c.Retention = 30 * 24 * time.Hour
	}
	if c.MaxSkew <= 0 {
		c.MaxSkew = 10 * time.Minute
	}
	if c.RatePerMin <= 0 {
		c.RatePerMin = 120
	}
	if c.CommandTTL <= 0 {
		c.CommandTTL = time.Hour
	}
	if c.PollEvery <= 0 {
		c.PollEvery = 3 * time.Second
	}
	if c.NoticeMaxAge <= 0 {
		c.NoticeMaxAge = 24 * time.Hour
	}
	e.rate, e.authFail = map[string][]time.Time{}, map[string]time.Time{}
	return e
}

func (e *Engine) audit(ctx context.Context, cap, outcome string, d map[string]any) {
	// its own trace: a served call already has exactly one formal record
	if t := heain.TraceID(ctx); t != "" {
		d["cause_trace"] = t
	}
	if err := e.Plat.Audit(heain.WithTrace(ctx, heain.NewID(), ""), cap, outcome, d); err != nil {
		e.Logf("heain-sensor: audit %s %s: %v", cap, outcome, err)
	}
}

// tell hands an alert notice to heain-notify (v1.1): the notice is kept
// until heain-notify takes it, so a notify instance that is down or
// restarting delays the notice but does not lose it; the idempotency key
// makes a retry after a lost answer the same message.
func (e *Engine) tell(ctx context.Context, to []string, kind, title, ref, sev string) {
	if len(to) == 0 {
		return
	}
	now := e.Now().UTC()
	n := Notice{ID: heain.NewID(), To: to, Kind: kind, Title: title, Ref: ref, Severity: sev, Next: now, Created: now}
	e.mu.Lock()
	err := e.Store.PutNotice(n)
	e.mu.Unlock()
	if err != nil {
		e.Logf("heain-sensor: keeping a notice: %v", err)
	}
	e.send(ctx, n)
}

var noticeBackoff = []time.Duration{5 * time.Second, 15 * time.Second, 30 * time.Second, time.Minute, 2 * time.Minute, 5 * time.Minute}

// send tries one notice; it is removed once heain-notify has taken it.
func (e *Engine) send(ctx context.Context, n Notice) {
	var out map[string]any
	_, err := e.Plat.Call(ctx, heain.CallSpec{App: e.Cfg.NotifyApp, Capability: "notify.send", Method: http.MethodPost, Path: "/v1/messages",
		Body: map[string]any{"to": n.To, "kind": n.Kind, "title": n.Title, "ref": n.Ref, "severity": n.Severity, "idempotency_key": n.ID}, Out: &out})
	now := e.Now().UTC()
	n.Attempts++
	outcome, det := "", map[string]any{"ref": n.Ref, "kind": n.Kind, "attempts": n.Attempts}
	e.mu.Lock()
	switch {
	case err == nil:
		_ = e.Store.DelNotice(n.ID)
		if n.Attempts > 1 {
			outcome, det["delay_s"] = "notice_delivered_late", int(now.Sub(n.Created).Seconds())
		}
	case now.Sub(n.Created) > e.Cfg.NoticeMaxAge:
		_ = e.Store.DelNotice(n.ID)
		outcome, det["error"] = "notice_given_up", trim(err.Error(), 200)
	default:
		b := noticeBackoff[len(noticeBackoff)-1]
		if n.Attempts-1 < len(noticeBackoff) {
			b = noticeBackoff[n.Attempts-1]
		}
		n.Next, n.LastErr = now.Add(b), trim(err.Error(), 200)
		_ = e.Store.PutNotice(n)
		if n.Attempts == 1 {
			outcome, det["error"] = "notice_queued", trim(err.Error(), 200)
		}
	}
	e.mu.Unlock()
	if outcome != "" {
		e.Logf("heain-sensor: notice %s (%s): %s after %d attempt(s)", n.ID, n.Ref, outcome, n.Attempts)
		e.audit(ctx, "sensor.alert", outcome, det)
	}
}

// resend retries the notices whose time has come.
func (e *Engine) resend(ctx context.Context) {
	now := e.Now()
	for _, n := range e.Store.Notices() {
		if !now.Before(n.Next) {
			e.send(ctx, n)
		}
	}
}

// Pending lists the notices heain-notify has not taken yet.
func (e *Engine) Pending() []Notice { return e.Store.Notices() }

func in(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// ---- devices ----

// DeviceInput registers a device.
type DeviceInput struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Type        string    `json:"type"`
	Metrics     []Metric  `json:"metrics"`
	Commands    []Command `json:"commands"`
	Readers     []string  `json:"readers"`
	Controllers []string  `json:"controllers"`
}

func (in DeviceInput) validate() error {
	switch {
	case !idRe.MatchString(in.ID):
		return invalid("id: [a-z0-9._-], up to 63 characters")
	case in.Type != "" && !nameRe.MatchString(in.Type):
		return invalid("type")
	case len(in.Name) > 120:
		return invalid("name: at most 120 characters")
	case len(in.Metrics) == 0 || len(in.Metrics) > 64:
		return invalid("metrics: 1 to 64 {name, unit, min, max}")
	case len(in.Commands) > 64:
		return invalid("commands: at most 64")
	}
	for _, m := range in.Metrics {
		if !nameRe.MatchString(m.Name) || len(m.Unit) > 16 || (m.Min != nil && m.Max != nil && *m.Min > *m.Max) {
			return invalid("metric %q", m.Name)
		}
	}
	for _, c := range in.Commands {
		if !nameRe.MatchString(c.Name) {
			return invalid("command %q", c.Name)
		}
	}
	for _, a := range append(append([]string{}, in.Readers...), in.Controllers...) {
		if !idRe.MatchString(a) {
			return invalid("%q is not an app id", a)
		}
	}
	return nil
}

func newSecret() ([]byte, string) {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return b, base64.RawURLEncoding.EncodeToString(b)
}

// RegisterDevice adds a device and returns its key (shown once).
func (e *Engine) RegisterDevice(ctx context.Context, in DeviceInput, by string) (Device, string, error) {
	if err := in.validate(); err != nil {
		return Device{}, "", err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, err := e.Store.Device(in.ID); err == nil {
		return Device{}, "", conflict("device %s exists", in.ID)
	}
	d := Device{ID: in.ID, Name: in.Name, Type: in.Type, Metrics: in.Metrics, Commands: in.Commands, Readers: in.Readers, Controllers: in.Controllers,
		Key: e.Store.KeyName(in.ID), KeyVersion: 1, Created: e.Now().UTC()}
	secret, shown := newSecret()
	if err := e.Store.PutSecret(ctx, d, secret); err != nil {
		return Device{}, "", err
	}
	if err := e.Store.PutDevice(d); err != nil {
		return Device{}, "", err
	}
	e.audit(ctx, "sensor.admin", "device_registered", map[string]any{"device": d.ID, "type": d.Type, "metrics": len(d.Metrics), "by": by})
	return d, shown, nil
}

// Rotate gives a device a new key; the old one stops working at once.
func (e *Engine) Rotate(ctx context.Context, id, by string) (Device, string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	d, err := e.Store.Device(id)
	if err != nil {
		return d, "", err
	}
	secret, shown := newSecret()
	if err := e.Store.PutSecret(ctx, d, secret); err != nil {
		return d, "", err
	}
	d.KeyVersion++
	d.Revoked = false
	if err := e.Store.PutDevice(d); err != nil {
		return d, "", err
	}
	e.audit(ctx, "sensor.admin", "device_key_rotated", map[string]any{"device": id, "key_version": d.KeyVersion, "by": by})
	return d, shown, nil
}

// Revoke stops a device at once (its data stays until it is deleted).
func (e *Engine) Revoke(ctx context.Context, id, by string) (Device, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	d, err := e.Store.Device(id)
	if err != nil {
		return d, err
	}
	d.Revoked = true
	if err := e.Store.PutDevice(d); err != nil {
		return d, err
	}
	e.audit(ctx, "sensor.admin", "device_revoked", map[string]any{"device": id, "by": by})
	return d, nil
}

// Delete destroys a device's key: its secret and readings are gone.
func (e *Engine) Delete(ctx context.Context, id, by string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	d, err := e.Store.Device(id)
	if err != nil {
		return err
	}
	if err := e.Store.DeleteDevice(ctx, d); err != nil {
		return err
	}
	e.audit(ctx, "sensor.admin", "device_deleted", map[string]any{"device": id, "crypto_shredded": true, "by": by})
	return nil
}

// ---- ingest (devices) ----

// Signed is what a device signs: HMAC-SHA256(key, this string), hex.
func Signed(method, path, device string, seq uint64, t int64, body []byte) string {
	h := sha256.Sum256(body)
	return method + "\n" + path + "\n" + device + "\n" + strconv.FormatUint(seq, 10) + "\n" + strconv.FormatInt(t, 10) + "\n" + hex.EncodeToString(h[:])
}

// ResponseSigned is what heain-sensor signs back with the device's key.
func ResponseSigned(device string, seq uint64, body []byte) string {
	h := sha256.Sum256(body)
	return "response\n" + device + "\n" + strconv.FormatUint(seq, 10) + "\n" + hex.EncodeToString(h[:])
}

// MAC computes the hex HMAC-SHA256.
func MAC(key []byte, s string) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(s))
	return hex.EncodeToString(m.Sum(nil))
}

// Batch is what a device posts.
type Batch struct {
	Readings []struct {
		Metric string  `json:"metric"`
		Value  float64 `json:"value"`
		T      int64   `json:"t,omitempty"` // unix milliseconds (default: now)
	} `json:"readings"`
	Results []struct {
		Command string `json:"command"`
		Status  string `json:"status"` // done | failed
		Detail  string `json:"detail,omitempty"`
	} `json:"results,omitempty"`
}

// Answer is what a device gets back.
type Answer struct {
	Accepted    int              `json:"accepted"`
	Implausible int              `json:"implausible"`
	Commands    []map[string]any `json:"commands"`
}

// Ingest checks a device's signed post and stores its readings. It returns
// the answer and the device's key (to sign the answer).
func (e *Engine) Ingest(ctx context.Context, device string, seq uint64, t int64, sig string, method, path string, body []byte, b Batch) (Answer, []byte, error) {
	now := e.Now()
	e.mu.Lock()
	d, err := e.Store.Device(device)
	var key []byte
	if err == nil && !d.Revoked {
		key, err = e.Store.Secret(ctx, d)
	}
	fail := func(why string) (Answer, []byte, error) {
		if err == nil {
			d.Rejected++
			_ = e.Store.PutDevice(d)
		}
		last := e.authFail[device]
		e.authFail[device] = now
		e.mu.Unlock()
		if now.Sub(last) > time.Minute { // at most one audit a minute per device
			e.audit(ctx, "sensor.ingest", "rejected", map[string]any{"device": device, "reason": why, "trust": Trust})
		}
		return Answer{}, nil, fmt.Errorf("%w: %s", ErrAuth, why)
	}
	switch {
	case err != nil || d.Revoked:
		return fail("unknown or revoked device")
	case !hmac.Equal([]byte(MAC(key, Signed(method, path, device, seq, t, body))), []byte(strings.ToLower(sig))):
		return fail("bad signature")
	case seq <= d.LastSeq:
		return fail(fmt.Sprintf("sequence %d is not after %d (replay?)", seq, d.LastSeq))
	case t != 0 && (time.Unix(t, 0).Sub(now) > e.Cfg.MaxSkew || now.Sub(time.Unix(t, 0)) > e.Cfg.MaxSkew):
		return fail("the request time is too far from now")
	}
	// rate
	win := e.rate[device][:0]
	for _, x := range e.rate[device] {
		if now.Sub(x) < time.Minute {
			win = append(win, x)
		}
	}
	if len(win) >= e.Cfg.RatePerMin {
		e.rate[device] = win
		e.mu.Unlock()
		return Answer{}, nil, conflict("rate limit: %d posts a minute", e.Cfg.RatePerMin)
	}
	e.rate[device] = append(win, now)
	if len(b.Readings) > 500 || len(b.Results) > 64 {
		e.mu.Unlock()
		return Answer{}, nil, invalid("at most 500 readings and 64 results a post")
	}
	var rs []Reading
	ans := Answer{Commands: []map[string]any{}}
	for _, r := range b.Readings {
		m, ok := d.Metric(r.Metric)
		if !ok || math.IsNaN(r.Value) || math.IsInf(r.Value, 0) {
			ans.Implausible++
			continue // an undeclared metric is dropped
		}
		at := now
		if r.T != 0 {
			at = time.UnixMilli(r.T)
			if at.Sub(now) > e.Cfg.MaxSkew || now.Sub(at) > e.Cfg.Retention {
				ans.Implausible++
				continue
			}
		}
		rd := Reading{Metric: r.Metric, T: at.UTC(), Value: r.Value, Received: now.UTC(), Seq: seq}
		if (m.Min != nil && r.Value < *m.Min) || (m.Max != nil && r.Value > *m.Max) {
			rd.Implausible = true
			ans.Implausible++
		} else {
			ans.Accepted++
		}
		rs = append(rs, rd)
	}
	d.LastSeq, d.LastSeen = seq, now.UTC()
	d.Accepted += int64(ans.Accepted)
	d.Implausible += int64(ans.Implausible)
	if len(rs) > 0 {
		if err := e.Store.PutReadings(ctx, d, rs); err != nil {
			e.mu.Unlock()
			return Answer{}, nil, err
		}
	}
	if err := e.Store.PutDevice(d); err != nil {
		e.mu.Unlock()
		return Answer{}, nil, err
	}
	// command results, then the commands waiting for it
	var done []Cmd
	for _, res := range b.Results {
		c, err := e.Store.Cmd(res.Command)
		if err != nil || c.Device != device || c.State != "delivered" {
			continue
		}
		c.State, c.Result, c.Updated = "failed", trim(res.Detail, 200), now.UTC()
		if res.Status == "done" {
			c.State = "done"
		}
		_ = e.Store.PutCmd(c)
		done = append(done, c)
	}
	var sent []Cmd
	for _, c := range e.Store.Cmds() {
		if c.Device != device || c.State != "queued" {
			continue
		}
		if now.After(c.Expires) {
			c.State, c.Updated = "expired", now.UTC()
			_ = e.Store.PutCmd(c)
			continue
		}
		c.State, c.Updated = "delivered", now.UTC()
		_ = e.Store.PutCmd(c)
		sent = append(sent, c)
		ans.Commands = append(ans.Commands, map[string]any{"id": c.ID, "name": c.Name, "args": c.Args})
	}
	e.mu.Unlock()
	for _, c := range done {
		e.audit(ctx, "sensor.command", "command_"+c.State, map[string]any{"command": c.ID, "device": device, "name": c.Name, "trust": Trust})
	}
	for _, c := range sent {
		e.audit(ctx, "sensor.command", "command_delivered", map[string]any{"command": c.ID, "device": device, "name": c.Name})
	}
	e.evaluate(ctx, d, rs)
	return ans, key, nil
}

func trim(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// ---- reading data (apps) ----

// Who is the caller: an app, or a person through heain-gateway.
type Who struct {
	App    string
	User   string
	Roles  []string
	Person bool
}

func (e *Engine) admin(w Who) bool {
	if w.Person {
		return in(w.Roles, AdminRole)
	}
	return in(e.Cfg.AdminCallers, w.App)
}

// MayRead: an admin, or an app the device names as a reader.
func (e *Engine) MayRead(d Device, w Who) bool {
	return e.admin(w) || (!w.Person && (in(d.Readers, w.App) || in(d.Controllers, w.App)))
}

// Query reads a device's metric.
func (e *Engine) Query(ctx context.Context, w Who, id, metric string, from, to time.Time, limit int) ([]Reading, error) {
	d, err := e.Store.Device(id)
	if err != nil || !e.MayRead(d, w) {
		return nil, fmt.Errorf("device %s: %w", id, ErrNotFound)
	}
	if _, ok := d.Metric(metric); !ok {
		return nil, invalid("device %s has no metric %s", id, metric)
	}
	if limit <= 0 || limit > 5000 {
		limit = 1000
	}
	return e.Store.Readings(ctx, d, metric, from, to, limit)
}

// ---- rules ----

func validRule(s RuleSpec) error {
	switch {
	case s.Device == "" || len(s.Device) > 70:
		return invalid("device: a device id or type:<type>")
	case s.Kind != "threshold" && s.Kind != "silence":
		return invalid("kind: threshold or silence")
	case s.Kind == "threshold" && (!nameRe.MatchString(s.Metric) || (s.Op != ">" && s.Op != ">=" && s.Op != "<" && s.Op != "<=")):
		return invalid("a threshold rule needs metric and op (> >= < <=)")
	case s.Severity != "info" && s.Severity != "warning" && s.Severity != "critical":
		return invalid("severity: info, warning or critical")
	case len(s.Notify) > 16:
		return invalid("notify: at most 16 heain-notify targets")
	}
	if s.WhileSilent != nil {
		if s.Kind != "threshold" || !idRe.MatchString(s.WhileSilent.Device) {
			return invalid("while_silent: a threshold rule only, naming a device id")
		}
		if d, err := time.ParseDuration(s.WhileSilent.For); err != nil || d < time.Second {
			return invalid("while_silent.for: a duration such as 10m")
		}
	}
	if s.Kind == "silence" {
		if d, err := time.ParseDuration(s.For); err != nil || d < time.Second {
			return invalid("a silence rule needs for: a duration such as 5m")
		}
	} else if s.For != "" {
		if n, err := strconv.Atoi(s.For); err != nil || n < 1 || n > 1000 {
			return invalid("for: how many readings in a row (1 to 1000)")
		}
	}
	return nil
}

// ProposeRule asks P5 to set (or, with del, remove) a rule.
func (e *Engine) ProposeRule(ctx context.Context, id string, s *RuleSpec, del bool, by string) (Rule, error) {
	if !nameRe.MatchString(id) {
		return Rule{}, invalid("rule id")
	}
	if !del {
		if err := validRule(*s); err != nil {
			return Rule{}, err
		}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	r, err := e.Store.Rule(id)
	if errors.Is(err, ErrNotFound) {
		if del {
			return r, fmt.Errorf("rule %s: %w", id, ErrNotFound)
		}
		r = Rule{ID: id}
	} else if err != nil {
		return r, err
	}
	if r.ActionID != "" && (r.Proposed != nil || r.Delete) {
		return r, conflict("rule %s already has a change waiting for P5 (%s)", id, r.ActionID)
	}
	data := map[string]any{"rule": id, "delete": del, "by": by}
	if s != nil {
		data["kind"], data["device"], data["metric"], data["op"], data["value"], data["severity"] = s.Kind, s.Device, s.Metric, s.Op, s.Value, s.Severity
		if s.WhileSilent != nil {
			data["while_silent"] = map[string]any{"device": s.WhileSilent.Device, "for": s.WhileSilent.For}
		}
	}
	res, err := e.Plat.Propose(ctx, heain.Proposal{Type: "sensor.rule.change", Category: heain.CategoryKnowledgeUpdate, Data: data})
	if err != nil {
		return r, fmt.Errorf("P5: %w", err)
	}
	r.Proposed, r.Delete, r.ActionID, r.By, r.Updated = s, del, res.ActionID, by, e.Now().UTC()
	if err := e.Store.PutRule(r); err != nil {
		return r, err
	}
	e.audit(ctx, "sensor.admin", "rule_proposed", map[string]any{"rule": id, "delete": del, "action_id": res.ActionID, "by": by})
	return r, nil
}

func (e *Engine) pollRules(ctx context.Context) {
	for _, r := range e.Store.Rules() {
		if r.ActionID == "" || (r.Proposed == nil && !r.Delete) {
			continue
		}
		res, err := e.Plat.PolicyStatus(ctx, r.ActionID)
		if err != nil || res.Waiting() {
			continue
		}
		e.mu.Lock()
		outcome := "rule_denied"
		switch {
		case res.Allowed() && r.Delete:
			_ = e.Store.DelRule(r.ID)
			outcome = "rule_removed"
		case res.Allowed():
			r.Active, r.Proposed = r.Proposed, nil
			_ = e.Store.PutRule(r)
			outcome = "rule_activated"
		default:
			r.Proposed, r.Delete = nil, false
			_ = e.Store.PutRule(r)
		}
		e.mu.Unlock()
		e.audit(ctx, "sensor.admin", outcome, map[string]any{"rule": r.ID, "action_id": r.ActionID})
	}
}

func applies(s RuleSpec, d Device) bool {
	return s.Device == d.ID || (strings.HasPrefix(s.Device, "type:") && d.Type != "" && s.Device == "type:"+d.Type)
}

// evaluate runs the threshold rules over new readings.
func (e *Engine) evaluate(ctx context.Context, d Device, rs []Reading) {
	for _, r := range e.Store.Rules() {
		s := r.Active
		if s == nil || s.Kind != "threshold" || !applies(*s, d) {
			continue
		}
		need := 1
		if s.For != "" {
			need, _ = strconv.Atoi(s.For)
		}
		counts := e.silentFor(*s)
		for _, rd := range rs {
			if rd.Metric != s.Metric || rd.Implausible {
				continue
			}
			over := (s.Op == ">" && rd.Value > s.Value) || (s.Op == ">=" && rd.Value >= s.Value) || (s.Op == "<" && rd.Value < s.Value) || (s.Op == "<=" && rd.Value <= s.Value)
			e.transition(ctx, r.ID, *s, d, over && counts, need, rd.Value)
		}
	}
}

// transition updates a rule's state for a device and reports changes.
func (e *Engine) transition(ctx context.Context, rule string, s RuleSpec, d Device, over bool, need int, v float64) {
	key := rule + "/" + d.ID
	e.mu.Lock()
	a, err := e.Store.Alert(key)
	if err != nil {
		a = Alert{Key: key, Rule: rule, Device: d.ID}
	}
	was := a.Firing
	if over {
		a.Count++
		if a.Count >= need && !a.Firing {
			a.Firing, a.Since = true, e.Now().UTC()
		}
	} else {
		a.Count = 0
		a.Firing = false
	}
	if s.Kind == "silence" && a.Firing == was && err == nil {
		e.mu.Unlock()
		return // nothing changed (checked every second)
	}
	a.Value, a.Updated = v, e.Now().UTC()
	_ = e.Store.PutAlert(a)
	e.mu.Unlock()
	if a.Firing == was {
		return
	}
	outcome, title, sev := "alert_raised", fmt.Sprintf("Sensor alert %s: %s", rule, d.ID), s.Severity
	if !a.Firing {
		outcome, title, sev = "alert_resolved", fmt.Sprintf("Sensor alert %s resolved: %s", rule, d.ID), "info"
	}
	det := map[string]any{"rule": rule, "device": d.ID, "kind": s.Kind, "severity": s.Severity, "trust": Trust}
	if s.Kind == "threshold" {
		det["metric"], det["value"], det["op"], det["threshold"] = s.Metric, v, s.Op, s.Value
	}
	e.audit(ctx, "sensor.alert", outcome, det)
	e.tell(ctx, s.Notify, "sensor."+outcome, title, key, sev)
}

// silentFor: a rule without while_silent always counts; one with it counts
// only while the named device has been silent long enough (v1.1).
func (e *Engine) silentFor(s RuleSpec) bool {
	if s.WhileSilent == nil {
		return true
	}
	d, err := e.Store.Device(s.WhileSilent.Device)
	if err != nil {
		return true // the watched device is gone: as silent as it gets
	}
	dur, _ := time.ParseDuration(s.WhileSilent.For)
	since := d.LastSeen
	if since.IsZero() {
		since = d.Created
	}
	return e.Now().Sub(since) > dur
}

// silences checks the silence rules.
func (e *Engine) silences(ctx context.Context) {
	now := e.Now()
	devs := e.Store.Devices()
	for _, r := range e.Store.Rules() {
		s := r.Active
		if s == nil || s.Kind != "silence" {
			continue
		}
		dur, _ := time.ParseDuration(s.For)
		for _, d := range devs {
			if !applies(*s, d) || d.Revoked {
				continue
			}
			since := d.LastSeen
			if since.IsZero() {
				since = d.Created
			}
			e.transition(ctx, r.ID, *s, d, now.Sub(since) > dur, 1, now.Sub(since).Seconds())
		}
	}
}

// ---- commands ----

// SendCommand queues a command (a controller app or an admin); a risky
// command waits for P5.
func (e *Engine) SendCommand(ctx context.Context, w Who, id, name string, args map[string]any, ttl time.Duration) (Cmd, error) {
	d, err := e.Store.Device(id)
	if err != nil {
		return Cmd{}, fmt.Errorf("device %s: %w", id, ErrNotFound)
	}
	if !e.admin(w) && (w.Person || !in(d.Controllers, w.App)) {
		return Cmd{}, fmt.Errorf("%w: %s may not send commands to %s", ErrForbidden, w.App, id)
	}
	var cmd *Command
	for i := range d.Commands {
		if d.Commands[i].Name == name {
			cmd = &d.Commands[i]
		}
	}
	if cmd == nil {
		return Cmd{}, invalid("device %s does not accept %q", id, name)
	}
	if len(args) > 16 {
		return Cmd{}, invalid("args: at most 16")
	}
	if ttl <= 0 || ttl > 7*24*time.Hour {
		ttl = e.Cfg.CommandTTL
	}
	by := w.App
	if w.Person {
		by = w.User
	}
	now := e.Now().UTC()
	c := Cmd{ID: heain.NewID(), Device: id, Name: name, Args: args, By: by, State: "queued", Created: now, Expires: now.Add(ttl), Updated: now}
	if cmd.Risky {
		res, err := e.Plat.Propose(ctx, heain.Proposal{Type: "sensor.command", Category: heain.CategoryAllowlist,
			Data: map[string]any{"device": id, "command": name, "args": args, "by": by}})
		if err != nil {
			return Cmd{}, fmt.Errorf("P5: %w", err)
		}
		c.ActionID, c.State = res.ActionID, "pending_approval"
		switch {
		case res.Allowed():
			c.State = "queued"
		case res.Result == heain.ResultDenied:
			c.State = "denied"
		}
	}
	e.mu.Lock()
	err = e.Store.PutCmd(c)
	e.mu.Unlock()
	if err != nil {
		return Cmd{}, err
	}
	e.audit(ctx, "sensor.command", "command_"+c.State, map[string]any{"command": c.ID, "device": id, "name": name, "risky": cmd.Risky, "action_id": c.ActionID, "by": by})
	return c, nil
}

func (e *Engine) pollCommands(ctx context.Context) {
	now := e.Now()
	for _, c := range e.Store.Cmds() {
		switch {
		case c.State == "pending_approval":
			res, err := e.Plat.PolicyStatus(ctx, c.ActionID)
			if err != nil || res.Waiting() {
				continue
			}
			c.State = "denied"
			if res.Allowed() {
				c.State = "queued"
			}
		case (c.State == "queued" || c.State == "delivered") && now.After(c.Expires):
			c.State = "expired"
		default:
			continue
		}
		c.Updated = now.UTC()
		e.mu.Lock()
		_ = e.Store.PutCmd(c)
		e.mu.Unlock()
		e.audit(ctx, "sensor.command", "command_"+c.State, map[string]any{"command": c.ID, "device": c.Device, "name": c.Name, "action_id": c.ActionID})
	}
}

// ---- the loop ----

// Run drives rules, silence checks, commands and retention.
func (e *Engine) Run(ctx context.Context) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	sweep := time.Time{}
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		e.Tick(ctx)
		if now := e.Now(); now.Sub(sweep) > time.Hour {
			sweep = now
			if n, err := e.Store.Sweep(now.Add(-e.Cfg.Retention)); err == nil && n > 0 {
				e.Logf("heain-sensor: removed %d readings past retention", n)
			}
		}
	}
}

// Tick does one round.
func (e *Engine) Tick(ctx context.Context) {
	if now := e.Now(); now.Sub(e.last) >= e.Cfg.PollEvery {
		e.last = now
		e.pollRules(ctx)
		e.pollCommands(ctx)
		e.resend(ctx)
	}
	e.silences(ctx)
}
