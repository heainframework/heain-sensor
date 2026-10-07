package sensor

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/heainframework/heain-sdk/heain"
)

type fake struct {
	mu       sync.Mutex
	n        int
	actions  map[string]heain.PolicyResult
	messages []map[string]any
	audits   []string
	traces   []string
}

func (f *fake) Propose(_ context.Context, p heain.Proposal) (heain.PolicyResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.n++
	r := heain.PolicyResult{ActionID: fmt.Sprintf("act-%d", f.n), Type: p.Type, Result: heain.ResultWaitingApproval}
	f.actions[r.ActionID] = r
	return r, nil
}

func (f *fake) decide(id, res string) {
	f.mu.Lock()
	r := f.actions[id]
	r.Result = res
	f.actions[id] = r
	f.mu.Unlock()
}

func (f *fake) PolicyStatus(_ context.Context, id string) (heain.PolicyResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.actions[id], nil
}

func (f *fake) Call(_ context.Context, cs heain.CallSpec) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	raw, _ := json.Marshal(cs.Body)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	f.messages = append(f.messages, m)
	return 202, nil
}

func (f *fake) Audit(ctx context.Context, c, o string, d map[string]any) error {
	f.mu.Lock()
	f.audits = append(f.audits, c+":"+o)
	f.traces = append(f.traces, heain.TraceID(ctx)+"|"+fmt.Sprint(d["cause_trace"]))
	f.mu.Unlock()
	return nil
}

func (f *fake) count(s string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, a := range f.audits {
		if a == s {
			n++
		}
	}
	return n
}

type keys struct {
	mu sync.Mutex
	k  map[string]*heain.Sealer
}

func (k *keys) sealer(_ context.Context, name string) (*heain.Sealer, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if s, ok := k.k[name]; ok {
		return s, nil
	}
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	s, _ := heain.NewSealer(b)
	k.k[name] = s
	return s, nil
}

func (k *keys) destroy(_ context.Context, name string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	delete(k.k, name)
	return nil
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func setup(t *testing.T) (*Engine, *fake, *keys, *clock, *httptest.Server, string) {
	t.Helper()
	inside := make([]byte, 32)
	_, _ = rand.Read(inside)
	k := &keys{k: map[string]*heain.Sealer{}}
	path := filepath.Join(t.TempDir(), "sensor.db")
	st, err := Open(path, inside, Keys{Sealer: k.sealer, Destroy: k.destroy})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	f := &fake{actions: map[string]heain.PolicyResult{}}
	c := &clock{t: time.Now().UTC().Truncate(time.Second)}
	e := New(&Engine{Store: st, Plat: f, Now: c.now, Logf: t.Logf, Cfg: Config{AdminCallers: []string{"ops"}, RatePerMin: 30, PollEvery: time.Nanosecond}})
	srv := httptest.NewServer(e.DeviceHandler())
	t.Cleanup(srv.Close)
	return e, f, k, c, srv, path
}

// dev is a test device.
type dev struct {
	id  string
	key []byte
	seq uint64
}

func (d *dev) post(t *testing.T, srv *httptest.Server, now time.Time, body string) (int, Answer) {
	t.Helper()
	d.seq++
	return d.postSeq(t, srv, now, body, d.seq, "")
}

func (d *dev) postSeq(t *testing.T, srv *httptest.Server, now time.Time, body string, seq uint64, sig string) (int, Answer) {
	t.Helper()
	ts := now.Unix()
	if sig == "" {
		sig = MAC(d.key, Signed("POST", IngestPath, d.id, seq, ts, []byte(body)))
	}
	req, _ := http.NewRequest("POST", srv.URL+IngestPath, strings.NewReader(body))
	req.Header.Set("X-Device-Id", d.id)
	req.Header.Set("X-Device-Seq", strconv.FormatUint(seq, 10))
	req.Header.Set("X-Device-Time", strconv.FormatInt(ts, 10))
	req.Header.Set("X-Device-Signature", sig)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(resp.Body)
	var a Answer
	if resp.StatusCode == 200 {
		if resp.Header.Get("X-Sensor-Signature") != MAC(d.key, ResponseSigned(d.id, seq, buf.Bytes())) {
			t.Fatal("the answer is not signed with the device key")
		}
		_ = json.Unmarshal(buf.Bytes(), &a)
	}
	return resp.StatusCode, a
}

func f64(v float64) *float64 { return &v }

func register(t *testing.T, e *Engine, id string) *dev {
	t.Helper()
	_, key, err := e.RegisterDevice(context.Background(), DeviceInput{ID: id, Type: "greenhouse", Metrics: []Metric{{Name: "temp", Unit: "C", Min: f64(-40), Max: f64(85)}, {Name: "hum"}},
		Commands: []Command{{Name: "fan"}, {Name: "valve", Risky: true}}, Readers: []string{"dash"}, Controllers: []string{"ctl"}}, "ops")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := base64.RawURLEncoding.DecodeString(key)
	return &dev{id: id, key: b}
}

func TestDevices(t *testing.T) {
	e, f, k, c, srv, path := setup(t)
	ctx := context.Background()
	d := register(t, e, "gh-1")
	if _, _, err := e.RegisterDevice(ctx, DeviceInput{ID: "gh-1", Metrics: []Metric{{Name: "x"}}}, "ops"); !errors.Is(err, ErrConflict) {
		t.Fatal("a device twice")
	}
	code, a := d.post(t, srv, c.now(), `{"readings":[{"metric":"temp","value":21.5},{"metric":"temp","value":999},{"metric":"hum","value":55},{"metric":"co2","value":400}]}`)
	if code != 200 || a.Accepted != 2 || a.Implausible != 2 {
		t.Fatalf("post: %d %+v", code, a)
	}
	// the signature, replay, an old time
	if code, _ := d.postSeq(t, srv, c.now(), `{"readings":[]}`, 99, strings.Repeat("0", 64)); code != 401 {
		t.Fatalf("a bad signature: %d", code)
	}
	if code, _ := d.postSeq(t, srv, c.now(), `{"readings":[]}`, 1, ""); code != 401 {
		t.Fatalf("a replayed sequence: %d", code)
	}
	if code, _ := d.post(t, srv, c.now().Add(-time.Hour), `{"readings":[]}`); code != 401 {
		t.Fatalf("an old request: %d", code)
	}
	other := &dev{id: "gh-9", key: d.key}
	if code, _ := other.post(t, srv, c.now(), `{"readings":[]}`); code != 401 {
		t.Fatal("an unknown device")
	}
	if f.count("sensor.ingest:rejected") != 2 { // gh-1 once a minute, gh-9 once
		t.Fatalf("rejections audited: %d", f.count("sensor.ingest:rejected"))
	}
	// readings: readers only; untrusted
	if _, err := e.Query(ctx, Who{App: "other"}, "gh-1", "temp", c.now().Add(-time.Hour), c.now().Add(time.Hour), 0); !errors.Is(err, ErrNotFound) {
		t.Fatal("an app the device does not name")
	}
	rs, err := e.Query(ctx, Who{App: "dash"}, "gh-1", "temp", c.now().Add(-time.Hour), c.now().Add(time.Hour), 0)
	if err != nil || len(rs) != 2 || rs[0].Implausible == rs[1].Implausible {
		t.Fatalf("readings: %v %+v", err, rs)
	}
	// rate limit
	for i := 0; i < 30; i++ {
		d.post(t, srv, c.now(), `{"readings":[]}`)
	}
	if code, _ := d.post(t, srv, c.now(), `{"readings":[]}`); code != 429 {
		t.Fatalf("rate limit: %d", code)
	}
	c.add(2 * time.Minute)
	// rotation and revocation
	old := d.key
	_, nk, _ := e.Rotate(ctx, "gh-1", "ops")
	if code, _ := d.post(t, srv, c.now(), `{"readings":[]}`); code != 401 {
		t.Fatal("the old key still works")
	}
	d.key, _ = base64.RawURLEncoding.DecodeString(nk)
	if code, _ := d.post(t, srv, c.now(), `{"readings":[]}`); code != 200 {
		t.Fatal("the new key")
	}
	_, _ = e.Revoke(ctx, "gh-1", "ops")
	if code, _ := d.post(t, srv, c.now(), `{"readings":[]}`); code != 401 {
		t.Fatal("a revoked device")
	}
	_ = old
	// at rest
	raw, _ := os.ReadFile(path)
	if bytes.Contains(raw, []byte("greenhouse")) || bytes.Contains(raw, []byte("21.5")) {
		t.Fatal("plaintext in sensor.db")
	}
	// delete: crypto-shred
	dv, _ := e.Store.Device("gh-1")
	if err := e.Delete(ctx, "gh-1", "ops"); err != nil {
		t.Fatal(err)
	}
	if _, ok := k.k[dv.Key]; ok {
		t.Fatal("the device key survived")
	}
	if _, err := e.Store.Device("gh-1"); !errors.Is(err, ErrNotFound) {
		t.Fatal("the device survived")
	}
	// retention
	d2 := register(t, e, "gh-2")
	d2.post(t, srv, c.now(), `{"readings":[{"metric":"hum","value":50}]}`)
	if n, _ := e.Store.Sweep(c.now().Add(time.Hour)); n != 1 {
		t.Fatalf("sweep: %d", n)
	}
}

func TestRulesAndAlerts(t *testing.T) {
	e, f, _, c, srv, _ := setup(t)
	ctx := context.Background()
	d := register(t, e, "gh-1")
	if _, err := e.ProposeRule(ctx, "hot", &RuleSpec{Device: "type:greenhouse", Kind: "threshold", Metric: "temp", Op: "~", Severity: "critical"}, false, "ops"); !errors.Is(err, ErrInvalid) {
		t.Fatal("a bad op")
	}
	r, err := e.ProposeRule(ctx, "hot", &RuleSpec{Device: "type:greenhouse", Kind: "threshold", Metric: "temp", Op: ">", Value: 40, For: "2", Severity: "critical", Notify: []string{"group:ops-team"}}, false, "ops")
	if err != nil {
		t.Fatal(err)
	}
	d.post(t, srv, c.now(), `{"readings":[{"metric":"temp","value":45},{"metric":"temp","value":46}]}`)
	if f.count("sensor.alert:alert_raised") != 0 {
		t.Fatal("a rule before P5")
	}
	f.decide(r.ActionID, heain.ResultApproved)
	e.Tick(ctx)
	d.post(t, srv, c.now(), `{"readings":[{"metric":"temp","value":45}]}`)
	if f.count("sensor.alert:alert_raised") != 0 {
		t.Fatal("raised after one reading (for: 2)")
	}
	d.post(t, srv, c.now(), `{"readings":[{"metric":"temp","value":47},{"metric":"temp","value":999}]}`)
	if f.count("sensor.alert:alert_raised") != 1 || len(f.messages) != 1 || f.messages[0]["severity"] != "critical" {
		t.Fatalf("raised: %d %v", f.count("sensor.alert:alert_raised"), f.messages)
	}
	d.post(t, srv, c.now(), `{"readings":[{"metric":"temp","value":48}]}`)
	if f.count("sensor.alert:alert_raised") != 1 {
		t.Fatal("raised twice")
	}
	d.post(t, srv, c.now(), `{"readings":[{"metric":"temp","value":22}]}`)
	if f.count("sensor.alert:alert_resolved") != 1 {
		t.Fatal("resolved")
	}
	// a silence rule
	s, _ := e.ProposeRule(ctx, "quiet", &RuleSpec{Device: "gh-1", Kind: "silence", For: "5m", Severity: "warning", Notify: []string{"group:ops-team"}}, false, "ops")
	f.decide(s.ActionID, heain.ResultApproved)
	e.Tick(ctx)
	c.add(6 * time.Minute)
	e.Tick(ctx)
	e.Tick(ctx)
	if f.count("sensor.alert:alert_raised") != 2 {
		t.Fatalf("silence: %d", f.count("sensor.alert:alert_raised"))
	}
	d.post(t, srv, c.now(), `{"readings":[{"metric":"hum","value":50}]}`)
	e.Tick(ctx)
	if f.count("sensor.alert:alert_resolved") != 2 {
		t.Fatal("silence resolved")
	}
	// removing a rule goes through P5 too
	del, _ := e.ProposeRule(ctx, "hot", nil, true, "ops")
	if _, err := e.ProposeRule(ctx, "hot", nil, true, "ops"); !errors.Is(err, ErrConflict) {
		t.Fatal("two pending changes")
	}
	f.decide(del.ActionID, heain.ResultApproved)
	c.add(time.Second)
	e.Tick(ctx)
	if _, err := e.Store.Rule("hot"); !errors.Is(err, ErrNotFound) {
		t.Fatal("rule removed")
	}
}

func TestCommands(t *testing.T) {
	e, f, _, c, srv, _ := setup(t)
	ctx := context.Background()
	d := register(t, e, "gh-1")
	if _, err := e.SendCommand(ctx, Who{App: "dash"}, "gh-1", "fan", nil, 0); !errors.Is(err, ErrForbidden) {
		t.Fatal("a reader sent a command")
	}
	if _, err := e.SendCommand(ctx, Who{App: "ctl"}, "gh-1", "heater", nil, 0); !errors.Is(err, ErrInvalid) {
		t.Fatal("a command the device does not accept")
	}
	fan, _ := e.SendCommand(ctx, Who{App: "ctl"}, "gh-1", "fan", map[string]any{"speed": 2}, 0)
	valve, _ := e.SendCommand(ctx, Who{App: "ctl"}, "gh-1", "valve", map[string]any{"open": true}, 0)
	if fan.State != "queued" || valve.State != "pending_approval" {
		t.Fatalf("states: %s %s", fan.State, valve.State)
	}
	_, a := d.post(t, srv, c.now(), `{"readings":[]}`)
	if len(a.Commands) != 1 || a.Commands[0]["name"] != "fan" {
		t.Fatalf("delivered: %+v", a.Commands)
	}
	f.decide(valve.ActionID, heain.ResultApproved)
	e.Tick(ctx)
	_, a = d.post(t, srv, c.now(), fmt.Sprintf(`{"readings":[],"results":[{"command":%q,"status":"done"}]}`, fan.ID))
	if len(a.Commands) != 1 || a.Commands[0]["name"] != "valve" {
		t.Fatalf("the valve after P5: %+v", a.Commands)
	}
	if x, _ := e.Store.Cmd(fan.ID); x.State != "done" {
		t.Fatalf("fan: %s", x.State)
	}
	d.post(t, srv, c.now(), fmt.Sprintf(`{"readings":[],"results":[{"command":%q,"status":"failed","detail":"stuck"}]}`, valve.ID))
	if x, _ := e.Store.Cmd(valve.ID); x.State != "failed" || x.Result != "stuck" {
		t.Fatalf("valve: %+v", x)
	}
	// denied, expired
	v2, _ := e.SendCommand(ctx, Who{App: "ctl"}, "gh-1", "valve", nil, 0)
	f.decide(v2.ActionID, heain.ResultDenied)
	e.Tick(ctx)
	f3, _ := e.SendCommand(ctx, Who{App: "ctl"}, "gh-1", "fan", nil, time.Minute)
	c.add(2 * time.Minute)
	e.Tick(ctx)
	if x, _ := e.Store.Cmd(v2.ID); x.State != "denied" {
		t.Fatal("denied")
	}
	if x, _ := e.Store.Cmd(f3.ID); x.State != "expired" {
		t.Fatal("expired")
	}
	if f.count("sensor.command:command_done") != 1 || f.count("sensor.command:command_failed") != 1 {
		t.Fatal("results audited")
	}
}

func TestAuditOwnTrace(t *testing.T) {
	e, f, _, _, _, _ := setup(t)
	e.audit(heain.WithTrace(context.Background(), "req-trace", ""), "sensor.admin", "x", map[string]any{})
	tr, cause, _ := strings.Cut(f.traces[len(f.traces)-1], "|")
	if tr == "" || tr == "req-trace" || cause != "req-trace" {
		t.Fatalf("trace %q cause %q", tr, cause)
	}
}
