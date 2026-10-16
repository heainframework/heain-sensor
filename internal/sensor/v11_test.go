package sensor

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/heainframework/heain-sdk/heain"
)

func approveRule(t *testing.T, e *Engine, f *fake, id string, s RuleSpec) {
	t.Helper()
	r, err := e.ProposeRule(context.Background(), id, &s, false, "ops")
	if err != nil {
		t.Fatal(err)
	}
	f.decide(r.ActionID, heain.ResultApproved)
	e.Tick(context.Background())
}

// v1.1: a notice heain-notify cannot take is kept and retried with the same
// idempotency key, then delivered; one never taken is given up and audited.
func TestNoticesSurviveNotifyDown(t *testing.T) {
	e, f, _, c, srv, _ := setup(t)
	ctx := context.Background()
	d := register(t, e, "gh-1")
	approveRule(t, e, f, "hot", RuleSpec{Device: "gh-1", Kind: "threshold", Metric: "temp", Op: ">", Value: 40, Severity: "critical", Notify: []string{"group:duty"}})
	f.mu.Lock()
	f.down = 3
	f.mu.Unlock()
	d.post(t, srv, c.now(), `{"readings":[{"metric":"temp","value":45}]}`)
	if f.count("sensor.alert:alert_raised") != 1 || f.count("sensor.alert:notice_queued") != 1 {
		t.Fatalf("raised and queued: %v", f.audits)
	}
	if p := e.Pending(); len(p) != 1 || p[0].Attempts != 1 {
		t.Fatalf("pending: %+v", p)
	}
	// retried as time passes (after 5 s, 15 s, 30 s): down twice more, then taken
	for i := 0; i < 5; i++ {
		c.add(20 * time.Second)
		e.Tick(ctx)
	}
	if p := e.Pending(); len(p) != 0 {
		t.Fatalf("still pending: %+v", p)
	}
	f.mu.Lock()
	msgs := append([]map[string]any(nil), f.messages...)
	f.mu.Unlock()
	if len(msgs) != 1 || msgs[0]["idempotency_key"] == "" || msgs[0]["severity"] != "critical" {
		t.Fatalf("delivered once, with an idempotency key: %v", msgs)
	}
	if f.count("sensor.alert:notice_delivered_late") != 1 {
		t.Fatalf("late delivery audited: %v", f.audits)
	}
	// never taken: given up after the maximum age, audited
	f.mu.Lock()
	f.down = 1000
	f.mu.Unlock()
	d.post(t, srv, c.now(), `{"readings":[{"metric":"temp","value":10}]}`) // resolved: another notice
	for i := 0; i < 300 && len(e.Pending()) > 0; i++ {
		c.add(5 * time.Minute)
		e.Tick(ctx)
	}
	if len(e.Pending()) != 0 || f.count("sensor.alert:notice_given_up") != 1 {
		t.Fatalf("given up: %d pending, %v", len(e.Pending()), f.audits)
	}
}

// v1.1: a cautious stand-in rule counts only while the main gauge is silent.
func TestWhileSilent(t *testing.T) {
	e, f, _, c, srv, _ := setup(t)
	ctx := context.Background()
	if _, err := e.ProposeRule(ctx, "x", &RuleSpec{Device: "gh-2", Kind: "silence", For: "5m", Severity: "warning", WhileSilent: &Silent{Device: "gh-1", For: "10m"}}, false, "ops"); !errors.Is(err, ErrInvalid) {
		t.Fatal("while_silent on a silence rule")
	}
	if _, err := e.ProposeRule(ctx, "x", &RuleSpec{Device: "gh-2", Kind: "threshold", Metric: "temp", Op: ">", Severity: "warning", WhileSilent: &Silent{Device: "gh-1", For: "x"}}, false, "ops"); !errors.Is(err, ErrInvalid) {
		t.Fatal("while_silent without a duration")
	}
	main, side := register(t, e, "gh-1"), register(t, e, "gh-2")
	approveRule(t, e, f, "cautious", RuleSpec{Device: "gh-2", Kind: "threshold", Metric: "temp", Op: ">", Value: 30, Severity: "critical",
		Notify: []string{"group:duty"}, WhileSilent: &Silent{Device: "gh-1", For: "10m"}})
	main.post(t, srv, c.now(), `{"readings":[{"metric":"temp","value":20}]}`)
	side.post(t, srv, c.now(), `{"readings":[{"metric":"temp","value":35}]}`)
	if f.count("sensor.alert:alert_raised") != 0 {
		t.Fatal("the stand-in counted while the main gauge reports")
	}
	c.add(11 * time.Minute)
	side.post(t, srv, c.now(), `{"readings":[{"metric":"temp","value":35}]}`)
	if f.count("sensor.alert:alert_raised") != 1 {
		t.Fatalf("the stand-in did not count with the main gauge silent: %v", f.audits)
	}
	main.post(t, srv, c.now(), `{"readings":[{"metric":"temp","value":21}]}`)
	side.post(t, srv, c.now(), `{"readings":[{"metric":"temp","value":36}]}`)
	if f.count("sensor.alert:alert_resolved") != 1 {
		t.Fatalf("the stand-in alert resolved when the main gauge came back: %v", f.audits)
	}
}
