package sensor

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/heainframework/heain-sdk/heain"
	bolt "go.etcd.io/bbolt"
)

// The store: device records, rules, alert states and commands sealed under
// the app's inside key; each device's secret and readings under the
// device's own key in heain-core's KMS, so deleting a device is a
// crypto-shred. Ids are indexed by HMAC.

var (
	bDevices  = []byte("devices")
	bSecrets  = []byte("secrets")
	bReadings = []byte("readings")
	bRules    = []byte("rules")
	bAlerts   = []byte("alerts")
	bCommands = []byte("commands")
)

// ErrNotFound: no such record.
var ErrNotFound = errors.New("not found")

// Keys gives per-device keys (core's KMS).
type Keys struct {
	Sealer  func(ctx context.Context, name string) (*heain.Sealer, error)
	Destroy func(ctx context.Context, name string) error
}

// Store is the sealed state.
type Store struct {
	db     *bolt.DB
	inside *heain.Sealer
	ixKey  []byte
	keys   Keys
}

// Open opens (creating) the store.
func Open(path string, inside []byte, keys Keys) (*Store, error) {
	s, err := heain.NewSealer(inside)
	if err != nil {
		return nil, err
	}
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		return nil, err
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		for _, b := range [][]byte{bDevices, bSecrets, bReadings, bRules, bAlerts, bCommands} {
			if _, err := tx.CreateBucketIfNotExists(b); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		db.Close()
		return nil, err
	}
	m := hmac.New(sha256.New, inside)
	m.Write([]byte("heain-sensor/index"))
	return &Store{db: db, inside: s, ixKey: m.Sum(nil), keys: keys}, nil
}

// Close closes the store.
func (s *Store) Close() error { return s.db.Close() }

func (s *Store) ix(kind, id string) []byte {
	m := hmac.New(sha256.New, s.ixKey)
	m.Write([]byte(kind + "\x00" + id))
	return m.Sum(nil)
}

func (s *Store) hx(kind, id string) string { return hex.EncodeToString(s.ix(kind, id)) }

func (s *Store) put(b []byte, kind, id string, v any) error {
	k := s.hx(kind, id)
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error { return tx.Bucket(b).Put([]byte(k), s.inside.Seal(raw, []byte(kind+"/"+k))) })
}

func (s *Store) get(b []byte, kind, id string, v any) error {
	k := s.hx(kind, id)
	var sealed []byte
	_ = s.db.View(func(tx *bolt.Tx) error {
		if x := tx.Bucket(b).Get([]byte(k)); x != nil {
			sealed = append([]byte(nil), x...)
		}
		return nil
	})
	if sealed == nil {
		return ErrNotFound
	}
	raw, err := s.inside.Open(sealed, []byte(kind+"/"+k))
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, v)
}

func (s *Store) del(b []byte, kind, id string) error {
	k := s.hx(kind, id)
	return s.db.Update(func(tx *bolt.Tx) error { return tx.Bucket(b).Delete([]byte(k)) })
}

func (s *Store) each(b []byte, kind string, f func(raw []byte)) {
	type kv struct{ k, v []byte }
	var all []kv
	_ = s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(b).ForEach(func(k, v []byte) error {
			if v != nil {
				all = append(all, kv{append([]byte(nil), k...), append([]byte(nil), v...)})
			}
			return nil
		})
	})
	for _, x := range all {
		if raw, err := s.inside.Open(x.v, []byte(kind+"/"+string(x.k))); err == nil {
			f(raw)
		}
	}
}

// ---- devices ----

// Metric is a value a device sends, with its plausible range.
type Metric struct {
	Name string   `json:"name"`
	Unit string   `json:"unit,omitempty"`
	Min  *float64 `json:"min,omitempty"`
	Max  *float64 `json:"max,omitempty"`
}

// Command is a command a device accepts.
type Command struct {
	Name  string `json:"name"`
	Risky bool   `json:"risky,omitempty"` // needs P5 before it is queued
}

// Device is a registered device.
type Device struct {
	ID          string    `json:"id"`
	Name        string    `json:"name,omitempty"`
	Type        string    `json:"type,omitempty"`
	Metrics     []Metric  `json:"metrics"`
	Commands    []Command `json:"commands,omitempty"`
	Readers     []string  `json:"readers,omitempty"`     // apps that may read its data
	Controllers []string  `json:"controllers,omitempty"` // apps that may send it commands
	Key         string    `json:"key"`                   // its KMS key (secret and readings)
	KeyVersion  int       `json:"key_version"`
	Revoked     bool      `json:"revoked,omitempty"`
	LastSeq     uint64    `json:"last_seq"`
	LastSeen    time.Time `json:"last_seen,omitempty"`
	Accepted    int64     `json:"accepted"`
	Implausible int64     `json:"implausible"`
	Rejected    int64     `json:"rejected"`
	Created     time.Time `json:"created"`
}

// Metric finds a metric.
func (d Device) Metric(name string) (Metric, bool) {
	for _, m := range d.Metrics {
		if m.Name == name {
			return m, true
		}
	}
	return Metric{}, false
}

// PutDevice stores a device record.
func (s *Store) PutDevice(d Device) error { return s.put(bDevices, "dev", d.ID, d) }

// Device reads one.
func (s *Store) Device(id string) (Device, error) {
	var d Device
	return d, s.get(bDevices, "dev", id, &d)
}

// Devices lists them.
func (s *Store) Devices() []Device {
	out := []Device{}
	s.each(bDevices, "dev", func(raw []byte) {
		var d Device
		if json.Unmarshal(raw, &d) == nil {
			out = append(out, d)
		}
	})
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// KeyName is the KMS key of a device.
func (s *Store) KeyName(id string) string { return "dev-" + s.hx("dev", id)[:24] }

// PutSecret seals a device's secret under its key.
func (s *Store) PutSecret(ctx context.Context, d Device, secret []byte) error {
	ks, err := s.keys.Sealer(ctx, d.Key)
	if err != nil {
		return fmt.Errorf("device key: %w", err)
	}
	k := s.hx("secret", d.ID)
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bSecrets).Put([]byte(k), ks.Seal(secret, []byte("secret/"+k)))
	})
}

// Secret opens a device's secret.
func (s *Store) Secret(ctx context.Context, d Device) ([]byte, error) {
	k := s.hx("secret", d.ID)
	var sealed []byte
	_ = s.db.View(func(tx *bolt.Tx) error {
		if x := tx.Bucket(bSecrets).Get([]byte(k)); x != nil {
			sealed = append([]byte(nil), x...)
		}
		return nil
	})
	if sealed == nil {
		return nil, ErrNotFound
	}
	ks, err := s.keys.Sealer(ctx, d.Key)
	if err != nil {
		return nil, err
	}
	return ks.Open(sealed, []byte("secret/"+k))
}

// DeleteDevice destroys the device's key, then its secret, readings and record.
func (s *Store) DeleteDevice(ctx context.Context, d Device) error {
	if err := s.keys.Destroy(ctx, d.Key); err != nil {
		return fmt.Errorf("destroying the device key: %w", err)
	}
	dk := s.hx("dev", d.ID)
	return s.db.Update(func(tx *bolt.Tx) error {
		_ = tx.Bucket(bSecrets).Delete([]byte(s.hx("secret", d.ID)))
		if tx.Bucket(bReadings).Bucket([]byte(dk)) != nil {
			if err := tx.Bucket(bReadings).DeleteBucket([]byte(dk)); err != nil {
				return err
			}
		}
		return tx.Bucket(bDevices).Delete([]byte(dk))
	})
}

// ---- readings ----

// Reading is one stored value.
type Reading struct {
	Metric      string    `json:"metric"`
	T           time.Time `json:"t"`
	Value       float64   `json:"value"`
	Implausible bool      `json:"implausible,omitempty"`
	Received    time.Time `json:"received"`
	Seq         uint64    `json:"seq"`
}

func (s *Store) rkey(d Device, metric string, t time.Time, n uint32) []byte {
	k := make([]byte, 0, 20)
	k = append(k, s.ix("metric/"+d.ID, metric)[:8]...)
	k = binary.BigEndian.AppendUint64(k, uint64(t.UnixNano()))
	return binary.BigEndian.AppendUint32(k, n)
}

// PutReadings seals readings under the device's key.
func (s *Store) PutReadings(ctx context.Context, d Device, rs []Reading) error {
	ks, err := s.keys.Sealer(ctx, d.Key)
	if err != nil {
		return fmt.Errorf("device key: %w", err)
	}
	dk := s.hx("dev", d.ID)
	return s.db.Update(func(tx *bolt.Tx) error {
		b, err := tx.Bucket(bReadings).CreateBucketIfNotExists([]byte(dk))
		if err != nil {
			return err
		}
		for i, r := range rs {
			k := s.rkey(d, r.Metric, r.T, uint32(r.Seq%1e6)*1000+uint32(i))
			raw, _ := json.Marshal(r)
			if err := b.Put(k, ks.Seal(raw, append([]byte("reading/"+dk+"/"), k...))); err != nil {
				return err
			}
		}
		return nil
	})
}

// Readings opens a metric's readings in [from, to), oldest first, at most limit.
func (s *Store) Readings(ctx context.Context, d Device, metric string, from, to time.Time, limit int) ([]Reading, error) {
	ks, err := s.keys.Sealer(ctx, d.Key)
	if err != nil {
		return nil, err
	}
	dk := s.hx("dev", d.ID)
	lo, hi := s.rkey(d, metric, from, 0), s.rkey(d, metric, to, 0)
	out := []Reading{}
	err = s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bReadings).Bucket([]byte(dk))
		if b == nil {
			return nil
		}
		c := b.Cursor()
		for k, v := c.Seek(lo); k != nil && string(k) < string(hi) && len(out) < limit; k, v = c.Next() {
			raw, err := ks.Open(v, append([]byte("reading/"+dk+"/"), k...))
			if err != nil {
				return err
			}
			var r Reading
			if err := json.Unmarshal(raw, &r); err != nil {
				return err
			}
			out = append(out, r)
		}
		return nil
	})
	return out, err
}

// Sweep removes readings older than before (every device, every metric).
func (s *Store) Sweep(before time.Time) (int, error) {
	n := 0
	err := s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bReadings).ForEach(func(dk, _ []byte) error {
			b := tx.Bucket(bReadings).Bucket(dk)
			if b == nil {
				return nil
			}
			var old [][]byte
			_ = b.ForEach(func(k, _ []byte) error {
				if len(k) == 20 && int64(binary.BigEndian.Uint64(k[8:16])) < before.UnixNano() {
					old = append(old, append([]byte(nil), k...))
				}
				return nil
			})
			for _, k := range old {
				if err := b.Delete(k); err != nil {
					return err
				}
				n++
			}
			return nil
		})
	})
	return n, err
}

// ---- rules, alerts, commands ----

// RuleSpec is an alert rule.
type RuleSpec struct {
	Device   string   `json:"device"`           // a device id, or "type:<type>"
	Metric   string   `json:"metric,omitempty"` // threshold rules
	Kind     string   `json:"kind"`             // threshold | silence
	Op       string   `json:"op,omitempty"`     // > >= < <=
	Value    float64  `json:"value,omitempty"`
	For      string   `json:"for,omitempty"` // threshold: consecutive readings; silence: a duration ("5m")
	Severity string   `json:"severity"`      // info | warning | critical
	Notify   []string `json:"notify,omitempty"`
}

// Rule is a rule with its pending change.
type Rule struct {
	ID       string    `json:"id"`
	Active   *RuleSpec `json:"active,omitempty"`
	Proposed *RuleSpec `json:"proposed,omitempty"`
	Delete   bool      `json:"delete,omitempty"` // the pending change removes it
	ActionID string    `json:"action_id,omitempty"`
	By       string    `json:"by,omitempty"`
	Updated  time.Time `json:"updated"`
}

// PutRule stores a rule.
func (s *Store) PutRule(r Rule) error { return s.put(bRules, "rule", r.ID, r) }

// DelRule removes one.
func (s *Store) DelRule(id string) error { return s.del(bRules, "rule", id) }

// Rule reads one.
func (s *Store) Rule(id string) (Rule, error) {
	var r Rule
	return r, s.get(bRules, "rule", id, &r)
}

// Rules lists them.
func (s *Store) Rules() []Rule {
	out := []Rule{}
	s.each(bRules, "rule", func(raw []byte) {
		var r Rule
		if json.Unmarshal(raw, &r) == nil {
			out = append(out, r)
		}
	})
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Alert is a rule's state for one device.
type Alert struct {
	Key     string    `json:"key"` // rule/device
	Rule    string    `json:"rule"`
	Device  string    `json:"device"`
	Firing  bool      `json:"firing"`
	Count   int       `json:"count"` // consecutive readings over the threshold
	Since   time.Time `json:"since,omitempty"`
	Value   float64   `json:"value,omitempty"`
	Updated time.Time `json:"updated"`
}

// PutAlert stores an alert state.
func (s *Store) PutAlert(a Alert) error { return s.put(bAlerts, "alert", a.Key, a) }

// Alert reads one.
func (s *Store) Alert(key string) (Alert, error) {
	var a Alert
	return a, s.get(bAlerts, "alert", key, &a)
}

// Alerts lists them.
func (s *Store) Alerts() []Alert {
	out := []Alert{}
	s.each(bAlerts, "alert", func(raw []byte) {
		var a Alert
		if json.Unmarshal(raw, &a) == nil {
			out = append(out, a)
		}
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

// Cmd is a command to a device.
type Cmd struct {
	ID       string         `json:"id"`
	Device   string         `json:"device"`
	Name     string         `json:"name"`
	Args     map[string]any `json:"args,omitempty"`
	By       string         `json:"by"`
	State    string         `json:"state"` // pending_approval | queued | delivered | done | failed | expired | denied
	ActionID string         `json:"action_id,omitempty"`
	Result   string         `json:"result,omitempty"`
	Created  time.Time      `json:"created"`
	Expires  time.Time      `json:"expires"`
	Updated  time.Time      `json:"updated"`
}

// PutCmd stores a command.
func (s *Store) PutCmd(c Cmd) error { return s.put(bCommands, "cmd", c.ID, c) }

// Cmd reads one.
func (s *Store) Cmd(id string) (Cmd, error) {
	var c Cmd
	return c, s.get(bCommands, "cmd", id, &c)
}

// Cmds lists them, oldest first.
func (s *Store) Cmds() []Cmd {
	out := []Cmd{}
	s.each(bCommands, "cmd", func(raw []byte) {
		var c Cmd
		if json.Unmarshal(raw, &c) == nil {
			out = append(out, c)
		}
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Created.Before(out[j].Created) })
	return out
}
