// Command device-sim posts like a device would (a reference for device
// firmware, and the device in scripts/live_4_6g.sh): it signs the batch with
// the device key (HMAC-SHA256), sends the next sequence number (kept in a
// file), checks the answer's signature and prints it.
//
//	device-sim -url https://host:8570 -ca sensor.pem -id gh-1 -key <key> -seq-file gh-1.seq \
//	  -readings temp=21.5,hum=50 [-results <command id>:done,<id>:failed]
package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/heainframework/heain-sensor/internal/sensor"
)

func main() {
	url := flag.String("url", "https://127.0.0.1:8570", "heain-sensor's device listener")
	ca := flag.String("ca", "", "the listener's certificate or CA (PEM) to trust")
	id := flag.String("id", "", "device id")
	key := flag.String("key", "", "the device key (as heain-sensor showed it)")
	seqFile := flag.String("seq-file", "", "where the last sequence number is kept")
	seqFlag := flag.Uint64("seq", 0, "send this sequence number instead (testing replays)")
	readings := flag.String("readings", "", "metric=value,... (now)")
	results := flag.String("results", "", "command-id:done|failed,...")
	skew := flag.Duration("time-offset", 0, "shift the request time (testing)")
	flag.Parse()
	k, err := base64.RawURLEncoding.DecodeString(*key)
	if err != nil || *id == "" {
		log.Fatal("device-sim: -id and -key are required")
	}
	var b struct {
		Readings []map[string]any `json:"readings"`
		Results  []map[string]any `json:"results,omitempty"`
	}
	b.Readings = []map[string]any{}
	for _, kv := range strings.Split(*readings, ",") {
		if m, v, ok := strings.Cut(kv, "="); ok {
			f, err := strconv.ParseFloat(v, 64)
			if err != nil {
				log.Fatalf("device-sim: %s", kv)
			}
			b.Readings = append(b.Readings, map[string]any{"metric": m, "value": f})
		}
	}
	for _, kv := range strings.Split(*results, ",") {
		if c, st, ok := strings.Cut(kv, ":"); ok {
			b.Results = append(b.Results, map[string]any{"command": c, "status": st})
		}
	}
	body, _ := json.Marshal(b)
	seq := *seqFlag
	if seq == 0 {
		if raw, err := os.ReadFile(*seqFile); err == nil {
			seq, _ = strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 64)
		}
		seq++
		if *seqFile != "" {
			_ = os.WriteFile(*seqFile, []byte(strconv.FormatUint(seq, 10)), 0o600)
		}
	}
	t := time.Now().Add(*skew).Unix()
	req, _ := http.NewRequest("POST", strings.TrimSuffix(*url, "/")+sensor.IngestPath, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Device-Id", *id)
	req.Header.Set("X-Device-Seq", strconv.FormatUint(seq, 10))
	req.Header.Set("X-Device-Time", strconv.FormatInt(t, 10))
	req.Header.Set("X-Device-Signature", sensor.MAC(k, sensor.Signed("POST", sensor.IngestPath, *id, seq, t, body)))
	tc := &tls.Config{MinVersion: tls.VersionTLS12}
	if *ca != "" {
		pem, err := os.ReadFile(*ca)
		if err != nil {
			log.Fatal(err)
		}
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(pem)
		tc.RootCAs = pool
	}
	resp, err := (&http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{TLSClientConfig: tc}}).Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	signed := resp.StatusCode == 200 && resp.Header.Get("X-Sensor-Signature") == sensor.MAC(k, sensor.ResponseSigned(*id, seq, out))
	fmt.Printf("{\"status\":%d,\"signed\":%v,\"answer\":%s}\n", resp.StatusCode, signed, jsonOr(out))
}

func jsonOr(b []byte) string {
	if json.Valid(b) {
		return string(bytes.TrimSpace(b))
	}
	q, _ := json.Marshal(string(b))
	return string(q)
}
