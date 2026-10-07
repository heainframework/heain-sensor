package sensor

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
)

// The device side: HTTPS, outside heain-sdk's mTLS (devices are not nodes
// and hold no certificate of the deployment).
//
//	POST /d/v1/ingest
//	  X-Device-Id: <id>
//	  X-Device-Seq: <a number larger than the last one>
//	  X-Device-Time: <unix seconds, or 0 when the device has no clock>
//	  X-Device-Signature: hex HMAC-SHA256(key, Signed("POST", "/d/v1/ingest", id, seq, time, body))
//	  {"readings": [{"metric": "temp", "value": 21.5, "t": <unix ms, optional>}],
//	   "results": [{"command": "<id>", "status": "done|failed", "detail": "..."}]}
//	-> 200 {"accepted", "implausible", "commands": [{"id", "name", "args"}]}
//	   X-Sensor-Signature: hex HMAC-SHA256(key, ResponseSigned(id, seq, body))
//
// Any failure of authentication answers 401 without saying why.

// IngestPath is the device endpoint.
const IngestPath = "/d/v1/ingest"

// DeviceHandler serves devices.
func (e *Engine) DeviceHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+IngestPath, func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 256<<10))
		if err != nil {
			http.Error(w, `{"error":"too large"}`, http.StatusRequestEntityTooLarge)
			return
		}
		dev := r.Header.Get("X-Device-Id")
		seq, err1 := strconv.ParseUint(r.Header.Get("X-Device-Seq"), 10, 64)
		t, err2 := strconv.ParseInt(r.Header.Get("X-Device-Time"), 10, 64)
		var b Batch
		if !idRe.MatchString(dev) || err1 != nil || err2 != nil || json.Unmarshal(body, &b) != nil {
			http.Error(w, `{"error":"bad request"}`, http.StatusBadRequest)
			return
		}
		ans, key, err := e.Ingest(context.Background(), dev, seq, t, r.Header.Get("X-Device-Signature"), r.Method, r.URL.Path, body, b)
		switch {
		case errors.Is(err, ErrAuth):
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		case errors.Is(err, ErrConflict):
			http.Error(w, `{"error":"rate limit"}`, http.StatusTooManyRequests)
			return
		case errors.Is(err, ErrInvalid):
			http.Error(w, `{"error":"too many readings or results"}`, http.StatusBadRequest)
			return
		case err != nil:
			http.Error(w, `{"error":"unavailable"}`, http.StatusServiceUnavailable)
			return
		}
		out, _ := json.Marshal(ans)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Sensor-Signature", MAC(key, ResponseSigned(dev, seq, out)))
		_, _ = w.Write(out)
	})
	return mux
}
