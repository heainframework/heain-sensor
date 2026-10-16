# heain-sensor

IoT and sensor ingest for a heain deployment (Step 4.6g, 2026-10-07). Devices (an ESP32, a PLC gateway, a Raspberry Pi) sit outside the trust boundary; heain-sensor is the one place they talk to.

- **Devices** are registered by an admin and get their own key, shown once. Every post is signed with it.
- **Readings** are stored on the node, sealed, and served to the apps the device names, always marked `untrusted_source`.
- **Alert rules** (a threshold, or a device gone silent) go through P5; alerts are formal events in core and go out through [heain-notify](https://github.com/heainframework/heain-notify).
- **Commands** reach a device in the answer to its next post. Risky ones wait for P5.

Built on [heain-sdk](https://github.com/heainframework/heain-sdk) v1. It passes the heain conformance suite. Run it however you like: a plain process, a service unit, or a container (Docker is not required).

## Author decisions (2026-10-07)

1. **A key per device, HMAC on every request.** A device cannot hold a heain mTLS identity, so an admin (an `-admin-callers` app, or a person with the `sensor-admin` role through heain-gateway) registers it and receives a 256-bit key once. Each post carries `X-Device-Id`, `X-Device-Seq` (strictly increasing), `X-Device-Time` (within 10 min) and `X-Device-Signature`; the answer is signed back. Keys rotate; a revoked device is refused at once.
2. **HTTPS first.** Devices post to a separate HTTPS listener (`-device-listen`, default `:8570`) with the operator's certificate. MQTT can come later, behind the same signing.
3. **heain-sensor keeps the readings.** Node-local, sealed under the device's key in core's KMS, kept for 30 days by default (`-retention`, at most 400 days since v1.1), queried by metric and time. Values outside the declared range are kept but marked `implausible`; undeclared metrics are dropped.
4. **Commands through a queue; risky ones through P5.** Controller apps queue a command; the device receives it in its next signed answer and reports `done` or `failed`. A command declared `risky` is a P5 proposal (`sensor.command`) first. Commands expire (1 h by default).

## v1.1 (2026-10-17)

These were added for the national disaster-warning case study. heain-sensor v1.1 needs **heain-notify v1.1**, because of the idempotency key.

- **Alert notices are kept until heain-notify takes them.**
  - Each notice is stored first, then handed to heain-notify.
  - If notify is down or restarting, the notice is retried after 5 s, 15 s, 30 s, 1 min, 2 min, then every 5 min. Every retry carries the same `idempotency_key`, so the notice arrives once.
  - A notice notify never takes is given up after `-notice-max-age` (24 h).
  - Each step is recorded in core: `notice_queued`, `notice_delivered_late` (with the delay), `notice_given_up`.
  - `GET /v1/notices` lists what is still waiting.
- **Cautious stand-in rules.**
  - A threshold rule may say `"while_silent": {"device": "<id>", "for": "10m"}`. It then counts only while that device has been silent for that long.
  - Use it for a lower threshold on a neighbouring gauge while the main one is out, approved through P5 in advance like any rule.
  - When the main device reports again, the stand-in stops counting and its alert resolves.
- **Readings may be kept up to 400 days** (`-retention`; the manifest's ceiling is now `400d`). This allows seasonal comparisons, such as a PM2.5 season against last year's. The default stays 30 days.

## Signing

```
signed  = METHOD "\n" PATH "\n" device-id "\n" seq "\n" time(RFC 3339) "\n" hex(sha256(body))
X-Device-Signature  = hex(HMAC-SHA256(key, signed))
X-Sensor-Signature  = hex(HMAC-SHA256(key, device-id "\n" seq "\n" hex(sha256(answer))))
```

The body is `{"readings": [{"metric", "value", "t"?}], "results": [{"id", "state", "detail"?}]}`; the answer is `{"accepted", "implausible", "commands": [{"id", "name", "args"}]}`. `tools/device-sim` is the reference client (Go, a few dozen lines to port to C).

Wrong key, replayed sequence, old time, unknown or revoked device: 401. Over `-rate-per-min` (120): 429. Refused posts are audited as `sensor.ingest rejected`, at most once a minute per device.

## The API

| Endpoint | Who |
|---|---|
| `POST /v1/devices {id, name, type, metrics: [{name, unit, min?, max?}], commands: [{name, risky}], readers, controllers}` (key in the answer, once) | admins |
| `GET /v1/devices`, `GET /v1/devices/{id}` | admins, the device's readers and controllers |
| `POST /v1/devices/{id}/rotate`, `/revoke`, `DELETE /v1/devices/{id}` (destroys the key) | admins |
| `GET /v1/devices/{id}/readings?metric=&from=&to=&limit=` | admins, readers |
| `PUT /v1/rules/{id} {device \| "type:x", kind: threshold \| silence, metric, op, value, for, severity, notify}`, `DELETE /v1/rules/{id}` (202, through P5 `sensor.rule.change`), `GET /v1/rules` | admins |
| `GET /v1/alerts` | admins |
| `GET /v1/notices` (v1.1: alert notices heain-notify has not taken yet) | admins |
| `POST /v1/devices/{id}/commands {name, args, ttl_s}`, `GET /v1/commands/{id}` | admins, controllers |

A threshold rule's `for` is how many readings in a row must break it; a silence rule's `for` is a duration.

## At rest and in the audit

- **Devices, readings, commands:** sealed under the device's key (`dev-…` in core's KMS) and indexed by HMAC. Deleting a device destroys its key.
- **Audit:** every request is audited by heain-sdk. Device changes, refused posts, alerts (with the value and `trust: untrusted_source`), rule changes and command results are audited under their own traces. No device name, key or command argument goes into the audit.

## Setting it up

```sh
go build -o heain-sensor ./cmd/heain-sensor
./heain-sensor -device-cert dev.pem -device-key dev.key -admin-callers ops   # apps on :19570 (HEAIN_LISTEN), devices on :8570
```

## Tests

```sh
go test ./...
bash scripts/live_4_6g.sh   # needs ~/heain-core, ~/heain-sdk, ~/heain-notify; ~2 min
```

The live test runs a real core node with heain-notify and its test sinks; device-sim plays the device. It covers signed posts and refusals, implausible values, reader access, alert rules through P5 (email and formal events), a silence rule, commands (a risky one through P5), rotation, revocation, crypto-shred on delete, nothing plaintext at rest, and the audit chain.
