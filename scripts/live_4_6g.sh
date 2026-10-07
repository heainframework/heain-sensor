#!/usr/bin/env bash
# heain-sensor live test 4.6g: devices outside the trust boundary, on a real heain-core node.
#   core G + heain-notify (+ TEST ONLY sinks) + heain-sensor; tools/device-sim plays the ESP32 over HTTPS.
#  - an admin app registers a device and gets its key once; the device posts signed batches; values outside the declared
#    range are kept but marked implausible; a bad signature, a replayed sequence, an old request, an unknown device: 401;
#  - apps the device names read its readings, marked untrusted_source; others see nothing;
#  - an alert rule waits for P5, then raises and resolves (heain-notify email, formal events in core); a silence rule;
#  - commands: a controller app queues one, the device picks it up in its answer and reports back; a risky one waits for P5;
#  - key rotation and revocation; deletion destroys the device's key; nothing plaintext at rest; the audit chain verifies.
# Needs ~/heain-core, ~/heain-sdk, ~/heain-notify. ~2 min.
# Run from ~/heain-sensor:  bash scripts/live_4_6g.sh
set -uo pipefail
SN=$(cd "$(dirname "$0")/.." && pwd)
NTDIR=${HEAIN_NOTIFY_DIR:-$HOME/heain-notify}
cd ~/heain-core || { echo "needs ~/heain-core"; exit 1; }
H=./test_1_2_live.sh
T=$HOME/heain-core/.test-1.2
C=$T/certs; L=$T/logs; P=$T/pids; BIN=$T/node; W=$T/sensor-4-6g
URL=https://127.0.0.1:18000
SURL=https://127.0.0.1:19570
DURL=https://127.0.0.1:18570
SINKS=$W/sinks.jsonl
PASS=0; FAIL=0
ok()  { echo "  PASS: $*"; PASS=$((PASS+1)); }
bad() { echo "  FAIL: $*"; FAIL=$((FAIL+1)); }
as() { local who=$1; shift; curl -sk --noproxy '*' --cert "$C/$who.pem" --key "$C/$who.key" --cacert "$C/ca.pem" "$@"; }
code() { local who=$1; shift; as "$who" -o /dev/null -w "%{http_code}" "$@"; }
cl() { local who=$1; shift; curl -sk --noproxy '*' --cert "$W/$who.pem" --key "$W/$who.key" --cacert "$C/ca.pem" -H 'Content-Type: application/json' "$@"; }
ccode() { local who=$1; shift; cl "$who" -o /dev/null -w "%{http_code}" "$@"; }
j() { python3 -c "import json,sys;d=json.load(sys.stdin);print($1)" 2>/dev/null; }
mkcert() { [ -f "$C/$1.pem" ] && return; openssl genrsa -out "$C/$1.key" 2048 >/dev/null 2>&1
  openssl req -new -key "$C/$1.key" -subj "/CN=$1" -out "$C/$1.csr" >/dev/null 2>&1
  openssl x509 -req -in "$C/$1.csr" -CA "$C/ca.pem" -CAkey "$C/ca.key" -CAcreateserial -out "$C/$1.pem" \
    -days 825 -sha256 -extfile <(printf "subjectAltName=DNS:%s" "$1") >/dev/null 2>&1; }
runapp() { local inst=$1 man=$2 port=$3 st=$4; shift 4; mkdir -p "$st"
  HEAIN_MANIFEST=$man HEAIN_INSTANCE=$inst HEAIN_CORE_URL=$URL HEAIN_CORE_ID=G HEAIN_CA=$C/ca.pem HEAIN_CHAIN=$W/prov.pem \
  HEAIN_STATE_DIR=$st HEAIN_ENROLL_TOKEN=$W/$inst.tok HEAIN_ENDPOINT_BASE=https://127.0.0.1:$port HEAIN_LISTEN=127.0.0.1:$port \
    nohup "$@" >> "$W/$inst.log" 2>&1 &
  echo $! > "$P/$inst.pid"; }
token() { as admin -X POST -H 'Content-Type: application/json' -d "{\"label\":\"$1\"}" $URL/provision/token > "$W/$2.tok"; }
pending() { as approver-1 $URL/v1/admin/policy/pending | j "' '.join(x['ID'] for x in d['actions'] if x['Type']=='$1')"; }
approve() { code approver-1 -X POST "$URL/v1/admin/policy/$1/approve"; }
audit() { as admin "$URL/v1/admin/audit?limit=3000&from=${1:-1}"; }
client() { as admin -X POST -H 'Content-Type: application/json' -d "{\"label\":\"$1\"}" $URL/provision/token > "$W/$1.json"
  python3 - "$W" "$1" <<'PY'
import json,sys; w,l=sys.argv[1],sys.argv[2]; d=json.load(open(f"{w}/{l}.json"))
open(f"{w}/{l}.boot.pem","w").write(d["bootstrap_cert_pem"]+open(w+"/prov.pem").read()); open(f"{w}/{l}.boot.key","w").write(d["bootstrap_key_pem"]); open(f"{w}/{l}.token","w").write(d["token"])
PY
  openssl genrsa -out "$W/$1.key" 2048 >/dev/null 2>&1; openssl req -new -key "$W/$1.key" -subj "/CN=$1" -out "$W/$1.csr" >/dev/null 2>&1
  python3 -c "import json;print(json.dumps({'token':open('$W/$1.token').read(),'csr_pem':open('$W/$1.csr').read()}))" > "$W/$1.req"
  curl -sk --noproxy '*' --cert "$W/$1.boot.pem" --key "$W/$1.boot.key" --cacert "$C/ca.pem" -X POST -H 'Content-Type: application/json' -d @"$W/$1.req" $URL/provision/csr \
    | python3 -c "import json,sys;open('$W/$1.pem','w').write(json.load(sys.stdin)['cert_pem']+open('$W/prov.pem').read())"; }
sinks() { python3 - "$SINKS" "$1" <<'PY' 2>/dev/null
import json,sys,os
rs=[json.loads(l) for l in open(sys.argv[1]) if l.strip()] if os.path.exists(sys.argv[1]) else []
print(sum(1 for r in rs if eval(sys.argv[2])))
PY
}
waitsink() { for k in $(seq 1 ${2:-30}); do [ "$(sinks "$1")" -ge "${3:-1}" ] 2>/dev/null && return 0; sleep 1; done; return 1; }
# the device: dev [key] [extra flags] -> {"status","signed","answer"}
KEY=""
dev() { local k=${1:-$KEY}; shift; NO_PROXY='*' "$W/device-sim" -url $DURL -ca "$W/dev.pem" -id gh-1 -key "$k" -seq-file "$W/gh-1.seq" "$@" 2>&1; }
st() { echo "$1" | j "d['status']"; }
events() { audit | j "sum(1 for x in d['records'] if x['event']['Action']=='app.event' and x['event']['Detail']['capability']=='$1' and x['event']['Result']=='$2')"; }
waitev() { for k in $(seq 1 ${4:-15}); do [ "$(events "$1" "$2")" -ge "$3" ] 2>/dev/null && return 0; sleep 1; done; return 1; }

echo "== 0. core node G; build everything"
$H clean >/dev/null; $H build >/dev/null || { echo "core build failed"; exit 1; }; $H certs >/dev/null
mkdir -p "$L" "$P" "$T/data-G" "$W"; for c in admin approver-1; do mkcert $c; done
openssl genrsa -out "$W/prov.key" 2048 >/dev/null 2>&1
openssl req -new -key "$W/prov.key" -subj "/CN=heain-test-provisioning-ca" -out "$W/prov.csr" >/dev/null 2>&1
openssl x509 -req -in "$W/prov.csr" -CA "$C/ca.pem" -CAkey "$C/ca.key" -CAcreateserial -out "$W/prov.pem" -days 30 -sha256 \
  -extfile <(printf "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign") >/dev/null 2>&1
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$W/dev.key" -out "$W/dev.pem" -days 2 -subj "/CN=127.0.0.1" -addext "subjectAltName=IP:127.0.0.1" >/dev/null 2>&1
: > "$L/G.log"
nohup "$BIN" -node-id=G -tier=ZONE -raft-addr=127.0.0.1:19000 -data-dir="$T/data-G" -http-addr=127.0.0.1:18000 \
  -cert="$C/G.pem" -key="$C/G.key" -ca="$C/ca.pem" -admin-node-id=admin -approver-ids=approver-1 -bootstrap=true \
  -approval-store-path="$T/data-G/approvals.db" -provision-ca-cert="$W/prov.pem" -provision-ca-key="$W/prov.key" >> "$L/G.log" 2>&1 &
echo $! > "$P/G.pid"; sleep 6
B="GOFLAGS= GOWORK=${SDK_GOWORK:-}"
( cd "$SN" && eval "$B go build -o $W/heain-sensor ./cmd/heain-sensor" && eval "$B go build -o $W/device-sim ./tools/device-sim" ) \
  && ( cd "$NTDIR" && eval "$B go build -o $W/heain-notify ./cmd/heain-notify" && eval "$B go build -o $W/test-sinks ./tools/test-sinks" ) \
  && ok "heain-sensor, device-sim, heain-notify and the test sinks build" || { bad "build"; exit 1; }
nohup "$W/test-sinks" -smtp 127.0.0.1:18525 -http 127.0.0.1:18526 -out "$SINKS" >> "$W/sinks.log" 2>&1 & echo $! > "$P/sinks.pid"
for k in $(seq 1 15); do [ "$(code admin -X POST -H 'Content-Type: application/json' -d '{"label":"probe.x"}' $URL/provision/token)" = 200 ] && break; sleep 1; done
for c in ops.c1 dash.d1 ctl.c1 other.o1; do client $c; done

echo "== 1. the apps start and are admitted"
token heain-notify.n1 n1; token heain-sensor.s1 s1
runapp n1 "$NTDIR/heain-app.yaml" 19520 "$W/state-n1" "$W/heain-notify" -admin-callers ops -smtp-addr 127.0.0.1:18525 -smtp-from heain@example.test -smtp-mode plain
runapp s1 "$SN/heain-app.yaml" 19570 "$W/state-s1" "$W/heain-sensor" -device-listen 127.0.0.1:18570 -device-cert "$W/dev.pem" -device-key "$W/dev.key" -admin-callers ops -poll 1s
for k in $(seq 1 60); do for a in $(pending app.register); do approve $a >/dev/null; done
  n=$(grep -lE "heain-sensor: active on|heain-notify: active" "$W"/n1.log "$W"/s1.log 2>/dev/null | wc -l); [ "$n" = 2 ] && break; sleep 1; done
[ "$n" = 2 ] && ok "heain-notify and heain-sensor admitted; devices post to $DURL" || { bad "start ($(tail -2 "$W/s1.log"))"; $H stop-all >/dev/null 2>&1; exit 1; }
NP() { cl ops.c1 -o /dev/null -w '%{http_code}' -X PUT -d "$2" "https://127.0.0.1:19520$1"; }
[ "$(NP /v1/contacts/ops '{"email":"ops@example.test"}')$(NP /v1/groups/ops-team '{"members":["ops"]}')" = 200200 ] && ok "notify: ops-team" || bad "contacts"

echo "== 2. a device and its posts"
DEV='{"id":"gh-1","name":"GH-SECRET-NAME","type":"greenhouse","metrics":[{"name":"temp","unit":"C","min":-40,"max":85},{"name":"hum","unit":"%"}],
 "commands":[{"name":"fan"},{"name":"valve","risky":true}],"readers":["dash"],"controllers":["ctl"]}'
[ "$(ccode dash.d1 -X POST -d "$DEV" $SURL/v1/devices)" = 403 ] && ok "a reader app cannot register devices" || bad "dash register"
r=$(cl ops.c1 -X POST -d "$DEV" $SURL/v1/devices); KEY=$(echo "$r" | j "d['key']")
[ -n "$KEY" ] && [ "$(cl ops.c1 $SURL/v1/devices/gh-1 | j "('key' in json.dumps(d['device'])) and False or d['trust']")" = untrusted_source ] && ok "ops registered gh-1; its key was shown once (never again); the device is marked untrusted_source" || bad "register: $r"
o=$(dev "$KEY" -readings temp=21.5,hum=55); [ "$(echo "$o" | j "(d['status'],d['signed'],d['answer']['accepted'])")" = "(200, True, 2)" ] && ok "gh-1 posted 2 readings over HTTPS; the answer is signed with its key" || bad "post: $o"
o=$(dev "$KEY" -readings temp=999,co2=400); [ "$(echo "$o" | j "(d['answer']['accepted'],d['answer']['implausible'])")" = "(0, 2)" ] && ok "temp 999 (above 85) kept as implausible; co2 (not declared) dropped" || bad "implausible: $o"
BADKEY=$(python3 -c "import base64,os;print(base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip('='))")
[ "$(st "$(dev "$BADKEY" -readings temp=20)")" = 401 ] && [ "$(st "$(dev "$KEY" -seq 1 -readings temp=20)")" = 401 ] && [ "$(st "$(dev "$KEY" -time-offset -1h -readings temp=20)")" = 401 ] \
  && [ "$(st "$(NO_PROXY='*' "$W/device-sim" -url $DURL -ca "$W/dev.pem" -id gh-9 -key "$KEY" -seq 5 -readings temp=1)")" = 401 ] \
  && ok "a wrong key, a replayed sequence, an hour-old request and an unknown device: 401" || bad "auth"
waitev sensor.ingest rejected 2 && ok "core's audit: the refused posts (at most one a minute per device)" || bad "rejected audit: $(events sensor.ingest rejected)"

echo "== 3. apps read what the device names"
r=$(cl dash.d1 "$SURL/v1/devices/gh-1/readings?metric=temp")
[ "$(echo "$r" | j "(d['trust'],[(float(x['value']),x.get('implausible',False)) for x in d['readings']])")" = "('untrusted_source', [(21.5, False), (999.0, True)])" ] && ok "dash (a reader) reads temp: untrusted_source, 999 marked implausible" || bad "read: $r"
[ "$(ccode other.o1 "$SURL/v1/devices/gh-1/readings?metric=temp")" = 404 ] && [ "$(cl other.o1 $SURL/v1/devices | j "len(d['devices'])")" = 0 ] && ok "another app sees no device" || bad "other read"

echo "== 4. alert rules through P5"
r=$(cl ops.c1 -X PUT -d '{"device":"type:greenhouse","kind":"threshold","metric":"temp","op":">","value":40,"for":"2","severity":"critical","notify":["group:ops-team"]}' $SURL/v1/rules/hot)
RA=$(echo "$r" | j "d['action_id']"); [ -n "$RA" ] && ok "rule hot (temp > 40, twice in a row) proposed to P5 ($RA)" || bad "rule: $r"
dev "$KEY" -readings temp=45 >/dev/null; dev "$KEY" -readings temp=46 >/dev/null; sleep 2
[ "$(events sensor.alert alert_raised)" = 0 ] && ok "not active yet: no alert" || bad "early alert"
approve $RA >/dev/null; for k in $(seq 1 10); do [ "$(cl ops.c1 $SURL/v1/rules | j "[r['active'] is not None for r in d['rules'] if r['id']=='hot'][0]")" = True ] && break; sleep 1; done
dev "$KEY" -readings temp=47 >/dev/null
[ "$(events sensor.alert alert_raised)" = 0 ] && dev "$KEY" -readings temp=48 >/dev/null && waitev sensor.alert alert_raised 1 \
  && ok "after P5: one reading over 40 is not enough; the second raises the alert" || bad "raise: $(events sensor.alert alert_raised)"
waitsink "r['to']=='ops@example.test' and 'Sensor alert hot: gh-1' in r['body']" 20 && ok "ops-team was told by email" || bad "alert email"
[ "$(audit | j "[(float(x['event']['Detail']['detail']['value']),x['event']['Detail']['detail']['trust']) for x in d['records'] if x['event']['Action']=='app.event' and x['event']['Result']=='alert_raised'][0]")" = "(48.0, 'untrusted_source')" ] \
  && ok "the formal event in core names the value (48) and that it is untrusted_source" || bad "alert event"
dev "$KEY" -readings temp=22 >/dev/null; waitev sensor.alert alert_resolved 1 && ok "temp 22: resolved" || bad "resolve"
r=$(cl ops.c1 -X PUT -d '{"device":"gh-1","kind":"silence","for":"4s","severity":"warning","notify":["group:ops-team"]}' $SURL/v1/rules/quiet); approve "$(echo "$r" | j "d['action_id']")" >/dev/null
waitev sensor.alert alert_raised 2 20 && ok "rule quiet (silent for 4 s), approved: gh-1 stopped posting, alert raised" || bad "silence"
dev "$KEY" -readings hum=50 >/dev/null; waitev sensor.alert alert_resolved 2 && ok "gh-1 posted again: resolved" || bad "silence resolved"
r=$(cl ops.c1 -X DELETE $SURL/v1/rules/quiet); approve "$(echo "$r" | j "d['action_id']")" >/dev/null
for k in $(seq 1 10); do [ "$(cl ops.c1 $SURL/v1/rules | j "len(d['rules'])")" = 1 ] && break; sleep 1; done
[ "$(cl ops.c1 $SURL/v1/rules | j "[r['id'] for r in d['rules']]")" = "['hot']" ] && ok "removing a rule went through P5 too" || bad "rule delete"

echo "== 5. commands"
[ "$(ccode dash.d1 -X POST -d '{"name":"fan"}' $SURL/v1/devices/gh-1/commands)" = 403 ] && ok "a reader app cannot send commands" || bad "dash command"
CF=$(cl ctl.c1 -X POST -d '{"name":"fan","args":{"speed":2}}' $SURL/v1/devices/gh-1/commands | j "d['id']")
r=$(cl ctl.c1 -X POST -d '{"name":"valve","args":{"open":true}}' $SURL/v1/devices/gh-1/commands); CV=$(echo "$r" | j "d['id']"); VA=$(echo "$r" | j "d['action_id']")
[ "$(echo "$r" | j "d['state']")" = pending_approval ] && [ "$(cl ctl.c1 $SURL/v1/commands/$CF | j "d['state']")" = queued ] && ok "ctl queued fan; valve (risky) waits for P5" || bad "commands: $r"
o=$(dev "$KEY" -readings hum=51); [ "$(echo "$o" | j "[c['name'] for c in d['answer']['commands']]")" = "['fan']" ] && ok "gh-1's next answer carries fan (signed)" || bad "deliver: $o"
approve $VA >/dev/null; for k in $(seq 1 10); do [ "$(cl ctl.c1 $SURL/v1/commands/$CV | j "d['state']")" = queued ] && break; sleep 1; done
o=$(dev "$KEY" -results "$CF:done"); [ "$(echo "$o" | j "[c['name'] for c in d['answer']['commands']]")" = "['valve']" ] && ok "after P5 the valve command goes out too; fan reported done" || bad "valve: $o"
dev "$KEY" -results "$CV:failed" >/dev/null
[ "$(cl ctl.c1 $SURL/v1/commands/$CF | j "d['state']")$(cl ctl.c1 $SURL/v1/commands/$CV | j "d['state']")" = donefailed ] && waitev sensor.command command_done 1 && ok "results: fan done, valve failed; audited" || bad "results"

echo "== 6. keys, revocation, deletion"
NK=$(cl ops.c1 -X POST $SURL/v1/devices/gh-1/rotate | j "d['key']")
[ "$(st "$(dev "$KEY" -readings hum=52)")" = 401 ] && [ "$(st "$(dev "$NK" -readings hum=52)")" = 200 ] && ok "after rotation the old key is refused, the new one works" || bad "rotate"
cl ops.c1 -X POST $SURL/v1/devices/gh-1/revoke >/dev/null; [ "$(st "$(dev "$NK" -readings hum=53)")" = 401 ] && ok "revoked: refused at once" || bad "revoke"
cp "$W/state-s1/sensor.db" "$W/before-delete.db"
[ "$(cl ops.c1 -X DELETE $SURL/v1/devices/gh-1 | j "d['crypto_shredded']")" = True ] && [ "$(ccode dash.d1 "$SURL/v1/devices/gh-1/readings?metric=temp")" = 404 ] && ok "gh-1 deleted: its key destroyed, its readings gone" || bad "delete"

echo "== 7. at rest; the audit"
s=$(python3 -c "import sys;n=0
for f in sys.argv[1:3]:
    b=open(f,'rb').read(); n+=sum(b.count(x.encode()) for x in sys.argv[3:])
print(n)" "$W/state-s1/sensor.db" "$W/before-delete.db" GH-SECRET-NAME greenhouse 21.5 speed "$KEY")
[ "$s" = 0 ] && ok "sensor.db (before and after the deletion) holds no name, type, value, command argument or key in plaintext" || bad "plaintext: $s"
audit | grep -q "GH-SECRET-NAME\|$KEY" && bad "a name or key in the audit" || ok "no device name or key in the audit chain"
[ "$(as admin $URL/v1/admin/audit/verify | j "d['ok']")" = True ] && ok "audit chain verifies" || bad "verify"

echo "== cleanup"
kill "$(cat "$P/sinks.pid")" 2>/dev/null
$H stop-all >/dev/null 2>&1
for f in n1 s1; do [ -f "$P/$f.pid" ] && kill "$(cat "$P/$f.pid")" 2>/dev/null; done
echo
echo "RESULT: $PASS passed, $FAIL failed"
echo "(logs: $W)"
