#!/bin/bash
# S1 daemon scenarios. Runs INSIDE the disposable client container as root
# (see run.sh); every mutation happens in the container's own network
# namespace. Exits non-zero on the first failed check.
set -euo pipefail

CLIENT=/opt/netorch/e2e/client.py
SOCK=/run/network-orchestrator/daemon.sock
STATE=/var/lib/network-orchestrator/state.json
UNIT=network-orchestrator.service
PASS=0

step() { printf '\n=== %s\n' "$*"; }
ok() { PASS=$((PASS + 1)); printf 'ok   %s\n' "$*"; }
fail() { printf 'FAIL %s\n' "$*"; exit 1; }
expect_eq() { [ "$1" = "$2" ] && ok "$3" || fail "$3: expected '$2', got '$1'"; }
as() { local user=$1; shift; runuser -u "$user" -- "$@"; }
ours() { ip "$@" route show proto 79; }
wait_socket() {
    for _ in $(seq 50); do [ -S "$SOCK" ] && return 0; sleep 0.1; done
    fail "daemon socket did not appear"
}
cond_status() {
    python3 "$CLIENT" condRules.list | python3 -c '
import json, sys
want = sys.argv[1]
rules = [r for r in json.load(sys.stdin)["rules"] if r["rule"]["id"] == want]
if not rules:
    print("missing")
else:
    s = rules[0]["status"]
    print(s["state"], s.get("matchedInterface"))' "$1"
}
cond_wait() { # RULE_ID EXPECTED_STATE [EXPECTED_IFACE] — polls up to ~20s
    local id=$1 want=$2 iface=${3:-} state matched
    for _ in $(seq 100); do
        read -r state matched <<<"$(cond_status "$id")"
        if [ "$state" = "$want" ] && { [ -z "$iface" ] || [ "$matched" = "$iface" ]; }; then
            return 0
        fi
        sleep 0.2
    done
    printf 'cond_wait %s: wanted "%s %s", last "%s"\n' "$id" "$want" "$iface" "$(cond_status "$id")" >&2
    return 1
}

step "service under systemd hardening"
systemctl is-active --quiet "$UNIT" || fail "unit not active: $(systemctl status "$UNIT" --no-pager)"
wait_socket
expect_eq "$(stat -c %a "$SOCK")" 666 "socket mode 0666 despite UMask=0077"
expect_eq "$(stat -c %a /var/lib/network-orchestrator)" 700 "state dir mode 0700"

step "isolated peer container"
peer=$(python3 -c 'from urllib.request import urlopen; print(urlopen("http://wg-server:8765/server-health.txt", timeout=3).read().decode().strip())' 2>/dev/null) || fail "peer container unreachable"
expect_eq "$peer" "netorch-e2e-server" "peer reachable over private Docker network"

step "test interfaces"
ip link add dum0 type dummy
ip addr add 192.0.2.1/24 dev dum0
ip -6 addr add 2001:db8:1::1/64 dev dum0 nodad
ip link set dum0 up
IDX=$(cat /sys/class/net/dum0/ifindex)
ok "dum0 index $IDX"

step "policy rule selects a non-main table for fibmatch lookup"
ip -4 route add 198.18.77.0/24 dev dum0 table 22379 proto 79
ip -4 rule add pref 21000 to 198.18.77.0/24 lookup 22379
lookup=$(ip -j -4 route get fibmatch 198.18.77.7)
python3 -c 'import json,sys; rows=json.loads(sys.argv[1]); assert len(rows)==1; route=rows[0]; assert route["dst"]=="198.18.77.0/24"; assert route["dev"]=="dum0"; assert str(route["table"])=="22379"' "$lookup" \
    && ok "fibmatch follows policy rule into table 22379" || fail "policy lookup: $lookup"
ip -4 rule del pref 21000 to 198.18.77.0/24 lookup 22379
ip -4 route del 198.18.77.0/24 dev dum0 table 22379

step "hello reports peer uid"
expect_eq "$(python3 "$CLIENT" owned.list)" '{"owners": []}' "root owned.list empty"
uid=$(python3 - <<EOF
import json, socket
s = socket.socket(socket.AF_UNIX); s.connect("$SOCK"); f = s.makefile("rwb")
f.write(b'{"id":1,"method":"hello","params":{"protocol":1,"client":"e2e"}}\n'); f.flush()
print(json.loads(f.readline())["result"]["uid"])
EOF
)
expect_eq "$uid" 0 "hello uid for root"

step "tailscale.status: absent daemon reports unavailable, not an RPC error"
ts=$(python3 "$CLIENT" tailscale.status)
python3 -c 'import json,sys; r=json.loads(sys.argv[1]); assert r["available"] is False and r["backendState"]=="Unavailable" and r["peers"]==[], r' "$ts" \
    && ok "tailscale.status available:false" || fail "tailscale.status: $ts"

step "routes.apply: on-link v4, via v4, via v6"
python3 "$CLIENT" routes.apply "{\"owner\":\"static\",\"routes\":[
  {\"destination\":\"203.0.113.0/24\",\"interfaceIndex\":$IDX,\"metric\":5},
  {\"destination\":\"198.51.100.0/24\",\"interfaceIndex\":$IDX,\"gateway\":\"192.0.2.254\",\"metric\":6},
  {\"destination\":\"2001:db8:2::/48\",\"interfaceIndex\":$IDX,\"gateway\":\"2001:db8:1::fe\",\"metric\":7}]}" >/dev/null \
    || fail "routes.apply"
ours -4 | grep -q "^203.0.113.0/24 dev dum0 .*scope link .*metric 5" && ok "on-link v4 installed with proto 79" || fail "on-link v4: $(ours -4)"
ours -4 | grep -q "^198.51.100.0/24 via 192.0.2.254 dev dum0 .*metric 6" && ok "v4 via gateway installed" || fail "via v4: $(ours -4)"
ours -6 | grep -q "^2001:db8:2::/48 via 2001:db8:1::fe dev dum0 .*metric 7" && ok "v6 via gateway installed" || fail "via v6: $(ours -6)"
python3 -c "import json,sys; d=json.load(open('$STATE')); assert d['entries'][0]['state']=='applied'" \
    && ok "journal records owner as applied" || fail "journal: $(cat $STATE)"
expect_eq "$(stat -c %a $STATE)" 600 "journal mode 0600"

step "EXCL: an identical foreign route conflicts and survives"
ip route add 192.0.2.128/25 dev dum0 metric 9 proto static
out=$(python3 "$CLIENT" routes.apply "{\"owner\":\"clash\",\"routes\":[{\"destination\":\"192.0.2.128/25\",\"interfaceIndex\":$IDX,\"metric\":9}]}" || true)
echo "$out" | grep -q '"conflict"' && ok "conflict reported" || fail "expected conflict, got $out"
ip route show 192.0.2.128/25 | grep -q "proto static" && ok "foreign route untouched" || fail "foreign route gone"
expect_eq "$(python3 "$CLIENT" owned.list | python3 -c 'import json,sys; print(len(json.load(sys.stdin)["owners"]))')" 1 "failed apply left no owner"

step "uid isolation and polkit without an agent"
expect_eq "$(as alice python3 "$CLIENT" owned.list)" '{"owners": []}' "alice does not see root owners"
out=$(as alice python3 "$CLIENT" routes.remove '{"owner":"static"}' || true)
echo "$out" | grep -q '"notAuthorized"' && ok "unauthorized alice cannot remove root owner" || fail "expected notAuthorized, got $out"
out=$(as alice python3 "$CLIENT" routes.apply "{\"owner\":\"a\",\"routes\":[{\"destination\":\"10.66.0.0/16\",\"interfaceIndex\":$IDX,\"metric\":5}]}" || true)
echo "$out" | grep -qE '"notAuthorized"|"authorizationDismissed"' && ok "alice denied without polkit agent ($out)" || fail "expected denial, got $out"
ip route show 10.66.0.0/16 | grep -q . && fail "denied route was installed" || ok "denied route not installed"
out=$(as alice python3 "$CLIENT" routes.apply '{"owner":"a","routes":[{"destination":"10.66.0.1/16","interfaceIndex":1,"metric":5}]}' || true)
echo "$out" | grep -q '"invalidParams"' && ok "invalid params rejected before polkit" || fail "expected invalidParams, got $out"

step "polkit rule grants bob system-network"
cat >/etc/polkit-1/rules.d/50-netorch-e2e.rules <<'EOF'
polkit.addRule(function(action, subject) {
    if (action.id.indexOf("com.netmanager.app.") == 0 && subject.user == "bob") {
        return polkit.Result.YES;
    }
});
EOF
sleep 1
as bob python3 "$CLIENT" routes.apply "{\"owner\":\"b\",\"routes\":[{\"destination\":\"10.77.0.0/16\",\"interfaceIndex\":$IDX,\"metric\":5}]}" >/dev/null \
    && ok "bob authorized by rule (pidfd subject accepted)" || fail "bob apply failed"
ours -4 | grep -q "^10.77.0.0/16" && ok "bob route installed" || fail "bob route missing"
out=$(as bob python3 "$CLIENT" routes.remove '{"owner":"static"}' || true)
echo "$out" | grep -q '"notFound"' && ok "authorized bob still cannot remove root owner (notFound)" || fail "expected notFound, got $out"
ours -4 | grep -q "^203.0.113.0/24" && ok "root route intact" || fail "root route removed by bob"
as bob python3 "$CLIENT" routes.remove '{"owner":"b"}' >/dev/null && ok "bob removed own owner" || fail "bob remove"
ours -4 | grep -q "^10.77.0.0/16" && fail "bob route still present" || ok "bob route removed"

step "VPN password mode (daemon settings)"
initial_mode=$(python3 "$CLIENT" settings.get)
out=$(as alice python3 "$CLIENT" settings.set '{"vpnAuthMode":"always"}' || true)
echo "$out" | grep -q '"notAuthorized"' && ok "unauthorized user cannot change mode" || fail "expected notAuthorized, got $out"
expect_eq "$(python3 "$CLIENT" settings.get)" "$initial_mode" "unauthorized change preserves mode"
python3 "$CLIENT" settings.set '{"vpnAuthMode":"always"}' >/dev/null && ok "administrator changed mode" || fail "settings.set as root"
expect_eq "$(stat -c %a /var/lib/network-orchestrator/settings.json)" 600 "settings file mode 0600"
systemctl restart "$UNIT"; wait_socket
expect_eq "$(as alice python3 "$CLIENT" settings.get)" '{"vpnAuthMode": "always"}' "mode persists across restart and is readable by users"
printf '{ corrupt' > /var/lib/network-orchestrator/settings.json
systemctl restart "$UNIT"; wait_socket
expect_eq "$(as alice python3 "$CLIENT" settings.get)" '{"vpnAuthMode": "always"}' "corrupt settings require administrator confirmation"
python3 "$CLIENT" settings.set '{"vpnAuthMode":"noPrompt"}' >/dev/null || fail "restore default mode"

step "link.set_state"
python3 "$CLIENT" link.set_state '{"name":"dum0","up":false}' >/dev/null || fail "link down"
ip -br link show dum0 | grep -q DOWN && ok "dum0 down" || fail "dum0 not down: $(ip -br link show dum0)"
python3 "$CLIENT" link.set_state '{"name":"dum0","up":true}' >/dev/null || fail "link up"
ip -br link show dum0 | grep -qE "UNKNOWN|UP" && ok "dum0 up" || fail "dum0 not up"
# Routes vanish with the link going down; re-add for the recovery checks.
python3 "$CLIENT" routes.remove '{"owner":"static"}' >/dev/null || true
python3 "$CLIENT" routes.apply "{\"owner\":\"static\",\"routes\":[{\"destination\":\"203.0.113.0/24\",\"interfaceIndex\":$IDX,\"metric\":5}]}" >/dev/null \
    || fail "re-apply after link flap"

step "kill -9 → systemd restart → startup recovery"
systemctl kill -s KILL "$UNIT"
sleep 3
systemctl is-active --quiet "$UNIT" && ok "restarted by systemd" || fail "not restarted"
wait_socket
ours -4 | grep -q "^203.0.113.0/24" && fail "leftover route survived recovery" || ok "leftover route removed on startup"
expect_eq "$(python3 -c "import json; print(len(json.load(open('$STATE'))['entries']))")" 0 "journal empty after recovery"

step "SIGTERM teardown"
python3 "$CLIENT" routes.apply "{\"owner\":\"static\",\"routes\":[{\"destination\":\"203.0.113.0/24\",\"interfaceIndex\":$IDX,\"metric\":5}]}" >/dev/null
systemctl stop "$UNIT"
ours -4 | grep -q "^203.0.113.0/24" && fail "route survived stop" || ok "stop removed routes"
[ -e "$SOCK" ] && fail "socket left behind" || ok "socket removed on stop"
systemctl start "$UNIT"; wait_socket

step "batch of 1000 routes"
routes=$(python3 -c "
import json
print(json.dumps({'owner':'bulk','routes':[{'destination':f'100.{64 + i // 256}.{i % 256}.0/24','interfaceIndex':$IDX,'metric':5} for i in range(1000)]}))")
start=$(date +%s%N)
python3 "$CLIENT" routes.apply "$routes" >/dev/null || fail "bulk apply"
elapsed_ms=$(( ($(date +%s%N) - start) / 1000000 ))
expect_eq "$(ours -4 | grep -c '^100\.')" 1000 "1000 routes installed"
[ "$elapsed_ms" -le 2000 ] && ok "bulk apply in ${elapsed_ms} ms (<= 2000)" || fail "bulk apply too slow: ${elapsed_ms} ms"
python3 "$CLIENT" routes.remove '{"owner":"bulk"}' >/dev/null
expect_eq "$(ours -4 | grep -c '^100\.' || true)" 0 "bulk removed"

step "corrupt journal blocks startup without losing ownership data"
systemctl stop "$UNIT"
printf '%s' '{broken journal' >"$STATE"
systemctl start "$UNIT" >/dev/null 2>&1 || true
sleep 2
systemctl is-active --quiet "$UNIT" && fail "daemon started with corrupt journal" || ok "daemon refused corrupt journal"
expect_eq "$(cat "$STATE")" '{broken journal' "corrupt journal preserved"
systemctl stop "$UNIT" >/dev/null 2>&1 || true
printf '%s\n' '{"version":1,"entries":[]}' >"$STATE"
systemctl reset-failed "$UNIT" >/dev/null 2>&1 || true
systemctl start "$UNIT"
wait_socket
ok "daemon starts after journal recovery"

step "conditional rules: interface-address lifecycle"
expect_eq "$(python3 "$CLIENT" condRules.list)" '{"rules": []}' "no conditional rules initially"

ip link add e2econd0 type dummy
ip link set e2econd0 up

# The condition prefix is absent from every interface: rule stores but
# stays inactive and installs nothing.
out=$(python3 "$CLIENT" condRules.put '{"rule":{"id":"office","name":"Office LAN","enabled":true,"condition":{"kind":"interfaceAddressIn","prefix":"203.0.222.0/24"},"routes":[{"destination":"203.0.223.0/24","metric":50},{"destination":"203.0.225.0/24","via":"203.0.222.1","metric":50}]}}')
echo "$out" | python3 -c 'import json,sys; r=json.load(sys.stdin); assert r["stored"] is True and r["status"]["state"]=="inactive", r' \
    && ok "rule stored inactive while prefix absent" || fail "condRules.put: $out"
expect_eq "$(stat -c %a /var/lib/network-orchestrator/cond-rules/0/rules.json)" 600 "cond-rules file mode 0600"
ours -4 | grep -q "203.0.22" && fail "routes installed without a match" || ok "no routes without a match"

# An address inside the prefix on a physical-looking link activates the
# rule: both routes land on the matching interface under proto 79.
ip addr add 203.0.222.7/24 dev e2econd0
cond_wait office active e2econd0 || fail "rule did not activate on address add"
ok "rule active on e2econd0 after address add"
ours -4 | grep -q "^203.0.223.0/24 dev e2econd0 .*scope link .*metric 50" \
    && ok "conditional on-link route installed" || fail "on-link route: $(ours -4)"
ours -4 | grep -q "^203.0.225.0/24 via 203.0.222.1 dev e2econd0 .*metric 50" \
    && ok "conditional via-route installed" || fail "via route: $(ours -4)"
python3 "$CLIENT" owned.list | grep -q '"cond:office"' \
    && ok "cond:office owner journaled" || fail "owned.list: $(python3 "$CLIENT" owned.list)"

# Clients cannot claim the reserved owner namespace.
out=$(python3 "$CLIENT" routes.apply "{\"owner\":\"cond:evil\",\"routes\":[{\"destination\":\"203.0.230.0/24\",\"interfaceIndex\":$IDX,\"metric\":5}]}" || true)
echo "$out" | grep -q '"invalidParams"' && ok "cond: prefix reserved from routes.apply" || fail "reserved owner: $out"
ip route show 203.0.230.0/24 | grep -q . && fail "reserved-owner route installed" || ok "reserved-owner route not installed"

# The trusted address moving to another interface rebinds the routes.
ip link add e2econd1 type dummy
ip addr add 203.0.222.9/24 dev e2econd1
ip link set e2econd1 up
ip addr del 203.0.222.7/24 dev e2econd0
cond_wait office active e2econd1 || fail "rule did not rebind to e2econd1"
ok "rule rebound to e2econd1"
ours -4 | grep -q "^203.0.223.0/24 dev e2econd1" && ok "route on new interface" || fail "rebind: $(ours -4)"
ours -4 | grep -q "dev e2econd0" && fail "stale route left on e2econd0" || ok "old interface withdrawn"

# Losing the address withdraws the routes and frees the owner.
ip addr del 203.0.222.9/24 dev e2econd1
cond_wait office inactive || fail "rule did not deactivate"
ok "rule inactive after address removal"
ours -4 | grep -q "203.0.22" && fail "conditional routes leaked" || ok "routes withdrawn"
python3 "$CLIENT" owned.list | grep -q '"cond:office"' && fail "owner left after deactivation" || ok "cond owner dropped"

# Restart: the rule file persists and the startup evaluation re-applies.
ip addr add 203.0.222.11/24 dev e2econd0
cond_wait office active e2econd0 || fail "rule did not reactivate"
systemctl restart "$UNIT"; wait_socket
restart_ok=0
for _ in $(seq 100); do
    [ "$(cond_status office)" = "active e2econd0" ] \
        && ours -4 | grep -q "^203.0.223.0/24 dev e2econd0" \
        && { restart_ok=1; break; }
    sleep 0.2
done
[ "$restart_ok" = 1 ] && ok "conditional rule survives daemon restart" || fail "post-restart: $(cond_status office) / $(ours -4)"

# Disabling withdraws the routes even though the condition still holds.
out=$(python3 "$CLIENT" condRules.put '{"rule":{"id":"office","name":"Office LAN","enabled":false,"condition":{"kind":"interfaceAddressIn","prefix":"203.0.222.0/24"},"routes":[{"destination":"203.0.223.0/24","metric":50}]}}')
echo "$out" | python3 -c 'import json,sys; r=json.load(sys.stdin); assert r["status"]["state"]=="disabled", r' \
    && ok "disabled rule reports disabled" || fail "disable: $out"
ours -4 | grep -q "203.0.223" && fail "disabled rule kept routes" || ok "disabling withdraws routes"

expect_eq "$(python3 "$CLIENT" condRules.remove '{"ruleId":"office"}')" '{"removed": true}' "condRules.remove"
expect_eq "$(python3 "$CLIENT" condRules.remove '{"ruleId":"office"}')" '{"removed": false}' "remove of absent rule is false"
python3 "$CLIENT" owned.list | grep -q 'cond:' && fail "cond owner left in journal" || ok "removal cleans journal"

# Validation happens before authorization side effects.
out=$(python3 "$CLIENT" condRules.put '{"rule":{"id":"bad id!","name":"x","enabled":true,"condition":{"kind":"interfaceAddressIn","prefix":"203.0.222.0/24"},"routes":[{"destination":"203.0.223.0/24","metric":1}]}}' || true)
echo "$out" | grep -q '"invalidParams"' && ok "invalid rule id rejected" || fail "bad id: $out"
out=$(python3 "$CLIENT" condRules.put '{"rule":{"id":"hostbits","name":"x","enabled":true,"condition":{"kind":"interfaceAddressIn","prefix":"203.0.222.0/24"},"routes":[{"destination":"203.0.223.7/24","metric":1}]}}' || true)
echo "$out" | grep -q '"invalidParams"' && ok "host-bits destination rejected" || fail "host bits: $out"
out=$(as alice python3 "$CLIENT" condRules.put '{"rule":{"id":"a","name":"x","enabled":true,"condition":{"kind":"interfaceAddressIn","prefix":"203.0.222.0/24"},"routes":[{"destination":"203.0.227.0/24","metric":5}]}}' || true)
echo "$out" | grep -qE '"notAuthorized"|"authorizationDismissed"' && ok "unauthorized user cannot put rule" || fail "alice put: $out"
expect_eq "$(as alice python3 "$CLIENT" condRules.list)" '{"rules": []}' "alice sees only her own rules"

ip link del e2econd0
ip link del e2econd1
expect_eq "$(python3 "$CLIENT" owned.list)" '{"owners": []}' "no owners left after conditional scenario"
expect_eq "$(python3 "$CLIENT" condRules.list)" '{"rules": []}' "no rules left after conditional scenario"

step "attach: deferred routes bind to an interface by name"

# The spec arms with no route while e2eext0 does not exist yet.
out=$(python3 "$CLIENT" routes.apply '{"owner":"attach","routes":[],"attach":{"interfaceName":"e2eext0","routes":[{"destination":"198.51.100.0/24","metric":7}],"endpointBypasses":[]}}' 2>&1) \
    || fail "attach apply: $out"
ours -4 | grep -q "198.51.100.0/24" && fail "route installed before the interface exists" || ok "route deferred while e2eext0 absent"
python3 "$CLIENT" owned.list | python3 -c 'import json,sys; sys.exit(0 if any(r.get("kind")=="attachSpec" for o in json.load(sys.stdin)["owners"] for r in o["resources"]) else 1)' \
    && ok "attach spec journaled" || fail "owned.list: $(python3 "$CLIENT" owned.list)"

# When the external client creates the interface, reconcile installs the
# declared routes on its current ifindex.
ip link add e2eext0 type dummy
ip link set e2eext0 up
seen=0
for _ in $(seq 150); do
    ours -4 | grep -q "^198.51.100.0/24 dev e2eext0" && { seen=1; break; }
    sleep 0.2
done
[ "$seen" = 1 ] && ok "attach installs the route once e2eext0 appears" || fail "route not installed: $(ours -4)"

# Deleting the interface withdraws the route; recreating it under a new
# ifindex rebinds — the spec stays armed in between.
ip link del e2eext0
gone=0
for _ in $(seq 100); do
    ours -4 | grep -q "198.51.100.0/24" || { gone=1; break; }
    sleep 0.2
done
[ "$gone" = 1 ] && ok "route withdrawn while e2eext0 absent" || fail "route survived link delete"
python3 "$CLIENT" owned.list | python3 -c 'import json,sys; sys.exit(0 if any(r.get("kind")=="attachSpec" for o in json.load(sys.stdin)["owners"] for r in o["resources"]) else 1)' \
    && ok "spec still armed without the interface" || fail "spec lost"
ip link add e2eext0 type dummy
ip link set e2eext0 up
seen=0
for _ in $(seq 150); do
    ours -4 | grep -q "^198.51.100.0/24 dev e2eext0" && { seen=1; break; }
    sleep 0.2
done
[ "$seen" = 1 ] && ok "route rebinds after interface recreation" || fail "rebind: $(ours -4)"

# An endpoint bypass pins a /32 to the physical default gateway, metric 50.
# routes.apply is not an upsert: update the armed spec via remove + apply,
# the same sequence the app drives when a profile's bypass list changes.
GW_DEV=$(ip -j -4 route show default | python3 -c 'import json,sys; rows=json.load(sys.stdin); print(rows[0]["dev"] if rows else "")')
GW_IP=$(ip -j -4 route show default | python3 -c 'import json,sys; rows=json.load(sys.stdin); print(rows[0].get("gateway","") if rows else "")')
if [ -n "$GW_DEV" ] && [ -n "$GW_IP" ]; then
    out=$(python3 "$CLIENT" routes.remove '{"owner":"attach"}' 2>&1) || fail "routes.remove before bypass reapply: $out"
    out=$(python3 "$CLIENT" routes.apply '{"owner":"attach","routes":[],"attach":{"interfaceName":"e2eext0","routes":[{"destination":"198.51.100.0/24","metric":7}],"endpointBypasses":["192.0.2.87"]}}' 2>&1) \
        || fail "attach apply with bypass: $out"
    seen=0
    for _ in $(seq 100); do
        ours -4 | grep -q "^192.0.2.87 via $GW_IP dev $GW_DEV" && { seen=1; break; }
        sleep 0.2
    done
    [ "$seen" = 1 ] && ok "endpoint bypass pinned to the uplink gateway" || fail "bypass: $(ours -4)"
else
    ok "no default gateway in container — bypass check skipped"
fi

# Removal withdraws every realized route and drops the spec.
out=$(python3 "$CLIENT" routes.remove '{"owner":"attach"}' 2>&1) || fail "routes.remove attach: $out"
gone=0
for _ in $(seq 100); do
    ours -4 | grep -qE "198.51.100.0/24|192.0.2.87" || { gone=1; break; }
    sleep 0.2
done
[ "$gone" = 1 ] && ok "routes.remove withdraws attach routes" || fail "attach routes left: $(ours -4)"
python3 "$CLIENT" owned.list | grep -q 'attach' && fail "attach owner left in journal" || ok "attach owner removed"
ip link del e2eext0

# Spec validation happens before any side effect.
out=$(python3 "$CLIENT" routes.apply '{"owner":"attach","routes":[],"attach":{"interfaceName":"e2ebad","routes":[],"endpointBypasses":["bad host!"]}}' || true)
echo "$out" | grep -q '"invalidParams"' && ok "invalid endpoint bypass rejected" || fail "bad endpoint: $out"

expect_eq "$(python3 "$CLIENT" owned.list)" '{"owners": []}' "no owners left after attach scenario"

printf '\nALL %d CHECKS PASSED\n' "$PASS"
