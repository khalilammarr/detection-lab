#!/usr/bin/env bash
# Harden the OPNsense LAN boundary: the protected fleet (10.10.20.0/24) may only
# reach the SOC host (10.10.10.1) on the Wazuh agent ports; every other pivot into
# the SOC management net (10.10.10.0/24) is blocked and logged.
# Idempotent-ish: creates 3 automation filter rules then applies. Re-running adds dupes,
# so it writes created UUIDs to .rule-uuids (git-ignored) for later rollback.
#
# Credentials come from the environment, never from a file in the repository:
#   export OPNSENSE_KEY=...  OPNSENSE_SECRET=...   (API key pair of a dedicated user)
#   export OPNSENSE_GW=https://10.10.20.1          (optional)
set -euo pipefail
cd "$(dirname "$0")"
: "${OPNSENSE_KEY:?set OPNSENSE_KEY}"
: "${OPNSENSE_SECRET:?set OPNSENSE_SECRET}"
KEY="$OPNSENSE_KEY"
SECRET="$OPNSENSE_SECRET"
GW="${OPNSENSE_GW:-https://10.10.20.1}"
AUTH=(-sk -u "$KEY:$SECRET" --max-time 20)
UUID_FILE=.rule-uuids

add_rule() {
  local desc="$1" payload="$2"
  local resp uuid
  resp=$(curl "${AUTH[@]}" -X POST "$GW/api/firewall/filter/addRule" \
         -H 'Content-Type: application/json' -d "$payload")
  uuid=$(echo "$resp" | python3 -c "import sys,json;print(json.load(sys.stdin).get('uuid',''))" 2>/dev/null || true)
  echo "  $desc -> $resp"
  [ -n "$uuid" ] && echo "$uuid # $desc" >> "$UUID_FILE"
}

echo "=== creating LAN hardening rules ==="
: > "$UUID_FILE"

# 1) PASS: fleet -> Wazuh manager agent ports (1514 comms, 1515 enrollment) — contiguous range
add_rule "pass-wazuh" '{"rule":{"enabled":"1","sequence":"1","action":"pass","quick":"1","interface":"lan","direction":"in","ipprotocol":"inet","protocol":"TCP","source_net":"10.10.20.0/24","destination_net":"10.10.10.1","destination_port":"1514-1515","log":"0","description":"SOC allow Wazuh agent (fleet 57.0/24 -> manager 56.1)"}}'

# 2) PASS: fleet -> manager ICMP (diagnostics only, single host)
add_rule "pass-icmp" '{"rule":{"enabled":"1","sequence":"2","action":"pass","quick":"1","interface":"lan","direction":"in","ipprotocol":"inet","protocol":"ICMP","source_net":"10.10.20.0/24","destination_net":"10.10.10.1","log":"0","description":"SOC allow ICMP (fleet 57.0/24 -> manager 56.1 diag)"}}'

# 3) BLOCK + LOG: any other fleet pivot into the SOC management net
add_rule "block-pivot" '{"rule":{"enabled":"1","sequence":"3","action":"block","quick":"1","interface":"lan","direction":"in","ipprotocol":"inet","protocol":"any","source_net":"10.10.20.0/24","destination_net":"10.10.10.0/24","log":"1","description":"SOC block+log fleet pivot into SOC mgmt net"}}'

echo "=== applying ==="
curl "${AUTH[@]}" -X POST "$GW/api/firewall/filter/apply" -H 'Content-Type: application/json' -d '{}'
echo ""
echo "UUIDs written to $UUID_FILE"
