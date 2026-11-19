#!/usr/bin/env python3
"""
Phase 1 — Reusable human-in-the-loop APPROVAL GATE (Block IP instance).

One self-contained workflow, visible in the Shuffle UI. A single webhook routes on
the `decision` field:

  decision=request  -> Telegram message with clickable ✅ APPROVE / ❌ DENY links
  decision=approve  -> block the IP at the OPNsense perimeter, then confirm
  decision=deny     -> notify "denied, no action"

The APPROVE / DENY links point back at this same webhook with decision preset, so a
human click *is* the approval. No User Input node, no manual UI wiring.

Lab note: the human clicks from the SOC host browser, so the links use
http://localhost:3001. In production this becomes the real Shuffle URL (reachable
from the analyst's phone). OPNsense creds are read from the environment at build time
(OPNSENSE_KEY / OPNSENSE_SECRET); in production they move to a vault.

Usage:  python3 01_approval_gate.py            # build/update in Shuffle + save export
        python3 01_approval_gate.py --test      # also fire request+approve+deny
"""
import json
import os
import sys
import time

import shuffle_lib as sl

WF_NAME = "Approval Gate - Block IP"
HUMAN_BASE = "http://localhost:3001"          # analyst-facing (lab: host browser)
OPNSENSE_URL = "https://10.10.20.1"
OPNSENSE_ALIAS = "SOC_blocklist"


def read_opnsense_creds():
    """OPNsense API key pair, from the environment (never hardcoded or committed)."""
    key = os.environ.get("OPNSENSE_KEY", "")
    secret = os.environ.get("OPNSENSE_SECRET", "")
    if not key or not secret:
        raise SystemExit("set OPNSENSE_KEY and OPNSENSE_SECRET before building")
    return key, secret


def find_existing(api, name):
    for w in api.list_workflows():
        if w.get("name") == name:
            return w["id"]
    return None


def build(api, protos, catalog):
    key, secret = read_opnsense_creds()

    trig = sl.webhook_trigger(protos, "alert_in", pos=(80, 300))
    tid = trig["id"]
    approve = f"{HUMAN_BASE}/api/v1/hooks/webhook_{tid}?decision=approve&srcip=$exec.srcip"
    deny = f"{HUMAN_BASE}/api/v1/hooks/webhook_{tid}?decision=deny&srcip=$exec.srcip"

    # Shuffle rule: the START node must run UNCONDITIONALLY. So the trigger hits a
    # router (Shuffle Tools echo) that always runs, then we branch on $exec.decision.
    router = sl.app_node(protos, catalog, "Shuffle Tools", "repeat_back_to_me",
                         label="router", values={"call": "$exec.decision"},
                         pos=(300, 300))
    router["isStartNode"] = True

    request = sl.telegram_node(
        protos, "request_approval",
        text=("SOC APPROVAL NEEDED\n"
              "Suspected attacker IP: $exec.srcip\n"
              "Reason: $exec.reason\n\n"
              f"APPROVE block:\n{approve}\n\n"
              f"DENY (no action):\n{deny}"),
        pos=(560, 120))

    execute = sl.http_node(
        protos, "execute_block", method="POST",
        url=f"{OPNSENSE_URL}/api/firewall/alias_util/add/{OPNSENSE_ALIAS}",
        headers=sl.json_header(), body='{"address": "$exec.srcip"}',
        username=key, password=secret, verify="false", pos=(560, 300))

    confirm = sl.telegram_node(
        protos, "confirm_block",
        text="BLOCKED $exec.srcip at the OPNsense perimeter (human-approved).",
        pos=(820, 300))

    denied = sl.telegram_node(
        protos, "notify_denied",
        text="Block DENIED for $exec.srcip - no action taken (human decision).",
        pos=(560, 480))

    def dec(v):
        return [sl.condition("$exec.decision", "equals", v)]
    branches = [
        sl.branch(tid, router["id"]),                       # unconditional -> start
        sl.branch(router["id"], request["id"], dec("request")),
        sl.branch(router["id"], execute["id"], dec("approve")),
        sl.branch(router["id"], denied["id"], dec("deny")),
        sl.branch(execute["id"], confirm["id"]),
    ]
    actions = [router, request, execute, confirm, denied]

    # reuse existing workflow id if present (update in place), else create fresh
    existing = find_existing(api, WF_NAME)
    if existing:
        wf = api.get_workflow(existing)
        wf["actions"], wf["branches"] = actions, branches
        wf["triggers"], wf["start"] = [trig], router["id"]
        wf["is_valid"] = True
        api.save_workflow(wf)
    else:
        wf = api.build_workflow(WF_NAME,
                                "Reusable human-approval gate for perimeter IP block",
                                actions=actions, triggers=[trig],
                                start=router["id"], branches=branches)

    api.register_webhook(wf["id"], tid, "approval-gate-block-ip", router["id"])
    sl.save_local(wf, "01_approval_gate_block_ip.json")
    return wf, tid


def main(do_test):
    api = sl.Shuffle()
    protos = sl.Prototypes()
    catalog = sl.AppCatalog(api)
    wf, tid = build(api, protos, catalog)
    print(f"[+] '{WF_NAME}' -> {wf['id']}")
    print(f"    open in Shuffle: {HUMAN_BASE}/workflows/{wf['id']}")
    print(f"    webhook id: {tid}")

    if not do_test:
        return 0

    print("\n[*] Test 1: request -> should send Telegram with approve/deny links")
    time.sleep(2)
    r = api.run_webhook(tid, {"decision": "request", "srcip": "203.0.113.55",
                              "reason": "SSH brute-force (rule 5712) - TEST"})
    print("    ->", json.dumps(r)[:120])
    time.sleep(6)

    print("[*] Test 2: deny -> should send 'denied' Telegram")
    api.run_webhook(tid, {"decision": "deny", "srcip": "203.0.113.55"})
    time.sleep(6)

    print("[*] Test 3: approve -> execute_block (OPNsense off => node errors; routing still proven)")
    api.run_webhook(tid, {"decision": "approve", "srcip": "203.0.113.55"})
    time.sleep(6)

    execs = api._req("GET", f"/api/v1/workflows/{wf['id']}/executions")
    execs = execs if isinstance(execs, list) else []
    print(f"\n[*] {len(execs)} executions recorded (newest first):")
    for e in execs[:3]:
        labels = [(x.get("action", {}).get("label"), x.get("status"))
                  for x in e.get("results", [])]
        print(f"    {e.get('status'):9} arg={str(e.get('execution_argument'))[:60]:60} nodes={labels}")
    return 0


if __name__ == "__main__":
    sys.exit(main("--test" in sys.argv))
