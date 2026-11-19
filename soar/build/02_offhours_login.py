#!/usr/bin/env python3
"""
SOC Playbook 3 - Connexion hors horaires (off-hours login).

Same simple, readable shape as Playbook 2 (malware):
    Wazuh alert (group off_hours, rule 100600/100601)
      -> webhook
      -> TheHive case  (analyst: verify this night login was legitimate)
      -> Telegram notify

An off-hours login is an IDENTITY event, not a malicious IP — so it does NOT go
through Playbook 1 (VirusTotal + block). It opens a review case instead.

All text is DYNAMIC ($exec.all_fields.rule.description etc.) so it reads correctly
for both the Windows (100600) and SSH (100601) variants.
"""
import json
import os
import sys
import time

import shuffle_lib as sl

WF_NAME = "SOC Playbook 3 - Connexion hors horaires"
# The Shuffle worker runs on Swarm overlay nets and CANNOT reach the vboxnet0 host
# IP 10.10.10.1; it reaches the host via the docker bridge gateway 172.17.0.1.
# TheHive publishes 9000 on 0.0.0.0 so 172.17.0.1:9000 hits it.
THEHIVE_URL = "http://172.17.0.1:9000"

THEHIVE_BODY = json.dumps({
    "type": "external",
    "source": "Wazuh SIEM",
    "sourceRef": "$exec.all_fields.id",
    "title": "[Hors horaires] $exec.all_fields.agent.name - connexion nocturne",
    "description": (
        "## Connexion en dehors des heures de bureau (22h-06h)\\n\\n"
        "$exec.all_fields.rule.description\\n\\n"
        "- Actif concerne : $exec.all_fields.agent.name\\n"
        "- Regle Wazuh : $exec.all_fields.rule.id (niveau $exec.all_fields.rule.level)\\n\\n"
        "**A verifier par l'analyste :** cette connexion nocturne est-elle "
        "legitime (astreinte, admin) ou suspecte (compte compromis) ?"),
    "severity": 2,
})

TELEGRAM_BODY = json.dumps({
    "chat_id": os.environ.get("TELEGRAM_CHAT_ID", ""),
    "text": ("\U0001F319 SOC Lab - Connexion hors horaires\n"
             "$exec.all_fields.rule.description\n"
             "Actif : $exec.all_fields.agent.name\n"
             "Regle $exec.all_fields.rule.id (niveau $exec.all_fields.rule.level)\n"
             "-> cas ouvert dans TheHive, a verifier."),
})


def find_existing(api, name):
    for w in api.list_workflows():
        if w.get("name") == name:
            return w["id"]
    return None


def build(api, protos):
    existing = find_existing(api, WF_NAME)
    existing_wf = api.get_workflow(existing) if existing else None

    trig = sl.webhook_trigger(protos, "offhours_alert_in", pos=(80, 300))
    # keep the webhook id STABLE across rebuilds so the Wazuh integration URL
    # never breaks
    if existing_wf and existing_wf.get("triggers"):
        trig["id"] = existing_wf["triggers"][0]["id"]

    thehive = sl.clone_node(protos, "thehive_benin", "thehive_offhours",
                            values={"body": THEHIVE_BODY, "url": THEHIVE_URL},
                            pos=(360, 300))
    thehive["isStartNode"] = True

    telegram = sl.clone_node(protos, "telegram_low", "telegram_offhours",
                             values={"body": TELEGRAM_BODY}, pos=(640, 300))

    branches = [
        sl.branch(trig["id"], thehive["id"]),      # unconditional -> start
        sl.branch(thehive["id"], telegram["id"]),  # linear
    ]
    actions = [thehive, telegram]

    if existing_wf:
        wf = existing_wf
        wf["actions"], wf["branches"] = actions, branches
        wf["triggers"], wf["start"] = [trig], thehive["id"]
        wf["is_valid"] = True
        api.save_workflow(wf)
    else:
        wf = api.build_workflow(WF_NAME,
                                "Connexion hors horaires -> cas TheHive + Telegram",
                                actions=actions, triggers=[trig],
                                start=thehive["id"], branches=branches)

    api.register_webhook(wf["id"], trig["id"], "offhours-login", thehive["id"])
    sl.save_local(wf, "02_offhours_login.json")
    return wf, trig["id"]


def main(do_test):
    api = sl.Shuffle()
    protos = sl.Prototypes()
    wf, tid = build(api, protos)
    hook = f"http://10.10.10.1:3001/api/v1/hooks/webhook_{tid}"
    print(f"[+] '{WF_NAME}' -> {wf['id']}")
    print(f"    open: http://localhost:3001/workflows/{wf['id']}")
    print(f"    webhook (for ossec.conf integration): {hook}")

    if do_test:
        print("\n[*] firing a sample off-hours alert payload...")
        time.sleep(2)
        sample = {"all_fields": {
            "id": "test-offhours-001",
            "rule": {"id": "100601", "level": "10",
                     "description": "Connexion SSH HORS HORAIRES (nuit) - utilisateur alice"},
            "agent": {"name": "victim-01"}}}
        r = api.run_webhook(tid, sample)
        print("    ->", json.dumps(r)[:120])
        time.sleep(8)
        execs = api._req("GET", f"/api/v1/workflows/{wf['id']}/executions")
        execs = execs if isinstance(execs, list) else []
        if execs:
            e = execs[0]
            print(f"    status={e.get('status')}")
            for x in e.get("results", []):
                print(f"      {x.get('action',{}).get('label'):20} {x.get('status')}")
    return 0


if __name__ == "__main__":
    sys.exit(main("--test" in sys.argv))
