#!/usr/bin/env python3
"""
Fix the two existing playbooks:

1. Playbook 1 ("SOC Playbook Ultimate") is shared by brute-force AND Suricata scans
   (group authentication_failures,ids). Its titles/messages were HARDCODED to
   "Brute-force SSH", so a scan would wrongly read as brute-force. -> make every
   title/message DYNAMIC using $exec.all_fields.rule.description (Wazuh's real
   description of what fired).

2. Both playbooks' TheHive nodes point at 10.10.10.1:9000, which the Shuffle
   worker (on Swarm overlay nets) can no longer reach -> ConnectTimeout, no cases
   created. Repoint to 172.17.0.1:9000 (docker bridge gateway -> host -> TheHive).

Telegram messages drop parse_mode (Markdown breaks on special chars in dynamic
rule descriptions); kept plain text + emoji.
"""
import json
import os
import sys
import time

import shuffle_lib as sl

THEHIVE_URL = "http://172.17.0.1:9000"

# ---- new DYNAMIC bodies for Playbook 1 -------------------------------------- #
BODIES = {
    "thehive_malicious": json.dumps({
        "type": "external", "source": "Wazuh SIEM",
        "sourceRef": "$exec.all_fields.id",
        "title": "[Menace confirmee] $exec.all_fields.agent.name - $exec.all_fields.rule.description",
        "description": (
            "## Menace reseau confirmee par VirusTotal\\n\\n"
            "**$exec.all_fields.rule.description**\\n\\n"
            "- Actif concerne : $exec.all_fields.agent.name\\n"
            "- IP source : $exec.all_fields.data.src_ip (confirmee malveillante par VirusTotal)\\n"
            "- Regle Wazuh : $exec.all_fields.rule.id (niveau $exec.all_fields.rule.level)\\n\\n"
            "**Reponse :** blocage de l'IP au perimetre recommande."),
        "severity": 3,
    }),
    "thehive_benin": json.dumps({
        "type": "external", "source": "Wazuh SIEM",
        "sourceRef": "$exec.all_fields.id",
        "title": "[Info] $exec.all_fields.rule.description",
        "description": (
            "## Evenement reseau - source non malveillante\\n\\n"
            "$exec.all_fields.rule.description\\n\\n"
            "- Actif : $exec.all_fields.agent.name\\n"
            "- IP source : $exec.all_fields.data.src_ip (non repertoriee malveillante par VirusTotal)\\n"
            "- Regle Wazuh : $exec.all_fields.rule.id (niveau $exec.all_fields.rule.level)"),
        "severity": 2,
    }),
    "telegram_high": json.dumps({
        "chat_id": os.environ.get("TELEGRAM_CHAT_ID", ""),
        "text": ("\U0001F6A8 SOC Lab - INCIDENT\n"
                 "$exec.all_fields.rule.description\n"
                 "Actif : $exec.all_fields.agent.name\n"
                 "IP source : $exec.all_fields.data.src_ip\n"
                 "VirusTotal : $virustotal.body.data.attributes.last_analysis_stats.malicious moteurs -> malveillant\n"
                 "Regle $exec.all_fields.rule.id (niveau $exec.all_fields.rule.level)\n"
                 "-> cas ouvert dans TheHive, blocage recommande."),
    }),
    "telegram_low": json.dumps({
        "chat_id": os.environ.get("TELEGRAM_CHAT_ID", ""),
        "text": ("ℹ️ SOC Lab - evenement\n"
                 "$exec.all_fields.rule.description\n"
                 "IP source : $exec.all_fields.data.src_ip (VirusTotal : non malveillante)\n"
                 "Regle $exec.all_fields.rule.id (niveau $exec.all_fields.rule.level) - trace dans TheHive."),
    }),
}


def set_param(node, name, value):
    for p in node["parameters"]:
        if p["name"] == name:
            p["value"] = value
            return


def fix_playbook1(api):
    wf = [w for w in api.list_workflows()
          if w["name"] == "SOC Playbook Ultimate - SOC Lab"][0]
    full = api.get_workflow(wf["id"])
    changed = []
    for a in full["actions"]:
        if a["label"] in BODIES:
            set_param(a, "body", BODIES[a["label"]])
            changed.append(a["label"])
        if a["app_name"] == "TheHive":
            set_param(a, "url", THEHIVE_URL)
    api.save_workflow(full)
    sl.save_local(full, "_playbook1_fixed.json")
    return full["id"], changed


def fix_playbook2_url(api):
    wf = [w for w in api.list_workflows()
          if w["name"] == "SOC Playbook 2 - Malware Response"][0]
    full = api.get_workflow(wf["id"])
    fixed = False
    for a in full["actions"]:
        if a["app_name"] == "TheHive":
            set_param(a, "url", THEHIVE_URL)
            fixed = True
    api.save_workflow(full)
    return full["id"], fixed


def main(do_test):
    api = sl.Shuffle()
    p1_id, changed = fix_playbook1(api)
    print(f"[+] Playbook 1 {p1_id}: dynamic bodies -> {changed}; TheHive url -> {THEHIVE_URL}")
    p2_id, fixed = fix_playbook2_url(api)
    print(f"[+] Playbook 2 {p2_id}: TheHive url fixed -> {fixed}")

    if do_test:
        # find Playbook 1's webhook and fire a SCAN alert to prove dynamic text
        full = api.get_workflow(p1_id)
        tid = full["triggers"][0]["id"]
        print("\n[*] firing a SCAN alert through Playbook 1 (should NOT say 'brute-force')")
        scan = {"all_fields": {
            "id": "test-scan-001",
            "rule": {"id": "100500", "level": "10",
                     "description": "Suricata: attaque reseau significative - ET SCAN Nmap"},
            "agent": {"name": "suricata-sensor"},
            "data": {"src_ip": "203.0.113.55"}}}
        r = api.run_webhook(tid, scan)
        print("   ->", json.dumps(r)[:110])
        time.sleep(14)
        execs = api._req("GET", f"/api/v1/workflows/{p1_id}/executions")
        execs = execs if isinstance(execs, list) else []
        if execs:
            d = json.dumps({"execution_id": execs[0]["execution_id"], "authorization": ""}).encode()
            import urllib.request
            rq = urllib.request.Request("http://localhost:5001/api/v1/streams/results", data=d,
                                        headers={"Authorization": f"Bearer {sl.API_KEY}",
                                                 "Content-Type": "application/json"})
            res = json.load(urllib.request.urlopen(rq, timeout=10))
            print(f"   exec status: {res.get('status')}")
            for x in res.get("results", []):
                lab = x.get("action", {}).get("label"); st = x.get("status")
                rr = str(x.get("result", ""))
                tag = "TheHive created" if ("createdAt" in rr or '"status": 201' in rr) else (
                    "Telegram OK" if "message_id" in rr else st)
                print(f"     {lab:20} {st:8} {tag}")
    return 0


if __name__ == "__main__":
    sys.exit(main("--test" in sys.argv))
