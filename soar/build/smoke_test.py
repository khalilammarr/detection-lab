#!/usr/bin/env python3
"""
Phase 0 smoke test: prove shuffle_lib can harvest prototypes, assemble a minimal
workflow (webhook -> Telegram notify cloned from the working template), import it,
register the webhook, fire it, confirm execution, then delete it.

Run:  python3 smoke_test.py            # build + run + CLEAN UP
      python3 smoke_test.py --keep     # leave the test workflow in Shuffle
"""
import json
import sys
import time

import shuffle_lib as sl


def main(keep: bool):
    api = sl.Shuffle()
    protos = sl.Prototypes()
    print(f"[*] backend {sl.BASE_URL}  org {sl.ORG_ID}")
    print(f"[*] harvested node prototypes: {sorted(protos._by_label)}")

    # assemble: webhook trigger -> telegram notify (cloned from 'telegram_low')
    trig = sl.webhook_trigger(protos, "wh", pos=(80, 300))
    tg = sl.clone_node(protos, "telegram_low", "smoke_notify",
                       values={}, pos=(400, 300))
    tg["isStartNode"] = True

    wf = api.build_workflow("ZZZ smoke-test (safe to delete)",
                            "Phase 0 foundation smoke test",
                            actions=[tg], triggers=[trig], start=tg["id"],
                            branches=[sl.branch(trig["id"], tg["id"])])
    print(f"[+] imported workflow {wf['id']}")
    api.register_webhook(wf["id"], trig["id"], "smoke-wh", tg["id"])
    print(f"[+] registered webhook {trig['id']}")

    time.sleep(2)
    r = api.run_webhook(trig["id"], {"smoke": "phase0", "data": {"srcip": "203.0.113.9"}})
    exec_id = r.get("execution_id") if isinstance(r, dict) else None
    print(f"[+] fired webhook -> {json.dumps(r)[:160]}")

    ok = False
    for _ in range(10):
        time.sleep(3)
        try:
            res = api.execution_result(wf["id"], exec_id) if exec_id else {}
            status = res.get("status")
            print(f"    exec status: {status}")
            if status in ("FINISHED", "ABORTED"):
                ok = status == "FINISHED"
                break
        except Exception as e:
            print(f"    (poll: {e})")
    print(f"[{'PASS' if ok else '??'}] execution finished={ok}")

    if keep:
        print(f"[=] --keep set; leaving workflow {wf['id']} in Shuffle")
    else:
        api.delete_workflow(wf["id"])
        print(f"[-] cleaned up workflow {wf['id']}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(keep="--keep" in sys.argv))
