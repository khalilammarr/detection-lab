# SOAR (Shuffle)

Shuffle receives Wazuh alerts through webhooks, enriches them, writes to TheHive, notifies on Telegram and, for one workflow, asks a human before blocking an address at the firewall.

## Workflows

| File | What it does | State |
|---|---|---|
| `workflows/playbook1_enrichment_block.json` | Webhook, VirusTotal lookup of the source IP, branch on the verdict. Malicious (more than 2 VirusTotal engines flag the IP): TheHive alert, Telegram, and a Wazuh active-response call (`!firewall-drop`) on the attacked agent. Otherwise: low-priority TheHive alert and Telegram. Used for SSH brute force and Suricata alerts. | Reported validated end to end (SSH brute force, Suricata attacks) |
| `workflows/02_offhours_login.json` | Off-hours login: TheHive alert and Telegram message. | Built and exercised with a sample payload by its build script |
| `workflows/01_approval_gate_block_ip.json` | The approval-gated block, described below. | Built; routing exercised; see state below |
| `workflows/_template_playbook1.json` | Source of working node definitions that the build scripts clone. | Support file |

One discrepancy to be aware of: the final report speaks of a perimeter block with an OPNsense call in the detection-to-block timing, while this export of playbook 1 blocks through the Wazuh active-response API on the attacked agent and contains no OPNsense node. I could not tell from the files which version the timing was measured on.

Playbook 2 (malware, isolation) is described in the validation runbook but its export is not in the project folder.

All exports are scrubbed. Credentials are `${NAME}` placeholders and instance identifiers are blanked. Importing a file into Shuffle gives you nodes with placeholder values; fill them in, or build the workflows with the scripts below, which read the values from the environment.

## Build scripts

`build/` creates workflows through the Shuffle API instead of by clicking, so they can be versioned.

- `shuffle_lib.py`: API client and node factories. New nodes are cloned from `_template_playbook1.json`, which keeps the exact parameter schema that Shuffle accepts. Known quirks of the Wazuh and Shuffle payloads are encoded once in helpers (the VirusTotal reply is under `.body`, Wazuh active-response command names need a leading `!`, no `parse_mode` on Telegram when text contains underscores).
- `scrub.py`: strips credentials from any export before it is written to disk. Added for this repository; `save_local` now calls it.
- `01_approval_gate.py`, `02_offhours_login.py`, `03_fix_existing_playbooks.py`, `smoke_test.py`.

Environment variables read by the scripts: `SHUFFLE_URL` (default `http://localhost:5001`), `SHUFFLE_DEFAULT_APIKEY` (or in `deploy/shuffle/Shuffle/.env`), `SHUFFLE_ORG_ID`, `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID`, `OPNSENSE_KEY`, `OPNSENSE_SECRET`. The scripts were edited to read credentials from the environment when this repository was prepared; they were not re-run afterwards against a live Shuffle.

## The approval gate

One workflow, one webhook. The webhook carries a `decision` field and a router node branches on it:

- `request`: a Telegram message "SOC APPROVAL NEEDED" with the suspected IP, the reason, and two links.
- `approve`: POST to the OPNsense API, `/api/firewall/alias_util/add/SOC_blocklist` with the address, then a confirmation message.
- `deny`: a message saying no action was taken.

The two links point back at the same webhook with `decision=approve` or `decision=deny`, so the click is the decision. No Shuffle user-input node is involved. A firewall rule on OPNsense drops traffic from addresses in the `SOC_blocklist` alias.

Shuffle requires the start node to run unconditionally, hence the small router node in front of the branches.

State, from the project's own records:

- The build script ran a three-request test (request, deny, approve). Its comment says the routing was proven and that the approve branch errored because OPNsense was powered off at the time. The exported workflow carried a validation record with a failure on `execute_block`, consistent with that. I have no recorded run where the gate completed an actual block.
- The final report says the gate was set aside: it was judged harder to read than the three straight-line playbooks, and the perimeter block in the lab ran automatically after enrichment. An approval step targeted at the block is listed there as the first production change.

So this is a working design and a tested router, not a feature that was in the live path.

## Known limits of the gate

- The approve and deny links are plain webhook URLs. Whoever holds the link decides; there is no identity check, expiry or one-time token.
- The links use `http://localhost:3001`, so they only work from a browser on the SOC host. A real deployment would need a reachable, authenticated URL.
- No approval timeout: an unanswered request just stays unanswered.
- Orborus mounts the host's Docker socket, which is root-equivalent on the host.
