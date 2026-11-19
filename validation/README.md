# Validation

## What the status labels mean

The lab used three levels of proof. The labels used across this repository map to them:

| Label here | Lab level | Method |
|---|---|---|
| end-to-end | N3 | A real attack was replayed against the lab and checked layer by layer: alert in Wazuh, TheHive entry, playbook run, notification, response action. |
| replay | N1 | A representative event was fed to `wazuh-logtest`. This proves the rule logic fires on the right pattern. It does not prove collection or decoding on a real machine. |
| reviewed | none | Logic read and compared with equivalent rules; never fired. |

The lab also defined N2 (a real event on a real machine, seen in the dashboard). The notes do not record any rule as stopping at N2.

## Why the Windows rules are "reviewed" only

`wazuh-logtest` parses a Windows event with its generic JSON decoder, not with the `windows_eventchannel` decoder the manager uses for events sent by an agent. The built-in Windows rules that the local rules depend on are never reached, so these rules cannot be exercised by replay. Their first real test is a campaign on the domain controller: create an account, add it to an admin group, clear the log, request an RC4 Kerberos ticket for a service account, log in at night, plug in a USB device. That campaign was not run. The Kerberoasting rule is the one that most needs it, since the two fields it matches (ticket encryption type, service name) are not used by any built-in rule.

## Status by rule

| Rule | Status |
|---|---|
| 100200, 100210 (YARA chain) | end-to-end. Run twice: EICAR, then a PHP webshell matched by a real signature. Isolation observed, including reversal. |
| 100500, 100501 (Suricata escalation) | end-to-end. Five real attacks: Shellshock, sqlmap, file inclusion, SQL injection, Nmap scan. |
| 100502 (Suricata, signature name) | replay. The three scan categories escalate to level 10. Added after the real-attack campaign, so not part of it. |
| 100601 (SSH off hours) | replay, with a time window covering the test instant. Needs a real night login to go further. |
| 110703 (USB on Linux) | replay |
| 110820 (login after brute force) | replay. Eight failures then one success; escalates to level 13. |
| 100600, 110700, 110701, 110702, 110800, 110810, 110811, 110830 | reviewed (8 Windows rules) |
| 100001 | stock Wazuh example, not a detection |

Outside the rules, the notes record: three agents Active (domain controller, Linux victim, Suricata sensor); SSH brute force to block checked end to end; OPNsense segmentation checked after the fleet moved behind it. The Windows client is scripted but its agent was not checked in the last campaign.

## Evidence caveat

These statuses are what the project's documentation records. They were not re-run when the repository was prepared, and the raw traces (screenshots, `alerts.json` extracts, execution logs) are not included. Treat them as claims with a method behind them, not as published proof.

## Reported timings

| Measure | Reported | Note |
|---|---|---|
| Event to indexed alert | under 10 s | no timestamp series kept |
| Isolation of a host | under 2 s | direct active response, no orchestrator |
| Detection to block | about 15 s | includes the VirusTotal call and the block call |
| Notifications per attack | 1 to 3 normally, more than 10 under a noisy attack | the stated target of 3 or fewer was missed in the noisy case |
| False-positive rate | not measured | needs a real observation period |

These are single-lab observations, not percentiles.

## The runbook

`runbook-e2e.md` is the manual procedure used for the campaigns: pre-flight checks, SSH brute force, malware, network attacks, Windows events, and a troubleshooting table of pitfalls hit along the way. It is in French, as written, with addresses replaced by placeholders. There was no replay script; replay was done by hand with `wazuh-logtest`, and the original replay inputs were not kept.

To replay a rule yourself, run `/var/ossec/bin/wazuh-logtest` in the manager container and paste a log line that matches the rule's parent, for example a successful SSH login line for 100601 during a time window that includes now.
