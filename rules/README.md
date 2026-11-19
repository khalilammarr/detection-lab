# Rules

Only one of the four rule folders contains files that were written for this lab.

| Folder | Contents | Why |
|---|---|---|
| `wazuh/` | `local_rules.xml`, the 17 local rules | Written for the lab. This is the detection logic. |
| `suricata/` | notes only | The sensor ran the stock Emerging Threats Open ruleset. No custom Suricata rule was written; the escalation is done in Wazuh (rules 100500 to 100502). |
| `yara/` | notes only | Scanning used a public rule set. The scan wrapper and decoder were not saved in the project folder. |
| `sysmon/` | notes only | Sysmon was installed with a public community configuration downloaded at install time. |

See each folder's README for details.
