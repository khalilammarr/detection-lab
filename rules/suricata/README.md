# Suricata

A VM on the protected network sniffs in promiscuous mode and writes `eve.json`. A Wazuh agent on that VM (agent 007 in the lab) ships `eve.json` to the manager, where Wazuh's built-in Suricata rule (parent id 86601) decodes each alert.

Detection content is the Emerging Threats Open ruleset, unmodified. What I added is the escalation layer in `../wazuh/local_rules.xml`:

- 100501, level 12: Suricata category is one of Administrator Privilege Gain, Network Trojan, Command and Control, Successful.
- 100500, level 10: category is one of Web Application Attack, User Privilege Gain, Information Leak, Network Scan, Potentially Bad Traffic, Executable, Exploit, Denial of Service.
- 100502, level 10: a safety net on the signature name (ET EXPLOIT, ET WEB_SERVER, ET SCAN, Nmap, Shellshock, CVE- ...).

100502 exists because some scans are classified by Suricata as "Misc activity". Those alerts stayed at level 3, below the level-10 threshold that triggers notifications and playbooks, so a detected scan produced nothing downstream. The fix is the rule. It is also a case where the alert was visible in the dashboard and still did nothing, which is why validation in this lab was checked down to the notification and not only to the SIEM.

Not in this repository: `suricata.yaml`, the sensor's interface setup and the ruleset download, because none of them were saved in the project folder.
