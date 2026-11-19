# YARA

The chain, as documented in the validation runbook:

1. File integrity monitoring (real-time) watches one directory on the Linux victim.
2. A new file there fires rule 100200 (level 7), which has the effect of starting a scan with `yara.sh`.
3. `yara.sh` scans the file with the public signature-base rule set. Matches are written to `active-responses.log` and decoded by a custom decoder named `yara_decoder`.
4. Rule 100210 (level 12, T1204) fires on the decoded match.
5. An active response named `isolate-host` cuts the victim's network while keeping the Wazuh manager reachable, and expires after 1800 seconds. Shuffle playbook 2 records the event in TheHive and sends a Telegram message.

Tested with the EICAR test file and with a PHP webshell that matches the stock signature `WEBSHELL_PHP_Dynamic_Big`.

Not in this repository, and not in the project folder either: `yara.sh`, the `yara_decoder` definition, the `isolate-host` script and its `<active-response>` block, and the signature-base rules (public, from the Neo23x0 project). The report's annex says plainly that the `isolate-host` block was not versioned. Rules 100200 and 100210 in `../wazuh/local_rules.xml` therefore depend on files you have to recreate; the rule logic itself is complete.
