# Sysmon

`deploy/windows-dc/02-install-sysmon.ps1` and `deploy/windows-client/02-install-sysmon.ps1` download Sysmon from Sysinternals and the community SwiftOnSecurity `sysmonconfig-export.xml`, then install it. No Sysmon configuration is vendored here because I did not write one.

The Wazuh agent is told to collect the `Microsoft-Windows-Sysmon/Operational` channel (see the agent install scripts), and Wazuh's built-in ruleset decodes it.

None of the 17 local rules depends on Sysmon events. The Windows rules use Security channel events:

| Event | Rule |
|---|---|
| 4624 successful logon | 100600 |
| 6416 new device (needs "Audit PnP Activity", enabled by `05-enable-pnp-audit.ps1`) | 110700 to 110702 |
| 1102 audit log cleared | 110800 |
| 4720 account created | 110810 |
| 4728 / 4732 member added to a group | 110811 |
| 4769 Kerberos service ticket | 110830 |

So Sysmon is part of the telemetry the lab collects, not part of the custom detections.
