# Post-mortem: Shuffle's Docker Swarm mode cut Wazuh off from its indexer

Status: resolved with a mitigation, not a removal of the cause.
When: early July 2026, during the lab build. The exact date was not recorded. Shuffle was installed on 3 July and the automatic fix is noted as in place from 6 July.
Scope: the single lab host that ran Wazuh, TheHive/Cortex and Shuffle side by side.

Everything below comes from the project's own notes: the internship report, the validation runbook and the configuration guide. Where the notes are silent, the text says so under "Gaps".

## Symptom

After Shuffle was brought up, Wazuh stopped working. The manager could no longer reach the indexer. The notes give two concrete signs: Filebeat in the manager logging `dial timeout`, and the Wazuh dashboard returning HTTP 503.

What made it confusing, in the report's words:

- the Wazuh containers were running and healthy,
- none of their configuration had been changed,
- the two stacks were separate compose projects, and Shuffle had no visible connection to Wazuh.

## Investigation

The report records the line of reasoning rather than a command log. Since nothing had changed on the Wazuh side, the search turned to what Shuffle's installation does outside its own containers. Shuffle runs its apps through Docker Swarm, and initializing Swarm mode changes the host's Docker networking: it creates an overlay network and affects the kernel parameter `bridge-nf-call-iptables`, which decides whether traffic crossing a Linux bridge is passed through the iptables chains. That setting belongs to the host, not to a stack, so it applied to every container on the machine, including Wazuh's.

The runbook describes the observed state precisely: Shuffle/Swarm sets `bridge-nf-call-iptables` back to `1`, and with the value at `1` the manager loses access to the indexer. Setting it to `0` restores the connection.

## Root cause

A component installed for an unrelated purpose changed a host-wide kernel network parameter. Container isolation covers processes and file systems; it does not cover sysctl values that sit on the host. Shuffle's runner needs Swarm (the compose file runs Orborus with `SHUFFLE_SWARM_CONFIG=run`), so the change comes with the product.

The notes do not explain why the value `1` makes Wazuh's manager-to-indexer traffic time out. They establish the correlation and the working fix, not the packet-level mechanism.

## Fix

Three layers, all from the notes:

1. Immediate: `sudo sysctl -w net.bridge.bridge-nf-call-iptables=0`.
2. Persistent: a systemd timer, `wazuh-bridge-nf.timer`, that reapplies `0` at boot and then every 20 seconds. The runbook dates this to 6 July 2026 and says no manual step remains. A reconstruction of the two unit files is in `deploy/host/`; the original files were not in the project folder.
3. Procedural: start order is Wazuh, then TheHive/Cortex, and Shuffle last. The check after startup is `sysctl -n net.bridge.bridge-nf-call-iptables`, which must print `0`.

The report also lists "leaving Swarm mode for components that do not need it". One more consequence is in the runbook: Shuffle's Swarm workers survive `docker compose stop`. To fully free memory, remove the services (`docker service rm $(docker service ls -q)`) and leave the swarm (`docker swarm leave --force`).

## Lesson

The report states it as: a container is not a sealed boundary. A component that reconfigures the Docker daemon or the host network acts on the whole machine, and that coupling appears in no architecture diagram. The rule adopted afterwards: after installing anything that touches the container infrastructure, re-check the stacks that have nothing to do with it.

Related incident, same cause family: Swarm also kept the DNS configuration the host had when Swarm was initialized. After the network was re-segmented, Shuffle's ephemeral containers kept using the old, unreachable resolver and Telegram notifications failed on name resolution. Fix there: set an explicit DNS server per service. The method that found it was testing connectivity from inside the failing container, not from the host.

## Gaps

- No command output, `iptables` dumps or logs from the incident itself were kept in the project folder.
- The mechanism linking the sysctl value to the indexer timeout is not documented.
- The fix is a mitigation. With a 20 second timer, a window of up to 20 seconds remains after anything sets the value back to `1`.
- The report mentions leaving Swarm for components that do not need it, but Shuffle itself keeps running in Swarm mode, and the runbook's end state relies on the timer. The notes do not say what was taken out of Swarm, if anything.
- Which Docker or Swarm operation exactly flips the value was not pinned down in the notes.
