# Deployment

This is the reconstruction of how the lab was brought up, taken from the project's runbook and install scripts. The anonymized copy in this repository has not been redeployed from scratch, so expect small gaps. Addresses are placeholders: 10.10.10.0/24 is the supervision network (the host is 10.10.10.1) and 10.10.20.0/24 is the protected network behind OPNsense (10.10.20.1).

## Layout

| Path | What |
|---|---|
| `wazuh/` | Compose file for single-node Wazuh 4.14.4, plus `ossec-custom.xml` with the manager additions |
| `thehive-cortex/` | Compose file for TheHive 5.4, Cassandra, Cortex 3.1.7 and the Elasticsearch that only Cortex uses |
| `shuffle/` | `install-shuffle.sh`, which clones upstream Shuffle and sets the memory options |
| `opnsense/` | `harden-lan.sh`, three firewall rules via the OPNsense API |
| `windows-dc/`, `windows-client/` | PowerShell for the domain controller and a client: promotion or join, Sysmon, Wazuh agent, test users, PnP auditing |
| `telegram/` | Helpers to find a chat id and send a test message |
| `host/` | Reconstructed systemd units for the bridge-nf workaround |

## Constraint

The whole lab ran on one 16 GB host (about 15 GB usable) and does not fit at once. Three profiles were used: detection (Wazuh and the VMs under test), response (TheHive, Cortex, Shuffle), and end to end (Wazuh with a reduced heap, TheHive, Shuffle and two VMs).

## Steps

1. Wazuh. Clone the upstream wazuh-docker repository at a 4.14.x tag, take its `single-node` directory, and generate the certificates with its `generate-indexer-certs.yml`. Put this repository's `wazuh/docker-compose.yml` in place of the upstream one, copy `.env.example` to `.env` and fill it (the values must match the upstream `internal_users.yml` and `wazuh.yml`). Merge `wazuh/ossec-custom.xml` into `config/wazuh_cluster/wazuh_manager.conf`. Then `docker compose up -d`.
2. Install the integrations in the manager container (default name `soc-lab-wazuh.manager-1`):
   ```
   docker cp integrations/custom-telegram  soc-lab-wazuh.manager-1:/var/ossec/integrations/
   docker cp integrations/custom-w2thive   soc-lab-wazuh.manager-1:/var/ossec/integrations/
   docker exec soc-lab-wazuh.manager-1 sh -c 'chmod 750 /var/ossec/integrations/custom-* && chown root:wazuh /var/ossec/integrations/custom-*'
   ```
   Put the Telegram settings in `/var/ossec/etc/telegram.env` (`TELEGRAM_BOT_TOKEN=...` and `TELEGRAM_CHAT_ID=...`, mode 640, owner root:wazuh). Install `rules/wazuh/local_rules.xml` as `/var/ossec/etc/rules/local_rules.xml` and restart the manager. Note: the rules reference `yara_decoder`; see `rules/yara/README.md`.
3. TheHive and Cortex. `cd thehive-cortex`, copy `.env.example` to `.env`, fill it, `docker compose up -d`. First boot takes a few minutes. In Cortex create an organization and a user whose API key goes into `CORTEX_API_KEY`, and enable the VirusTotal analyzer with your own key. In TheHive create an organization and a service user for Wazuh; its API key goes into `ossec-custom.xml`.
4. Shuffle, last. `./shuffle/install-shuffle.sh` clones upstream Shuffle into `shuffle/Shuffle/`, sets `vm.max_map_count` and caps the OpenSearch heap at 512 MB. Then `docker compose up -d` in that directory. Shuffle turns on Docker Swarm, which is why it goes last and why step 5 exists.
5. Check the kernel parameter: `sysctl -n net.bridge.bridge-nf-call-iptables` must print `0`. Install the units in `host/` to keep it there. Background: `docs/postmortem-swarm-netfilter.md`.
6. Build or import the workflows, see `soar/README.md`, and point the Shuffle integrations in `ossec-custom.xml` at the webhook ids.
7. VMs: OPNsense (supervision and protected interfaces), a Linux victim with a Wazuh agent, FIM on one directory and the YARA wrapper, a Suricata sensor with a Wazuh agent reading `eve.json`, and the Windows domain controller. On the Windows machines run the scripts in order, with `LAB_PASSWORD` set in the session.
8. Optional: run `opnsense/harden-lan.sh` after exporting `OPNSENSE_KEY` and `OPNSENSE_SECRET`. It allows the fleet to reach the manager on ports 1514 and 1515 (and ICMP), and blocks and logs any other attempt to reach the supervision network.

## Secrets

None of these are in the repository. The names are the ones the files expect.

| Variable | Used by |
|---|---|
| `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID` | `integrations/custom-telegram`, `deploy/telegram/*`, build scripts |
| `THEHIVE_SECRET`, `CORTEX_SECRET`, `CORTEX_API_KEY` | `thehive-cortex/docker-compose.yml` and Cortex config |
| `INDEXER_PASSWORD`, `DASHBOARD_PASSWORD`, `WAZUH_API_PASSWORD` | `wazuh/docker-compose.yml` |
| `OPNSENSE_KEY`, `OPNSENSE_SECRET` | `opnsense/harden-lan.sh`, `soar/build/01_approval_gate.py` |
| `SHUFFLE_DEFAULT_APIKEY`, `SHUFFLE_ORG_ID`, `SHUFFLE_URL` | `soar/build/*` |
| `VIRUSTOTAL_API_KEY`, `THEHIVE_API_KEY`, `WAZUH_API_USER`, `WAZUH_API_PASSWORD` | placeholders in the workflow exports |
| `LAB_PASSWORD` | the Windows scripts |

In the original lab several of these were stored in clear text in Shuffle nodes and manager files. Keep them out of exports; `soar/build/scrub.py` does that for workflows. Rotate anything that has ever been in a file.
