#!/usr/bin/env bash
# =====================================================================
# Installation Shuffle (SOAR) - lab SOC
# Shuffle = frontend + backend + orborus (exec workflows) + opensearch
# Doc : https://github.com/Shuffle/Shuffle
# =====================================================================
set -euo pipefail

DEST="${1:-$HOME/detection-lab/deploy/shuffle/Shuffle}"

echo "[*] Clonage de Shuffle dans : $DEST"
if [ ! -d "$DEST/.git" ]; then
  git clone https://github.com/Shuffle/Shuffle "$DEST"
fi
cd "$DEST"

# --- Pre-requis OpenSearch : vm.max_map_count -------------------------
echo "[*] Reglage vm.max_map_count (requis par OpenSearch)"
sudo sysctl -w vm.max_map_count=262144
grep -q 'vm.max_map_count' /etc/sysctl.conf 2>/dev/null || \
  echo 'vm.max_map_count=262144' | sudo tee -a /etc/sysctl.conf >/dev/null

# --- Permissions du volume opensearch ---------------------------------
mkdir -p shuffle-database
sudo chown -R 1000:1000 shuffle-database

# --- Allegement RAM pour lab 16 Go (heap OpenSearch) ------------------
if [ -f .env ]; then
  grep -q 'OPENSEARCH_JAVA_OPTS' .env || \
    echo 'OPENSEARCH_JAVA_OPTS=-Xms512m -Xmx512m' >> .env
fi

echo
echo "[*] Pret. Pour demarrer :"
echo "    cd \"$DEST\" && docker compose up -d"
echo
echo "[*] Interface     : http://<IP_HOST>:3001   (HTTP)  ou  https://<IP_HOST>:3443"
echo "[*] Premier acces : creer le compte admin (le tout premier user = admin)."
