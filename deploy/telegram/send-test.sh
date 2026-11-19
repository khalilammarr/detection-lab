#!/usr/bin/env bash
# =====================================================================
# Test d'envoi d'une notification Telegram (bot du lab SOC)
# Usage :
#   export TG_BOT_TOKEN="123456:ABC-DEF..."
#   export TG_CHAT_ID="123456789"
#   ./send-test.sh            # envoie un message d'exemple
#   ./send-test.sh "mon texte"
# =====================================================================
set -euo pipefail

: "${TG_BOT_TOKEN:?Definis TG_BOT_TOKEN (donne par @BotFather)}"
: "${TG_CHAT_ID:?Definis TG_CHAT_ID (voir get-chat-id.sh)}"

MSG="${1:-"🚨 *SOC Lab* — ALERTE CRITIQUE (test)

*Règle* : 5712 — Brute-force SSH
*Niveau* : 10
*Agent* : victim-01 (10.10.20.101)
*Source* : 10.10.10.1
*MITRE* : T1110 — Brute Force
*Heure* : $(date '+%F %T')

_Ceci est un test d'intégration Telegram._"}"

curl -s -X POST "https://api.telegram.org/bot${TG_BOT_TOKEN}/sendMessage" \
  -d chat_id="${TG_CHAT_ID}" \
  -d parse_mode="Markdown" \
  --data-urlencode text="${MSG}" | \
  { command -v jq >/dev/null && jq '.ok, .result.message_id' || cat; }

echo
echo "[*] Si 'ok: true' -> le bot fonctionne. Sinon verifie token / chat_id / que tu as bien fait /start au bot."
