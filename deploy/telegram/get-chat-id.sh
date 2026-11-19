#!/usr/bin/env bash
# =====================================================================
# Recupere le CHAT_ID de ta conversation avec le bot.
# Prealable : dans Telegram, ouvre ton bot et envoie-lui "/start"
#             (ou ajoute-le a un groupe et ecris un message).
# Usage :
#   export TG_BOT_TOKEN="123456:ABC-DEF..."
#   ./get-chat-id.sh
# =====================================================================
set -euo pipefail
: "${TG_BOT_TOKEN:?Definis TG_BOT_TOKEN (donne par @BotFather)}"

echo "[*] Lecture des derniers messages recus par le bot..."
RESP=$(curl -s "https://api.telegram.org/bot${TG_BOT_TOKEN}/getUpdates")

if command -v jq >/dev/null; then
  echo "$RESP" | jq -r '.result[].message.chat | "chat_id=\(.id)\ttype=\(.type)\tnom=\(.title // (.first_name + " " + (.last_name // "")))"' | sort -u
else
  echo "$RESP"
fi

echo
echo "[*] Copie le chat_id qui correspond a toi/ton groupe :"
echo "    export TG_CHAT_ID=\"<ce_nombre>\"   puis   ./send-test.sh"
