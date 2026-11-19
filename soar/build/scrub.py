"""
scrub — keep secrets out of exported Shuffle workflows.

Shuffle stores node credentials in clear inside the workflow export. These
helpers do two things:

  scrub_workflow(wf)   replace every credential in an export with a ${NAME}
                       placeholder, and blank identifiers that tie the file to
                       one Shuffle instance (owner, org, bundled icons).
  expand(value)        the reverse, used when building: ${NAME} -> $NAME from
                       the environment (left untouched when NAME is not set).

Placeholders used by the shipped workflows:

  TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID
  THEHIVE_API_KEY, VIRUSTOTAL_API_KEY
  OPNSENSE_KEY, OPNSENSE_SECRET
  WAZUH_API_USER, WAZUH_API_PASSWORD
"""
from __future__ import annotations

import copy
import os
import re

TELEGRAM_TOKEN_RE = re.compile(r"\b\d{8,12}:[A-Za-z0-9_-]{30,}\b")
HEX64_RE = re.compile(r"\b[0-9a-fA-F]{64}\b")
CHAT_ID_RE = re.compile(r'("chat_id"\s*:\s*")\d+(")')
PLACEHOLDER_RE = re.compile(r"\$\{([A-Z][A-Z0-9_]*)\}")

_APIKEY_BY_APP = {"TheHive": "THEHIVE_API_KEY", "Virustotal_v3": "VIRUSTOTAL_API_KEY"}


def expand(value):
    """Replace ${NAME} with os.environ[NAME] when it is set."""
    if not isinstance(value, str):
        return value
    return PLACEHOLDER_RE.sub(lambda m: os.environ.get(m.group(1), m.group(0)), value)


def _credential_names(action: dict) -> tuple[str, str]:
    """Placeholder names for an HTTP node's username/password, chosen by target."""
    url = next((p.get("value", "") for p in action.get("parameters", [])
                if p.get("name") == "url"), "")
    if "/api/firewall" in url:
        return "OPNSENSE_KEY", "OPNSENSE_SECRET"
    if ":55000" in url:
        return "WAZUH_API_USER", "WAZUH_API_PASSWORD"
    return "HTTP_USERNAME", "HTTP_PASSWORD"


def _scrub_action(action: dict) -> None:
    app = action.get("app_name", "")
    user_name, pass_name = _credential_names(action)
    for p in action.get("parameters", []):
        name, value = p.get("name"), p.get("value", "")
        if not isinstance(value, str) or not value:
            continue
        if name == "api_token":
            p["value"] = "${TELEGRAM_BOT_TOKEN}"
        elif name == "apikey":
            p["value"] = "${%s}" % _APIKEY_BY_APP.get(app, app.upper() + "_API_KEY")
        elif name == "username":
            p["value"] = "${%s}" % user_name
        elif name == "password":
            p["value"] = "${%s}" % pass_name
        elif name == "body":
            p["value"] = CHAT_ID_RE.sub(r"\1${TELEGRAM_CHAT_ID}\2", value)
        p["value"] = TELEGRAM_TOKEN_RE.sub("${TELEGRAM_BOT_TOKEN}", p["value"])
        p["value"] = HEX64_RE.sub("${VIRUSTOTAL_API_KEY}", p["value"])
    action["authentication_id"] = ""
    action["large_image"] = ""


def scrub_workflow(wf: dict) -> dict:
    """Return a scrubbed deep copy of a Shuffle workflow export."""
    out = copy.deepcopy(wf)
    for action in out.get("actions", []):
        _scrub_action(action)
    for trigger in out.get("triggers", []):
        trigger["large_image"] = ""
        trigger["small_image"] = ""
    out["validation"] = {}          # last validation run: instance-specific, may quote errors
    for key in ("owner", "org_id", "updated_by", "image", "created_by"):
        if key in out:
            out[key] = "" if out[key] else out[key]
    if isinstance(out.get("execution_org"), dict):
        out["execution_org"] = {"name": "default", "id": ""}
    return out
