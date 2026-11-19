"""
shuffle_lib — SOC lab Shuffle workflow builder foundation.

Production goal: author SOAR playbooks as VERSIONED code (PLAN_SOC Phase 3), not
fragile UI clicks. This library talks to the local Shuffle backend API and builds
workflows by CLONING real, working node prototypes harvested from an existing
workflow export — this reuses the exact parameter schema, embedded app images and
auth wiring that make a node valid, instead of hand-authoring JSON.

Config/creds are read from the Shuffle .env (never hardcoded here). Known Wazuh->
Shuffle payload quirks are encoded once as helpers so every playbook stops
re-solving them:
  - VirusTotal (HTTP-OpenAPI app) wraps its reply under `.body` -> use vt_ref()
  - TheHive/Telegram HTTP bodies need header Content-Type=application/json
  - Suricata uses data.src_ip, auth uses data.srcip -> normalize with src_ip_ref()
  - No array refs inside JSON bodies (their quotes break the JSON)
  - Telegram: no parse_mode when a value contains underscores
  - Wazuh AR API command names must be prefixed with '!'
"""
from __future__ import annotations

import copy
import json
import os
import re
import time
import urllib.request
import urllib.error
import uuid
from pathlib import Path

from scrub import expand, scrub_workflow

# --------------------------------------------------------------------------- #
# Paths & config
# --------------------------------------------------------------------------- #
HERE = Path(__file__).resolve().parent
SHUFFLE_DIR = HERE.parent.parent / "deploy" / "shuffle" / "Shuffle"
WORKFLOWS_DIR = HERE.parent / "workflows"
ENV_FILE = SHUFFLE_DIR / ".env"

BASE_URL = os.environ.get("SHUFFLE_URL", "http://localhost:5001")
ORG_ID = os.environ.get("SHUFFLE_ORG_ID", "")   # org id shown in the Shuffle admin page
EXEC_ENV = "Shuffle"           # execution environment for action nodes
TEMPLATE = WORKFLOWS_DIR / "_template_playbook1.json"


def _read_env(key: str) -> str:
    """Pull a value out of the Shuffle .env without importing dotenv."""
    if key in os.environ:
        return os.environ[key]
    if ENV_FILE.exists():
        for line in ENV_FILE.read_text().splitlines():
            line = line.strip()
            if line.startswith(key + "="):
                return line.split("=", 1)[1].strip().strip('"').strip("'")
    raise KeyError(f"{key} not found in env or {ENV_FILE}")


API_KEY = _read_env("SHUFFLE_DEFAULT_APIKEY")


# --------------------------------------------------------------------------- #
# API client (stdlib only — no external deps, matches the no-deps lab style)
# --------------------------------------------------------------------------- #
class Shuffle:
    def __init__(self, base_url: str = BASE_URL, api_key: str = API_KEY):
        self.base = base_url.rstrip("/")
        self.key = api_key

    def _req(self, method: str, path: str, body=None, raw: bool = False):
        url = f"{self.base}{path}"
        data = None
        headers = {"Authorization": f"Bearer {self.key}"}
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                payload = r.read().decode()
        except urllib.error.HTTPError as e:
            raise RuntimeError(f"{method} {path} -> HTTP {e.code}: {e.read().decode()[:400]}")
        if raw:
            return payload
        try:
            return json.loads(payload)
        except json.JSONDecodeError:
            return payload

    # --- workflows ---------------------------------------------------------- #
    def list_workflows(self):
        d = self._req("GET", "/api/v1/workflows")
        return d if isinstance(d, list) else d.get("data", d)

    def get_workflow(self, wf_id: str):
        return self._req("GET", f"/api/v1/workflows/{wf_id}")

    def save_workflow(self, wf: dict):
        """Persist a workflow object (create or update in place by its id)."""
        return self._req("PUT", f"/api/v1/workflows/{wf['id']}", body=wf)

    def create_workflow(self, name: str, description: str = ""):
        return self._req("POST", "/api/v1/workflows",
                         body={"name": name, "description": description})

    def build_workflow(self, name: str, description: str, *, actions, branches,
                       triggers, start: str, variables=None):
        """Canonical path: POST-create a server skeleton (real id + org), overlay
        our assembled nodes, then PUT-save. Returns the saved workflow object."""
        wf = self.create_workflow(name, description)
        wf["actions"] = actions
        wf["branches"] = branches
        wf["triggers"] = triggers
        wf["start"] = start
        if variables is not None:
            wf["workflow_variables"] = variables
        wf["is_valid"] = True
        self.save_workflow(wf)
        return wf

    def delete_workflow(self, wf_id: str):
        return self._req("DELETE", f"/api/v1/workflows/{wf_id}")

    def apps(self):
        d = self._req("GET", "/api/v1/apps")
        return d if isinstance(d, list) else d.get("data", d)

    def register_webhook(self, wf_id: str, trigger_id: str, name: str, start_node: str):
        """A webhook created inside workflow JSON must also be registered to fire."""
        return self._req("POST", "/api/v1/hooks",
                         body={"id": trigger_id, "name": name,
                               "workflow": wf_id, "start": start_node,
                               "type": "webhook", "status": "running"})

    # --- execution ---------------------------------------------------------- #
    def run_webhook(self, trigger_id: str, payload: dict):
        return self._req("POST", f"/api/v1/hooks/webhook_{trigger_id}", body=payload)

    def execution_result(self, wf_id: str, execution_id: str):
        """Fetch one execution's record from the workflow's executions list."""
        raw = self._req("GET", f"/api/v1/workflows/{wf_id}/executions")
        lst = raw if isinstance(raw, list) else (
            raw.get("executions") or raw.get("data") or [])
        for e in lst:
            if e.get("execution_id") == execution_id:
                return e
        return {}


def _expand_node(node: dict) -> dict:
    """Fill ${NAME} placeholders in a template node from the environment."""
    for p in node.get("parameters", []):
        p["value"] = expand(p.get("value", ""))
    return node


# --------------------------------------------------------------------------- #
# Prototype harvesting — clone real nodes instead of authoring schema by hand
# --------------------------------------------------------------------------- #
def load_template(path: Path = TEMPLATE) -> dict:
    return json.loads(Path(path).read_text())


class Prototypes:
    """Real node prototypes harvested from a working workflow export."""

    def __init__(self, template: dict | None = None):
        self.tpl = template or load_template()
        self._by_label = {a.get("label"): a for a in self.tpl.get("actions", [])}
        self._by_app_action = {}
        for a in self.tpl.get("actions", []):
            self._by_app_action[(a.get("app_name"), a.get("name"))] = a
        self.webhook = next((t for t in self.tpl.get("triggers", [])
                             if t.get("trigger_type") == "WEBHOOK"), None)

    def node(self, label: str) -> dict:
        """Deep copy of a template node by its label (e.g. 'wazuh_auth')."""
        if label not in self._by_label:
            raise KeyError(f"no template node labelled {label!r}; "
                           f"have {list(self._by_label)}")
        return _expand_node(copy.deepcopy(self._by_label[label]))

    def http(self) -> dict:
        """The universal HTTP node (used for any REST call — most portable)."""
        return self.node("wazuh_auth")


# --------------------------------------------------------------------------- #
# Factories
# --------------------------------------------------------------------------- #
def new_id() -> str:
    return str(uuid.uuid4())


class AppCatalog:
    """Live catalog of enabled apps -> lets us build a node for ANY app+action
    (not just the ones present in the template), pulling the real app_id,
    version, image and the action's parameter schema from the running Shuffle."""

    def __init__(self, api: "Shuffle"):
        self._apps = {a.get("name"): a for a in api.apps()}

    def app(self, name: str) -> dict:
        if name not in self._apps:
            raise KeyError(f"app {name!r} not enabled; have {list(self._apps)}")
        return self._apps[name]

    def action(self, app_name: str, action: str) -> dict:
        for a in self.app(app_name).get("actions", []):
            if a.get("name") == action:
                return a
        raise KeyError(f"{app_name} has no action {action!r}")


def app_node(protos: "Prototypes", catalog: AppCatalog, app_name: str,
             action: str, *, label: str, values: dict | None = None,
             pos=(400, 300), auth_id: str = "") -> dict:
    """Build an action node for any enabled app+action, using a real template
    node for the standard scaffolding fields and the live catalog for the
    app-specific fields + parameter schema."""
    app = catalog.app(app_name)
    act = catalog.action(app_name, action)
    n = copy.deepcopy(protos.http())        # reuse valid node scaffolding
    n["id"] = new_id()
    n["label"] = label
    n["app_id"] = app.get("id")
    n["app_name"] = app_name
    n["app_version"] = app.get("app_version")
    n["name"] = action
    n["large_image"] = app.get("large_image", n.get("large_image", ""))
    n["authentication_id"] = auth_id
    n["isStartNode"] = False
    n["position"] = {"x": float(pos[0]), "y": float(pos[1])}
    n["errors"] = []
    n["parameters"] = [copy.deepcopy(p) for p in act.get("parameters", [])]
    if values:
        _set_params(n, values)
    return n


def _set_params(node: dict, values: dict) -> dict:
    """Override existing parameter values on a cloned node (immutably-ish:
    the node is a fresh deepcopy already, so we mutate the copy)."""
    known = {p["name"] for p in node.get("parameters", [])}
    for p in node["parameters"]:
        if p["name"] in values:
            p["value"] = values[p["name"]]
    for k, v in values.items():
        if k not in known:
            node["parameters"].append({"description": "", "id": "", "name": k,
                                       "example": "", "value": v})
    return node


def http_node(protos: Prototypes, label: str, *, method: str, url: str,
              headers: str = "", body: str = "", username: str = "",
              password: str = "", verify: str = "false", timeout: str = "15",
              pos=(400, 300)) -> dict:
    """Build an HTTP action node by cloning the template HTTP node."""
    n = protos.http()
    n["id"] = new_id()
    n["label"] = label
    n["name"] = method.upper()
    n["isStartNode"] = False
    n["position"] = {"x": float(pos[0]), "y": float(pos[1])}
    n["errors"] = []
    _set_params(n, {"url": url, "headers": headers, "body": body,
                    "username": username, "password": password,
                    "verify": verify, "timeout": timeout})
    return n


def clone_node(protos: Prototypes, template_label: str, new_label: str,
               values: dict | None = None, pos=(400, 300)) -> dict:
    """Clone any dedicated-app template node (VT/TheHive/Telegram) by label."""
    n = protos.node(template_label)
    n["id"] = new_id()
    n["label"] = new_label
    n["isStartNode"] = False
    n["position"] = {"x": float(pos[0]), "y": float(pos[1])}
    n["errors"] = []
    if values:
        _set_params(n, values)
    return n


def telegram_node(protos: Prototypes, label: str, text: str, pos=(400, 300)) -> dict:
    """Clone the working Telegram node and set a plain-text message (no parse_mode
    — Markdown breaks on underscores in webhook URLs, per the lab lesson).
    Bot token and chat id come from TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID."""
    n = clone_node(protos, "telegram_low", label, pos=pos)
    token = os.environ.get("TELEGRAM_BOT_TOKEN", "")
    chat_id = os.environ.get("TELEGRAM_CHAT_ID", "")
    if not token or not chat_id:
        raise SystemExit("set TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID before building")
    body = json.dumps({"chat_id": chat_id, "text": text})
    _set_params(n, {"api_token": token, "body": body})
    return n


def branch(source_id: str, dest_id: str, conditions=None) -> dict:
    return {"destination_id": dest_id, "id": new_id(), "source_id": source_id,
            "label": "", "has_errors": False, "conditions": conditions or [],
            "decorator": False, "parent_controlled": False, "source_parent": ""}


def condition(source_ref: str, op: str, dest_value: str) -> dict:
    """A branch condition. op e.g. 'larger than','less than','equals','contains'."""
    def side(val):
        return {"type": "value", "value": val, "id": new_id()}
    return {"id": new_id(), "source": side(source_ref),
            "destination": side(dest_value),
            "condition": {"type": "static", "value": op, "id": new_id()}}


def webhook_trigger(protos: Prototypes, label: str, pos=(80, 300)) -> dict:
    """A fresh webhook trigger cloned from the template (new id)."""
    t = copy.deepcopy(protos.webhook)
    t["id"] = new_id()
    t["label"] = label
    t["isStartNode"] = False
    t["status"] = "running"
    t["position"] = {"x": float(pos[0]), "y": float(pos[1])}
    t["errors"] = []
    return t


# --------------------------------------------------------------------------- #
# Workflow assembly
# --------------------------------------------------------------------------- #
def blank_workflow(name: str, description: str, protos: Prototypes) -> dict:
    """A workflow skeleton derived from the template (keeps org/env scaffolding),
    with actions/branches/triggers emptied for fresh assembly."""
    wf = copy.deepcopy(protos.tpl)
    wf["id"] = new_id()
    wf["name"] = name
    wf["description"] = description
    wf["actions"] = []
    wf["branches"] = []
    wf["triggers"] = []
    wf["start"] = ""
    wf["is_valid"] = False
    wf["previously_saved"] = False
    for k in ("last_runtime", "published_id", "revision_id", "parentorg_workflow"):
        wf[k] = wf.get(k, "") and ""
    return wf


# --------------------------------------------------------------------------- #
# Payload-quirk helpers (encode the lessons once)
# --------------------------------------------------------------------------- #
def vt_ref(field: str) -> str:
    """Reference a VirusTotal field — the HTTP-OpenAPI app wraps under .body."""
    return f"$virustotal.body.{field.lstrip('.')}"


def src_ip_ref() -> str:
    """Normalized attacker IP ref: auth uses data.srcip, Suricata data.src_ip.
    Prefer srcip, fall back handled in a Shuffle Tools/normalizer node upstream."""
    return "$exec.data.srcip"


def json_header() -> str:
    """Value for an HTTP node 'headers' param so bodies aren't sent octet-stream."""
    return "Content-Type=application/json"


def ar_command(name: str) -> str:
    """Wazuh Active-Response API command names require a leading '!'."""
    return name if name.startswith("!") else "!" + name


def save_local(wf: dict, filename: str) -> Path:
    """Write a scrubbed workflow export to the versioned workflows/ dir."""
    WORKFLOWS_DIR.mkdir(parents=True, exist_ok=True)
    out = WORKFLOWS_DIR / filename
    out.write_text(json.dumps(scrub_workflow(wf), indent=2))   # never write credentials
    return out
