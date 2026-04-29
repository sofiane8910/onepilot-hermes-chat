"""HTTP wrapper API for the Onepilot Hermes plugin.

Same contract as the OpenClaw onepilot-channel wrapper:
  GET  /onepilot/v1/health
  POST /onepilot/v1/configure
  POST /onepilot/v1/account/rotate
  POST /onepilot/v1/account/revoke
  POST /onepilot/v1/plugin/uninstall

Bind: 127.0.0.1:(ONEPILOT_WRAPPER_PORT or HERMES_GATEWAY_PORT+1).
Auth: Authorization: Bearer <agentKey> against the configured key.
Out-of-process effects (config writes, plugin uninstall) shell out to
`hermes` from inside this plugin so framework-CLI changes ship via plugin
update instead of an iOS release.
"""

from __future__ import annotations

import hmac
import json
import logging
import os
import shutil
import subprocess
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Optional
from urllib import request as urlrequest
from urllib.error import HTTPError, URLError

logger = logging.getLogger("hermes_plugins.onepilot.wrapper")

PLUGIN_DIR = Path(__file__).resolve().parent
CONFIG_PATH = PLUGIN_DIR / "config.json"
PLUGIN_VERSION = "0.6.0"


def _load_config() -> dict[str, Any]:
    try:
        return json.loads(CONFIG_PATH.read_text())
    except FileNotFoundError:
        return {}
    except Exception as exc:
        logger.warning("[onepilot:wrapper] config load failed: %s", exc)
        return {}


def _save_config(cfg: dict[str, Any]) -> None:
    tmp = CONFIG_PATH.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(cfg, indent=2))
    os.replace(tmp, CONFIG_PATH)


def _resolve_profile_id() -> Optional[str]:
    # Plugin lives at ~/.hermes/profiles/<id>/plugins/onepilot-platform/
    parts = PLUGIN_DIR.resolve().parts
    try:
        i = parts.index("profiles")
        return parts[i + 1]
    except (ValueError, IndexError):
        return os.environ.get("HERMES_PROFILE_ID")


def _hermes_bin() -> str:
    return os.environ.get("HERMES_BIN") or shutil.which("hermes") or "hermes"


def _shell_hermes(args: list[str], timeout: float = 30.0) -> tuple[int, str, str]:
    profile = _resolve_profile_id()
    cmd = [_hermes_bin()]
    if profile:
        cmd.extend(["-p", profile])
    cmd.extend(args)
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except subprocess.TimeoutExpired as exc:
        return 124, "", str(exc)
    except Exception as exc:
        return 1, "", str(exc)


def _framework_version() -> Optional[str]:
    rc, out, _ = _shell_hermes(["--version"], timeout=5.0)
    if rc == 0 and out.strip():
        return out.strip()
    return None


class _Handler(BaseHTTPRequestHandler):
    server_version = "onepilot-wrapper/0.4"
    started_at: str = ""
    expected_keys: list[str] = []
    keys_lock = threading.Lock()

    def log_message(self, fmt: str, *args: Any) -> None:  # silence default stderr
        logger.info("[onepilot:wrapper] " + fmt, *args)

    # --- helpers ---

    def _send_json(self, status: int, body: dict[str, Any]) -> None:
        payload = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _read_json(self, max_bytes: int = 64 * 1024) -> Any:
        length = int(self.headers.get("content-length") or 0)
        if length <= 0:
            return {}
        if length > max_bytes:
            raise ValueError("payload too large")
        raw = self.rfile.read(length)
        if not raw:
            return {}
        return json.loads(raw.decode("utf-8"))

    def _check_auth(self) -> bool:
        header = self.headers.get("authorization") or ""
        if not header.startswith("Bearer "):
            return False
        presented = header[len("Bearer "):]
        with self.__class__.keys_lock:
            keys = list(self.__class__.expected_keys)
        # Re-load from disk if no match (cheap; happens after rotate).
        if not any(hmac.compare_digest(presented, k) for k in keys):
            cfg = _load_config()
            disk_key = cfg.get("agentKey")
            if disk_key:
                with self.__class__.keys_lock:
                    if disk_key not in self.__class__.expected_keys:
                        self.__class__.expected_keys.append(disk_key)
                    keys = list(self.__class__.expected_keys)
            return any(hmac.compare_digest(presented, k) for k in keys)
        return True

    # --- routing ---

    def do_GET(self) -> None:  # noqa: N802
        try:
            if not self._check_auth():
                return self._send_json(401, {"ok": False, "error": "unauthorized"})
            if self.path == "/onepilot/v1/health":
                return self._handle_health()
            self._send_json(404, {"ok": False, "error": "not found"})
        except Exception as exc:
            logger.warning("[onepilot:wrapper] GET %s failed: %s", self.path, exc)
            try:
                self._send_json(500, {"ok": False, "error": str(exc)})
            except Exception:
                pass

    def do_POST(self) -> None:  # noqa: N802
        try:
            if not self._check_auth():
                return self._send_json(401, {"ok": False, "error": "unauthorized"})
            body = self._read_json()
            if self.path == "/onepilot/v1/configure":
                return self._handle_configure(body)
            if self.path == "/onepilot/v1/account/rotate":
                return self._handle_rotate(body)
            if self.path == "/onepilot/v1/account/revoke":
                return self._handle_revoke(body)
            if self.path == "/onepilot/v1/plugin/uninstall":
                return self._handle_uninstall()
            self._send_json(404, {"ok": False, "error": "not found"})
        except json.JSONDecodeError as exc:
            self._send_json(400, {"ok": False, "error": f"invalid json: {exc}"})
        except ValueError as exc:
            self._send_json(400, {"ok": False, "error": str(exc)})
        except Exception as exc:
            logger.warning("[onepilot:wrapper] POST %s failed: %s", self.path, exc)
            try:
                self._send_json(500, {"ok": False, "error": str(exc)})
            except Exception:
                pass

    # --- handlers ---

    def _handle_health(self) -> None:
        cfg = _load_config()
        configured = bool(cfg.get("agentKey") and cfg.get("agentProfileId"))
        self._send_json(200, {
            "ok": True,
            "plugin_id": "onepilot",
            "plugin_version": PLUGIN_VERSION,
            "framework": "hermes",
            "framework_version": _framework_version(),
            "account_configured": configured,
            "enabled": cfg.get("enabled") is not False if configured else False,
            "wrapper_api": "v1",
            "started_at": self.__class__.started_at,
        })

    def _handle_configure(self, body: dict[str, Any]) -> None:
        # Hermes plugin has a single account in its own config.json (no
        # multi-account dict like OpenClaw). Sparse merge into config.json.
        accounts = body.get("accounts") if isinstance(body, dict) else None
        patch: dict[str, Any]
        if isinstance(accounts, dict) and accounts:
            # Accept either {default: {...}} or a flat shape for parity.
            patch = accounts.get("default") or next(iter(accounts.values()), {})
        else:
            patch = body if isinstance(body, dict) else {}
        if not isinstance(patch, dict):
            return self._send_json(400, {"ok": False, "error": "invalid configure payload"})
        cfg = _load_config()
        cfg.update(patch)
        _save_config(cfg)
        if isinstance(cfg.get("agentKey"), str):
            with self.__class__.keys_lock:
                if cfg["agentKey"] not in self.__class__.expected_keys:
                    self.__class__.expected_keys.append(cfg["agentKey"])
        self._send_json(200, {"ok": True, "written": ["default"]})

    def _handle_rotate(self, body: dict[str, Any]) -> None:
        access_token = body.get("accessToken") if isinstance(body, dict) else None
        if not access_token:
            return self._send_json(400, {"ok": False, "error": "accessToken required"})
        cfg = _load_config()
        backend_url = cfg.get("backendUrl")
        agent_profile_id = cfg.get("agentProfileId")
        if not backend_url or not agent_profile_id:
            return self._send_json(409, {"ok": False, "error": "plugin not configured"})
        url = f"{backend_url}/functions/v1/mint-agent-key"
        req = urlrequest.Request(
            url,
            data=json.dumps({"agent_profile_id": agent_profile_id}).encode("utf-8"),
            method="POST",
        )
        req.add_header("content-type", "application/json")
        req.add_header("authorization", f"Bearer {access_token}")
        api_key = body.get("publishableKey") or cfg.get("publishableKey")
        if api_key:
            req.add_header("apikey", api_key)
        try:
            with urlrequest.urlopen(req, timeout=20) as r:
                raw = r.read().decode("utf-8")
                parsed = json.loads(raw)
        except HTTPError as exc:
            return self._send_json(exc.code, {
                "ok": False,
                "error": f"mint failed: {exc.read().decode('utf-8', errors='replace')[:200]}",
            })
        except (URLError, json.JSONDecodeError) as exc:
            return self._send_json(502, {"ok": False, "error": f"mint failed: {exc}"})
        new_key = parsed.get("agent_key") if isinstance(parsed, dict) else None
        if not isinstance(new_key, str) or not new_key.startswith("oak_"):
            return self._send_json(502, {"ok": False, "error": "mint response missing agent_key"})
        cfg["agentKey"] = new_key
        _save_config(cfg)
        with self.__class__.keys_lock:
            if new_key not in self.__class__.expected_keys:
                self.__class__.expected_keys.append(new_key)
        self._send_json(200, {
            "ok": True,
            "agent_key_prefix": new_key[:8],
            "rotated_at": datetime.now(timezone.utc).isoformat(),
        })

    def _handle_revoke(self, _body: dict[str, Any]) -> None:
        cfg = _load_config()
        if not cfg:
            return self._send_json(404, {"ok": False, "error": "not configured"})
        # Disable + clear the key. We don't delete the file so the plugin
        # remains addressable for re-pair without a fresh deploy.
        cfg["enabled"] = False
        cfg["agentKey"] = ""
        _save_config(cfg)
        self._send_json(200, {"ok": True})

    def _handle_uninstall(self) -> None:
        rc, out, err = _shell_hermes(
            ["plugins", "uninstall", "onepilot", "--force"], timeout=30.0
        )
        if rc != 0:
            return self._send_json(500, {
                "ok": False,
                "error": f"uninstall rc={rc}: {(err or out)[:200]}",
            })
        self._send_json(200, {"ok": True})


def start_wrapper_api(initial_config: dict[str, Any], gateway_port: int) -> Optional[ThreadingHTTPServer]:
    """Start the wrapper HTTP server in a daemon thread. Returns the server."""
    port_env = os.environ.get("ONEPILOT_WRAPPER_PORT")
    try:
        port = int(port_env) if port_env else gateway_port + 1
    except ValueError:
        port = gateway_port + 1

    _Handler.started_at = datetime.now(timezone.utc).isoformat()
    initial_key = initial_config.get("agentKey")
    if isinstance(initial_key, str) and initial_key:
        _Handler.expected_keys = [initial_key]

    try:
        server = ThreadingHTTPServer(("127.0.0.1", port), _Handler)
    except OSError as exc:
        logger.warning("[onepilot:wrapper] bind 127.0.0.1:%d failed: %s", port, exc)
        return None

    def _serve() -> None:
        try:
            server.serve_forever(poll_interval=1.0)
        except Exception as exc:
            logger.warning("[onepilot:wrapper] serve_forever crashed: %s", exc)

    thread = threading.Thread(target=_serve, name="onepilot-wrapper", daemon=True)
    thread.start()
    logger.info(
        "[onepilot:wrapper] listening on 127.0.0.1:%d (v%s)", port, PLUGIN_VERSION
    )
    return server
