"""HTTP wrapper API for the Onepilot Hermes plugin.

Bind: 127.0.0.1:(ONEPILOT_WRAPPER_PORT or HERMES_GATEWAY_PORT+1).
Auth: Bearer <wrapperApiToken> — loopback-only, no Supabase scope.
"""

from __future__ import annotations

import hmac
import json
import logging
import os
import re
import secrets
import shutil
import subprocess
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Optional
from urllib import request as urlrequest
from urllib.error import HTTPError, URLError

logger = logging.getLogger("hermes_plugins.onepilot.wrapper")

PLUGIN_DIR = Path(__file__).resolve().parent
CONFIG_PATH = PLUGIN_DIR / "config.json"
PLUGIN_VERSION = "0.10.0"

_UUID_RE = re.compile(r"^[0-9a-f-]{36}$", re.IGNORECASE)


def _import_pop_keys():
    try:
        from . import pop_keys as _mod  # type: ignore[import-not-found]
        return _mod
    except (ImportError, ValueError):
        import sys
        here = str(PLUGIN_DIR)
        if here not in sys.path:
            sys.path.insert(0, here)
        import pop_keys as _mod  # type: ignore[no-redef]
        return _mod


def _import_approvals():
    try:
        from . import approvals as _mod  # type: ignore[import-not-found]
        return _mod
    except (ImportError, ValueError):
        import sys
        here = str(PLUGIN_DIR)
        if here not in sys.path:
            sys.path.insert(0, here)
        import approvals as _mod  # type: ignore[no-redef]
        return _mod


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
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
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
    server_version = "onepilot-wrapper/0.10"
    started_at: str = ""
    expected_tokens: list[str] = []
    tokens_lock = threading.Lock()

    def log_message(self, fmt: str, *args: Any) -> None:
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
        return json.loads(raw.decode("utf-8")) if raw else {}

    def _bearer_present(self) -> Optional[str]:
        header = self.headers.get("authorization") or ""
        if not header.startswith("Bearer "):
            return None
        return header[len("Bearer "):]

    def _is_bootstrap_allowed(self) -> bool:
        # First-run bootstrap: no wrapperApiToken yet → allow ONLY
        # POST /onepilot/v1/account/configure-key. Closes the install
        # chicken-and-egg without exposing the rest of the surface.
        if self.command != "POST" or self.path != "/onepilot/v1/account/configure-key":
            return False
        cfg = _load_config()
        return not isinstance(cfg.get("wrapperApiToken"), str) or not cfg.get("wrapperApiToken")

    def _check_auth(self) -> bool:
        presented = self._bearer_present() or ""
        if presented:
            with self.__class__.tokens_lock:
                tokens = list(self.__class__.expected_tokens)
            if any(hmac.compare_digest(presented, t) for t in tokens):
                return True
            # Re-read from disk in case configure-key just minted a token.
            cfg = _load_config()
            disk = cfg.get("wrapperApiToken")
            if isinstance(disk, str) and disk:
                with self.__class__.tokens_lock:
                    if disk not in self.__class__.expected_tokens:
                        self.__class__.expected_tokens.append(disk)
                if hmac.compare_digest(presented, disk):
                    return True
        return self._is_bootstrap_allowed()

    # --- routing ---

    def do_GET(self) -> None:  # noqa: N802
        try:
            if not self._check_auth():
                return self._send_json(401, {"ok": False, "error": "unauthorized"})
            if self.path == "/onepilot/v1/health":
                return self._handle_health()
            if self.path == "/onepilot/v1/approvals/config":
                return self._handle_approvals_config_get()
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
            if self.path == "/onepilot/v1/account/configure-key":
                return self._handle_configure_key(body)
            if self.path == "/onepilot/v1/account/revoke":
                return self._handle_revoke(body)
            if self.path == "/onepilot/v1/plugin/uninstall":
                return self._handle_uninstall()
            if self.path == "/onepilot/v1/approvals/config":
                return self._handle_approvals_config_post(body)
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
        configured = bool(cfg.get("wrapperApiToken") and cfg.get("agentProfileId"))
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
        # Sparse merge, non-secret fields only. wrapperApiToken is minted
        # exclusively by configure-key — never accept it from a body.
        accounts = body.get("accounts") if isinstance(body, dict) else None
        if isinstance(accounts, dict) and accounts:
            patch = accounts.get("default") or next(iter(accounts.values()), {})
        else:
            patch = body if isinstance(body, dict) else {}
        if not isinstance(patch, dict):
            return self._send_json(400, {"ok": False, "error": "invalid configure payload"})
        cfg = _load_config()
        for k, v in patch.items():
            if k in {"wrapperApiToken", "agentKey"}:
                continue  # write-once / banned fields
            cfg[k] = v
        _save_config(cfg)
        self._send_json(200, {"ok": True, "written": ["default"]})

    def _handle_configure_key(self, body: dict[str, Any]) -> None:
        access_token = body.get("accessToken") if isinstance(body, dict) else None
        agent_profile_id = (body.get("agentProfileId") or "").lower()
        if not access_token:
            return self._send_json(400, {"ok": False, "error": "accessToken required"})
        if not _UUID_RE.match(agent_profile_id):
            return self._send_json(400, {"ok": False, "error": "agentProfileId (uuid) required"})

        cfg = _load_config()
        existing_id = (cfg.get("agentProfileId") or "").lower() if isinstance(cfg.get("agentProfileId"), str) else ""
        if existing_id and existing_id != agent_profile_id:
            return self._send_json(409, {
                "ok": False,
                "error": f"plugin already bound to a different agentProfileId",
            })

        merged = {
            "enabled": cfg.get("enabled") if cfg.get("enabled") is not None else True,
            "backendUrl": body.get("backendUrl") or cfg.get("backendUrl"),
            "streamUrl": body.get("streamUrl") or cfg.get("streamUrl"),
            "publishableKey": body.get("publishableKey") or cfg.get("publishableKey"),
            "userId": body.get("userId") or cfg.get("userId"),
            "agentProfileId": agent_profile_id,
            "sessionKey": body.get("sessionKey") or cfg.get("sessionKey") or "main",
            "wrapperApiToken": cfg.get("wrapperApiToken"),
            "configuredAt": cfg.get("configuredAt") or datetime.now(timezone.utc).isoformat(),
        }
        required = ["backendUrl", "streamUrl", "publishableKey", "userId", "agentProfileId", "sessionKey"]
        missing = [k for k in required if not merged.get(k)]
        if missing:
            return self._send_json(400, {"ok": False, "error": f"missing fields: {','.join(missing)}"})

        try:
            pop = _import_pop_keys()
        except Exception as exc:
            return self._send_json(500, {"ok": False, "error": f"pop_keys import: {exc}"})

        try:
            public_key_b64u, already_existed = pop.get_or_create_keypair(agent_profile_id)
        except Exception as exc:
            return self._send_json(500, {"ok": False, "error": f"keypair: {exc}"})

        # Register the public key with mint-agent-key. POP-only on the server.
        url = f"{merged['backendUrl']}/functions/v1/mint-agent-key"
        req = urlrequest.Request(
            url,
            data=json.dumps({
                "agent_profile_id": agent_profile_id,
                "client_public_key": public_key_b64u,
            }).encode("utf-8"),
            method="POST",
        )
        req.add_header("content-type", "application/json")
        req.add_header("authorization", f"Bearer {access_token}")
        if merged.get("publishableKey"):
            req.add_header("apikey", merged["publishableKey"])

        try:
            with urlrequest.urlopen(req, timeout=20) as r:
                parsed = json.loads(r.read().decode("utf-8"))
        except HTTPError as exc:
            return self._send_json(exc.code, {
                "ok": False,
                "error": f"mint failed: {exc.read().decode('utf-8', errors='replace')[:200]}",
            })
        except (URLError, json.JSONDecodeError) as exc:
            return self._send_json(502, {"ok": False, "error": f"mint failed: {exc}"})

        key_fingerprint = parsed.get("key_fingerprint") if isinstance(parsed, dict) else None
        if not isinstance(key_fingerprint, str):
            return self._send_json(502, {"ok": False, "error": "mint response missing key_fingerprint"})

        token_issued = False
        if not isinstance(merged.get("wrapperApiToken"), str) or not merged.get("wrapperApiToken"):
            merged["wrapperApiToken"] = "wat_" + secrets.token_urlsafe(32).rstrip("=")
            token_issued = True

        _save_config(merged)
        with self.__class__.tokens_lock:
            if merged["wrapperApiToken"] not in self.__class__.expected_tokens:
                self.__class__.expected_tokens.append(merged["wrapperApiToken"])

        resp: dict[str, Any] = {
            "ok": True,
            "accountId": "default",
            "agentProfileId": agent_profile_id,
            "keyFingerprint": key_fingerprint,
            "keypairProvisioned": not already_existed,
            "configuredAt": merged["configuredAt"],
        }
        if token_issued:
            resp["wrapperApiToken"] = merged["wrapperApiToken"]
        self._send_json(200, resp)

    def _handle_revoke(self, _body: dict[str, Any]) -> None:
        cfg = _load_config()
        if not cfg:
            return self._send_json(404, {"ok": False, "error": "not configured"})
        cfg["enabled"] = False
        # Clear loopback token but keep agentProfileId so a later configure-key
        # call can detect "same agent, lost token → re-pair from iOS". The
        # private key on disk also stays — its only effect now is to make a
        # fresh mint reuse the same public key, which is harmless.
        cfg["wrapperApiToken"] = ""
        _save_config(cfg)
        self._send_json(200, {"ok": True})

    def _handle_uninstall(self) -> None:
        rc, out, err = _shell_hermes(["plugins", "uninstall", "onepilot", "--force"], timeout=30.0)
        if rc != 0:
            return self._send_json(500, {
                "ok": False,
                "error": f"uninstall rc={rc}: {(err or out)[:200]}",
            })
        self._send_json(200, {"ok": True})

    # --- approvals ---

    def _handle_approvals_config_get(self) -> None:
        try:
            mod = _import_approvals()
            enabled = bool(mod.is_approvals_forwarding_enabled())
        except Exception as exc:
            return self._send_json(500, {"ok": False, "error": f"approvals: {exc}"})
        self._send_json(200, {"ok": True, "enabled": enabled})

    def _handle_approvals_config_post(self, body: dict[str, Any]) -> None:
        if not isinstance(body, dict):
            return self._send_json(400, {"ok": False, "error": "json object required"})
        enabled = body.get("enabled")
        if not isinstance(enabled, bool):
            return self._send_json(400, {"ok": False, "error": "`enabled` (boolean) required"})
        try:
            mod = _import_approvals()
            mod.set_approvals_forwarding_enabled(enabled)
        except Exception as exc:
            return self._send_json(500, {"ok": False, "error": f"approvals write failed: {exc}"})
        self._send_json(200, {"ok": True, "enabled": enabled})


def start_wrapper_api(initial_config: dict[str, Any], gateway_port: int) -> Optional[ThreadingHTTPServer]:
    """Start the wrapper HTTP server in a daemon thread. Returns the server."""
    port_env = os.environ.get("ONEPILOT_WRAPPER_PORT")
    try:
        port = int(port_env) if port_env else gateway_port + 1
    except ValueError:
        port = gateway_port + 1

    _Handler.started_at = datetime.now(timezone.utc).isoformat()
    initial_token = initial_config.get("wrapperApiToken")
    if isinstance(initial_token, str) and initial_token:
        _Handler.expected_tokens = [initial_token]

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

    threading.Thread(target=_serve, name="onepilot-wrapper", daemon=True).start()
    logger.info("[onepilot:wrapper] listening on 127.0.0.1:%d (v%s)", port, PLUGIN_VERSION)
    return server
