"""Contract test for the Hermes onepilot wrapper API (v0.10.0+)."""

from __future__ import annotations

import json
import os
import sys
import time
import unittest
from pathlib import Path
from urllib import request as urlrequest
from urllib.error import HTTPError

PLUGIN_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PLUGIN_DIR))


WRAPPER_TOKEN = "wat_test_wrappertoken1234567890"


def _pick_port() -> int:
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class WrapperApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.cfg_path = PLUGIN_DIR / "config.json"
        self.prev_cfg = self.cfg_path.read_bytes() if self.cfg_path.exists() else None
        self.cfg_path.write_text(json.dumps({
            "enabled": True,
            "backendUrl": "http://127.0.0.1:9999",
            "streamUrl": "ws://127.0.0.1:9999",
            "publishableKey": "pk_test",
            "wrapperApiToken": WRAPPER_TOKEN,
            "userId": "11111111-1111-1111-1111-111111111111",
            "agentProfileId": "22222222-2222-2222-2222-222222222222",
            "sessionKey": "main",
            "configuredAt": "2026-05-06T12:00:00+00:00",
        }))

        self.port = _pick_port()
        os.environ["ONEPILOT_WRAPPER_PORT"] = str(self.port)

        import wrapper_api  # type: ignore[import-not-found]
        self.wrapper_api = wrapper_api
        wrapper_api._Handler.expected_tokens = []
        self.server = wrapper_api.start_wrapper_api(
            initial_config=json.loads(self.cfg_path.read_text()),
            gateway_port=8642,
        )
        self.assertIsNotNone(self.server, "wrapper failed to start")
        time.sleep(0.05)

    def tearDown(self) -> None:
        try:
            self.server.shutdown()
            self.server.server_close()
        except Exception:
            pass
        if self.prev_cfg is None:
            if self.cfg_path.exists():
                self.cfg_path.unlink()
        else:
            self.cfg_path.write_bytes(self.prev_cfg)
        os.environ.pop("ONEPILOT_WRAPPER_PORT", None)

    def _curl(self, method: str, path: str, body=None, key: str = WRAPPER_TOKEN):
        data = json.dumps(body).encode("utf-8") if body is not None else None
        req = urlrequest.Request(
            f"http://127.0.0.1:{self.port}{path}",
            data=data,
            method=method,
        )
        if key is not None:
            req.add_header("authorization", f"Bearer {key}")
        if data is not None:
            req.add_header("content-type", "application/json")
        try:
            with urlrequest.urlopen(req, timeout=5) as r:
                return r.status, json.loads(r.read().decode("utf-8"))
        except HTTPError as exc:
            try:
                payload = json.loads(exc.read().decode("utf-8"))
            except Exception:
                payload = {}
            return exc.code, payload

    def test_rejects_missing_bearer(self):
        req = urlrequest.Request(f"http://127.0.0.1:{self.port}/onepilot/v1/health")
        try:
            urlrequest.urlopen(req, timeout=5)
            self.fail("expected 401")
        except HTTPError as exc:
            self.assertEqual(exc.code, 401)

    def test_rejects_wrong_bearer(self):
        status, _ = self._curl("GET", "/onepilot/v1/health", key="wat_wrong")
        self.assertEqual(status, 401)

    def test_health_shape(self):
        status, body = self._curl("GET", "/onepilot/v1/health")
        self.assertEqual(status, 200)
        self.assertTrue(body["ok"])
        self.assertEqual(body["plugin_id"], "onepilot")
        self.assertEqual(body["framework"], "hermes")
        self.assertEqual(body["wrapper_api"], "v1")
        self.assertTrue(body["account_configured"])
        self.assertIsInstance(body["plugin_version"], str)

    def test_configure_merges_non_secret_only(self):
        # Sparse merge keeps wrapperApiToken untouched even if a malicious
        # caller sends one. Same for the legacy agentKey field.
        status, body = self._curl("POST", "/onepilot/v1/configure", {
            "accounts": {"default": {
                "sessionKey": "rotated",
                "wrapperApiToken": "wat_attacker_supplied",
                "agentKey": "oak_attacker_supplied",
            }},
        })
        self.assertEqual(status, 200, body)
        self.assertTrue(body["ok"])
        on_disk = json.loads(self.cfg_path.read_text())
        self.assertEqual(on_disk["sessionKey"], "rotated")
        self.assertEqual(on_disk["wrapperApiToken"], WRAPPER_TOKEN)
        self.assertNotIn("agentKey", on_disk)

    def test_revoke_disables(self):
        status, body = self._curl("POST", "/onepilot/v1/account/revoke", {})
        self.assertEqual(status, 200, body)
        self.assertTrue(body["ok"])
        on_disk = json.loads(self.cfg_path.read_text())
        self.assertEqual(on_disk["enabled"], False)
        self.assertEqual(on_disk["wrapperApiToken"], "")

    def test_unknown_path(self):
        status, _ = self._curl("GET", "/onepilot/v1/nope")
        self.assertEqual(status, 404)

    def test_configure_key_requires_access_token(self):
        # Plugin already has a wrapperApiToken so bootstrap is closed; need
        # the bearer. configure-key body is missing accessToken → 400.
        status, body = self._curl(
            "POST",
            "/onepilot/v1/account/configure-key",
            {"agentProfileId": "22222222-2222-2222-2222-222222222222"},
        )
        self.assertEqual(status, 400, body)

    def test_configure_key_rejects_mismatched_agent_profile(self):
        status, body = self._curl(
            "POST",
            "/onepilot/v1/account/configure-key",
            {
                "accessToken": "fake-jwt",
                "agentProfileId": "33333333-3333-3333-3333-333333333333",
                "publishableKey": "pk_test",
                "backendUrl": "http://127.0.0.1:9999",
                "streamUrl": "ws://127.0.0.1:9999",
                "userId": "11111111-1111-1111-1111-111111111111",
                "sessionKey": "main",
            },
        )
        self.assertEqual(status, 409, body)

    def test_bootstrap_only_configure_key(self):
        # Wipe wrapperApiToken to enter bootstrap mode. /health and
        # /configure must still 401 without auth; configure-key is allowed.
        cfg = json.loads(self.cfg_path.read_text())
        cfg.pop("wrapperApiToken", None)
        self.cfg_path.write_text(json.dumps(cfg))

        # /health → 401 (bootstrap only opens for configure-key)
        status, _ = self._curl("GET", "/onepilot/v1/health", key=None)
        self.assertEqual(status, 401)

        # configure-key without bearer → reaches the handler (will 400 on
        # missing accessToken, not 401).
        status, body = self._curl(
            "POST",
            "/onepilot/v1/account/configure-key",
            {},
            key=None,
        )
        self.assertEqual(status, 400, body)


if __name__ == "__main__":
    unittest.main()
