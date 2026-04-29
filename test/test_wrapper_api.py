"""Contract test for the Hermes onepilot-platform wrapper API.

Boots wrapper_api on a random port with a fixture config.json; hits each
endpoint with urllib; asserts shape. No real Hermes process required —
shell-out paths are exercised only by /plugin/uninstall (skipped here
because we can't safely shell `hermes` in CI).
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from urllib import request as urlrequest
from urllib.error import HTTPError

PLUGIN_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PLUGIN_DIR))


AGENT_KEY = "oak_test_keykey1234567890"


def _pick_port() -> int:
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class WrapperApiTests(unittest.TestCase):
    def setUp(self) -> None:
        # Write a fixture config.json adjacent to the plugin module so that
        # CONFIG_PATH (PLUGIN_DIR/config.json) finds it. Save the previous
        # contents (if any) so we can restore them.
        self.cfg_path = PLUGIN_DIR / "config.json"
        self.prev_cfg = self.cfg_path.read_bytes() if self.cfg_path.exists() else None
        self.cfg_path.write_text(json.dumps({
            "enabled": True,
            "backendUrl": "http://127.0.0.1:9999",
            "streamUrl": "ws://127.0.0.1:9999",
            "publishableKey": "pk_test",
            "agentKey": AGENT_KEY,
            "userId": "11111111-1111-1111-1111-111111111111",
            "agentProfileId": "22222222-2222-2222-2222-222222222222",
            "sessionKey": "main",
        }))

        # Force start_wrapper_api to use the chosen port.
        self.port = _pick_port()
        os.environ["ONEPILOT_WRAPPER_PORT"] = str(self.port)

        import wrapper_api  # type: ignore[import-not-found]
        self.wrapper_api = wrapper_api
        # Reset Handler class state between tests (module-level singletons).
        wrapper_api._Handler.expected_keys = []
        self.server = wrapper_api.start_wrapper_api(
            initial_config=json.loads(self.cfg_path.read_text()),
            gateway_port=8642,
        )
        self.assertIsNotNone(self.server, "wrapper failed to start")
        # Give the daemon thread a beat to begin serving.
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

    def _curl(self, method: str, path: str, body=None, key: str = AGENT_KEY):
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
        status, _ = self._curl("GET", "/onepilot/v1/health", key="oak_wrong")
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

    def test_configure_merges(self):
        status, body = self._curl("POST", "/onepilot/v1/configure", {
            "accounts": {"default": {"sessionKey": "rotated"}},
        })
        self.assertEqual(status, 200, body)
        self.assertTrue(body["ok"])
        on_disk = json.loads(self.cfg_path.read_text())
        self.assertEqual(on_disk["sessionKey"], "rotated")
        # untouched fields preserved
        self.assertEqual(on_disk["agentKey"], AGENT_KEY)

    def test_revoke_disables(self):
        status, body = self._curl("POST", "/onepilot/v1/account/revoke", {})
        self.assertEqual(status, 200, body)
        self.assertTrue(body["ok"])
        on_disk = json.loads(self.cfg_path.read_text())
        self.assertEqual(on_disk["enabled"], False)
        self.assertEqual(on_disk["agentKey"], "")

    def test_unknown_path(self):
        status, _ = self._curl("GET", "/onepilot/v1/nope")
        self.assertEqual(status, 404)

    def test_rotate_requires_token(self):
        status, body = self._curl("POST", "/onepilot/v1/account/rotate", {})
        self.assertEqual(status, 400, body)


if __name__ == "__main__":
    unittest.main()
