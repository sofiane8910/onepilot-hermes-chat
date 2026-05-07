"""Unit tests for the per-host POP signing module."""

from __future__ import annotations

import base64
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

PLUGIN_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PLUGIN_DIR))


def _b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


class PopKeysTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="onepilot-popkeys-")
        os.environ["HERMES_HOME"] = self.tmp
        # Force a fresh module load so HERMES_HOME is picked up.
        for mod in list(sys.modules):
            if mod == "pop_keys":
                del sys.modules[mod]
        import pop_keys  # noqa: F401  - imported for side-effect-free test use
        self.pop_keys = pop_keys

    def tearDown(self) -> None:
        os.environ.pop("HERMES_HOME", None)
        # Best-effort cleanup; tempfile.mkdtemp wins on remove failures.
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_keypair_idempotent(self):
        agent_id = "33333333-3333-3333-3333-333333333333"
        pub1, existed1 = self.pop_keys.get_or_create_keypair(agent_id)
        pub2, existed2 = self.pop_keys.get_or_create_keypair(agent_id)
        self.assertFalse(existed1)
        self.assertTrue(existed2)
        self.assertEqual(pub1, pub2)
        # 32-byte raw Ed25519 key, base64url no-pad.
        self.assertEqual(len(_b64url_decode(pub1)), 32)
        # File must exist with mode 0600.
        key_file = Path(self.tmp) / ".hermes" / "secrets" / f"{agent_id}.key"
        self.assertTrue(key_file.exists())
        self.assertEqual(key_file.stat().st_mode & 0o777, 0o600)

    def test_jwt_shape(self):
        agent_id = "44444444-4444-4444-4444-444444444444"
        self.pop_keys.get_or_create_keypair(agent_id)
        bearer = self.pop_keys.sign_auth_header(
            agent_profile_id=agent_id,
            method="POST",
            url="https://example.test/functions/v1/agent-message-ingest?ignored=1",
            scope="ingest",
        )
        self.assertTrue(bearer.startswith("Bearer "))
        token = bearer[len("Bearer "):]
        parts = token.split(".")
        self.assertEqual(len(parts), 3)

        header = json.loads(_b64url_decode(parts[0]))
        self.assertEqual(header["alg"], "EdDSA")
        self.assertEqual(header["typ"], "JWT")
        self.assertEqual(header["kid"], agent_id)

        payload = json.loads(_b64url_decode(parts[1]))
        self.assertEqual(payload["sub"], agent_id)
        self.assertEqual(payload["scope"], "ingest")
        # htu drops the query string.
        self.assertEqual(payload["htu"], "https://example.test/functions/v1/agent-message-ingest")
        self.assertEqual(payload["htm"], "POST")
        self.assertGreater(payload["exp"] - payload["iat"], 0)
        self.assertLessEqual(payload["exp"] - payload["iat"], 120)
        self.assertGreaterEqual(len(payload["jti"]), 16)

        # Signature must verify against the stored public key.
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        pub_b64u, _ = self.pop_keys.get_or_create_keypair(agent_id)
        pub = Ed25519PublicKey.from_public_bytes(_b64url_decode(pub_b64u))
        signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
        # Will raise on mismatch; success returns None.
        pub.verify(_b64url_decode(parts[2]), signing_input)

    def test_jwt_missing_keypair_raises(self):
        with self.assertRaises(RuntimeError):
            self.pop_keys.sign_auth_header(
                agent_profile_id="55555555-5555-5555-5555-555555555555",
                method="GET",
                url="https://example.test/x",
                scope="history",
            )

    def test_required_args(self):
        with self.assertRaises(ValueError):
            self.pop_keys.sign_auth_header(
                agent_profile_id="", method="GET", url="https://x", scope="history",
            )


if __name__ == "__main__":
    unittest.main()
