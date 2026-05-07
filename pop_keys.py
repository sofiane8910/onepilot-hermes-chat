"""Per-host Ed25519 keypair + POP JWT signing for Supabase calls."""

from __future__ import annotations

import base64
import json
import os
import secrets
import threading
import time
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

_TOKEN_LIFETIME_S = 90

_HOME = Path(os.environ.get("HERMES_HOME") or os.path.expanduser("~"))
_SECRETS_DIR = _HOME / ".hermes" / "secrets"

_gen_lock = threading.Lock()
_per_id_locks: dict[str, threading.Lock] = {}


def _b64url(buf: bytes) -> str:
    return base64.urlsafe_b64encode(buf).rstrip(b"=").decode("ascii")


def _key_path(agent_profile_id: str) -> Path:
    return _SECRETS_DIR / f"{agent_profile_id.lower()}.key"


def _id_lock(agent_profile_id: str) -> threading.Lock:
    with _gen_lock:
        lk = _per_id_locks.get(agent_profile_id)
        if lk is None:
            lk = threading.Lock()
            _per_id_locks[agent_profile_id] = lk
        return lk


def _ensure_secrets_dir() -> None:
    _SECRETS_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        os.chmod(_SECRETS_DIR, 0o700)
    except OSError:
        pass


def _public_key_b64u(priv: Ed25519PrivateKey) -> str:
    raw = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return _b64url(raw)


def get_or_create_keypair(agent_profile_id: str) -> tuple[str, bool]:
    """Return (public_key_b64u, already_existed). Idempotent per id."""
    if not isinstance(agent_profile_id, str) or not agent_profile_id:
        raise ValueError("agent_profile_id required")
    key_id = agent_profile_id.lower()
    path = _key_path(key_id)
    with _id_lock(key_id):
        if path.exists():
            priv = serialization.load_pem_private_key(path.read_bytes(), password=None)
            assert isinstance(priv, Ed25519PrivateKey)
            return _public_key_b64u(priv), True
        _ensure_secrets_dir()
        priv = Ed25519PrivateKey.generate()
        pem = priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        # Atomic write so a crash mid-write doesn't leave a half-PEM.
        tmp = path.with_suffix(".key.tmp")
        tmp.write_bytes(pem)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        return _public_key_b64u(priv), False


def _load_private_key(agent_profile_id: str) -> Ed25519PrivateKey:
    path = _key_path(agent_profile_id)
    if not path.exists():
        raise RuntimeError(f"keypair not provisioned for {agent_profile_id}")
    priv = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(priv, Ed25519PrivateKey):
        raise RuntimeError(f"unexpected key type for {agent_profile_id}")
    return priv


def sign_auth_header(*, agent_profile_id: str, method: str, url: str, scope: str) -> str:
    """Return `Bearer <jwt>` signing this exact request. ~50µs Ed25519."""
    if not (agent_profile_id and method and url and scope):
        raise ValueError("agent_profile_id, method, url, scope required")
    from urllib.parse import urlsplit
    parts = urlsplit(url)
    htu = f"{parts.scheme}://{parts.netloc}{parts.path}"
    htm = method.upper()
    now = int(time.time())
    kid = agent_profile_id.lower()
    header = {"alg": "EdDSA", "typ": "JWT", "kid": kid}
    payload = {
        "sub": kid,
        "iat": now,
        "exp": now + _TOKEN_LIFETIME_S,
        "jti": _b64url(secrets.token_bytes(16)),
        "htu": htu,
        "htm": htm,
        "scope": scope,
    }
    header_b64 = _b64url(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    payload_b64 = _b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    sig = _load_private_key(kid).sign(signing_input)
    return f"Bearer {header_b64}.{payload_b64}.{_b64url(sig)}"


def public_key_fingerprint(public_key_b64u: str) -> str:
    """Non-secret short ID for logs/UI."""
    return f"pop_{public_key_b64u[:12]}"
