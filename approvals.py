"""Tool-call approval gate for the Onepilot Hermes plugin.

Mirrors the OpenClaw v0.9.0 plugin-owned local-gate pattern but uses
Hermes's `pre_tool_call` plugin SDK seam (synchronous block via
``{"action": "block", "message": ...}`` return value, see
``hermes/hermes_cli/plugins.py:get_pre_tool_call_block_message``).

Why not Hermes's MCP EventBridge: an earlier v0.9.x attempt long-polled
``events_wait("approval_requested")`` for tool-call approvals, but
nothing in Hermes core *emits* approval_requested into EventBridge —
the agent loop fires `pre_tool_call` directly and respects the block
return value. So we own the gate here and skip the dead queue.

Threading model (the riskiest piece):
- ``register(ctx)`` runs on Hermes's main thread at plugin load time and
  hands the asyncio loop reference to the hook factory before starting
  the plugin's daemon thread.
- The ``pre_tool_call`` callback fires synchronously on the *agent
  thread* (whichever thread is running the model loop).
- The Realtime listener (in ``__init__.py``) runs on the plugin's
  asyncio loop in a separate daemon thread; it intercepts
  ``/approve <id> <decision>`` chat messages and calls ``apply_decision``.
- The hand-off uses ``threading.Event`` (stdlib OS primitive — works
  across all three threads). The hook calls ``event.wait(timeout)``,
  ``apply_decision`` calls ``event.set()`` from the asyncio thread.
- Sync-to-async broadcast uses ``asyncio.run_coroutine_threadsafe``
  bound to the captured loop reference, with a 3s timeout so a wedged
  loop can't stall the agent thread indefinitely.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

logger = logging.getLogger("hermes_plugins.onepilot.approvals")

# Flag file. Toggled via the wrapper API (`POST /onepilot/v1/approvals/config`)
# or the local CLI (``approvals_cli.py enable|disable``). The hook checks this
# on every fire, so flipping it doesn't require a plugin restart.
_FLAG_DIR = Path.home() / ".hermes-onepilot"
ENABLED_FLAG_FILE = _FLAG_DIR / "approvals.enabled"

# Tool-name allowlist for "this is an exec-shaped tool that should ask".
# Hermes's shell tool is named `terminal` (see hermes/agent/shell_hooks.py:34
# and hermes/agent/context_compressor.py:176). Mirrors OpenClaw's
# EXEC_TOOL_NAMES intent without depending on Hermes's allowlist.
EXEC_TOOL_NAMES: frozenset[str] = frozenset({"terminal"})

# 5 min — long enough for a human tap after iOS push, short enough that a
# dropped/idle agent context doesn't leave the gate hung. Mirror of OpenClaw's
# DEFAULT_TIMEOUT_MS (approvals-gate.js:38).
DEFAULT_TIMEOUT_S: float = 5 * 60


@dataclass
class _PendingEntry:
    approval_id: str
    event: threading.Event
    session_id: str
    tool_name: str
    created_at_ms: int
    decision: Optional[str] = None  # set by apply_decision before event.set()


_pending: dict[str, _PendingEntry] = {}
_pending_lock = threading.Lock()


# ---------------------------------------------------------------------------
# Flag file (CI-required symbols + wrapper-api backing)
# ---------------------------------------------------------------------------


def is_approvals_forwarding_enabled() -> bool:
    """True iff the user has flipped the toggle on (flag file present)."""
    try:
        return ENABLED_FLAG_FILE.exists()
    except OSError as exc:
        logger.warning("[approvals] flag file probe failed: %s — treating as disabled", exc)
        return False


def set_approvals_forwarding_enabled(enabled: bool) -> None:
    """Create or remove the flag file. Idempotent."""
    try:
        if enabled:
            _FLAG_DIR.mkdir(parents=True, exist_ok=True)
            ENABLED_FLAG_FILE.touch(exist_ok=True)
        else:
            try:
                ENABLED_FLAG_FILE.unlink()
            except FileNotFoundError:
                pass
    except OSError as exc:
        # Surface the error to the caller (CLI / wrapper-api) so the user
        # sees it rather than a silent toggle that didn't take effect.
        raise RuntimeError(f"failed to write approvals flag: {exc}") from exc


# ---------------------------------------------------------------------------
# Decision plumbing
# ---------------------------------------------------------------------------


def apply_decision(approval_id: str, decision: str) -> bool:
    """Resolve a pending approval. Returns True iff a matching entry was
    waiting (so the caller can post `⚠️ already resolved or expired` when
    False). Mirrors OpenClaw ``approvals-gate.js:applyDecision``."""
    with _pending_lock:
        entry = _pending.get(approval_id)
        if entry is None:
            return False
        entry.decision = decision
        entry.event.set()
    return True


def pending_snapshot() -> list[str]:
    """Diagnostic: prefixes of all pending approval ids. Used in log lines
    when ``/approve`` doesn't match anything pending so we can tell whether
    the gate timed out, was never registered, or had a different id."""
    with _pending_lock:
        return [str(k)[:8] for k in _pending.keys()]


def approvals_loop(*args: Any, **kwargs: Any) -> None:
    """DEPRECATED. v0.8.x of this plugin attempted to long-poll Hermes's
    MCP EventBridge ``events_wait`` queue for ``approval_requested`` events
    that Hermes core never actually emits. v0.9.0 owns the gate locally
    via ``pre_tool_call``, so this symbol is a no-op kept only to satisfy
    the existing CI symbol-grep contract. Will be dropped in a follow-up
    release once CI is updated.
    """
    logger.debug("[approvals] approvals_loop invoked (deprecated no-op in v0.9.0+)")


# ---------------------------------------------------------------------------
# Realtime broadcast helper (copy of `__init__.py:_broadcast` to avoid a
# circular import — `__init__.py` imports from this module).
# ---------------------------------------------------------------------------


def _channel_for_session(session_id: str) -> str:
    """Mirrors RealtimeMessageListener in iOS: ``messages_<UUID-prefix>``,
    uppercased without dashes. Case-sensitive on the Realtime side."""
    s = str(session_id).replace("-", "").upper()
    return f"messages_{s[:8]}"


async def _broadcast(
    config: dict[str, Any],
    session_id: str,
    event: str,
    payload: dict[str, Any],
) -> None:
    """Best-effort fire-and-forget broadcast on the iOS Realtime topic.
    Bounded 3s timeout — a wedged endpoint must not stall the gate."""
    import httpx  # local import; httpx is a Hermes runtime dep already

    url = f"{config['backendUrl']}/realtime/v1/api/broadcast"
    body = {
        "messages": [
            {
                "topic": _channel_for_session(session_id),
                "event": event,
                "payload": payload,
                "private": False,
            }
        ]
    }
    headers = {
        "Content-Type": "application/json",
        "apikey": config["publishableKey"],
        "Authorization": f"Bearer {config['publishableKey']}",
    }
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            await client.post(url, headers=headers, json=body)
    except Exception as exc:
        logger.debug("[approvals] broadcast %s failed: %s", event, exc)


# ---------------------------------------------------------------------------
# pre_tool_call hook factory
# ---------------------------------------------------------------------------


def _format_command(args: dict[str, Any]) -> tuple[str, list[str]]:
    """Pull the human-readable command + argv off Hermes's terminal tool
    args. Hermes's terminal tool typically has a single ``command`` string
    (see `hermes/agent/shell_hooks.py`); ``argv`` is provided as a fallback
    so the schema mirrors OpenClaw's ApprovalRequest."""
    cmd = args.get("command")
    if isinstance(cmd, str):
        return cmd, []
    argv = args.get("argv")
    if isinstance(argv, list):
        argv_str = [str(a) for a in argv]
        return " ".join(argv_str), argv_str
    return "", []


def register_pre_tool_call_hook(
    plugin_loop: asyncio.AbstractEventLoop,
    config: dict[str, Any],
    lookup_session_id: Callable[[], Optional[str]],
) -> Callable[..., Optional[dict[str, Any]]]:
    """Build a ``pre_tool_call`` callback closing over the plugin's
    asyncio loop, config, and session-id lookup. Caller passes the
    returned function to ``ctx.register_hook("pre_tool_call", ...)``.

    The callback is **synchronous** because Hermes invokes it via
    ``invoke_hook("pre_tool_call", ...)`` and inspects the return value
    directly (``hermes/hermes_cli/plugins.py:1071``). To do async work
    (broadcast, persist) we hand it off to ``plugin_loop`` via
    ``run_coroutine_threadsafe``. The hook then blocks on a
    ``threading.Event`` waiting for the user's decision, which arrives
    on the asyncio thread when the ``/approve`` interceptor in
    ``__init__.py`` calls :func:`apply_decision`.
    """
    agent_profile_id = str(config.get("agentProfileId") or "")

    def pre_tool_call_hook(
        *,
        tool_name: str,
        args: Optional[dict[str, Any]] = None,
        task_id: str = "",
        session_id: str = "",
        tool_call_id: str = "",
    ) -> Optional[dict[str, Any]]:
        # 1. Allowlist filter — only gate exec-shaped tools.
        if tool_name not in EXEC_TOOL_NAMES:
            return None

        # 2. Toggle check — re-read every call so flipping it doesn't
        # require a plugin restart.
        if not is_approvals_forwarding_enabled():
            return None

        # 3. Resolve the iOS Realtime topic (chat session_id). Without a
        # cached id the broadcast goes nowhere → the bubble never appears
        # → the hook would block until timeout. Fail open (let the tool
        # through) instead, mirroring OpenClaw's deadlock-avoidance at
        # approvals-gate.js:161-164. Diagnostic line tells the user how
        # to populate the cache (any iOS chat message will do).
        cached_session_id = lookup_session_id()
        if not cached_session_id:
            logger.info(
                "[approvals] no cached session_id — letting %s through to avoid deadlock "
                "(send any iOS message first to populate cache)",
                tool_name,
            )
            return None

        # 4. Mint an id, register the pending entry under lock.
        approval_id = str(uuid.uuid4())
        event = threading.Event()
        entry = _PendingEntry(
            approval_id=approval_id,
            event=event,
            session_id=cached_session_id,
            tool_name=tool_name,
            created_at_ms=int(time.time() * 1000),
        )
        with _pending_lock:
            _pending[approval_id] = entry

        command, argv = _format_command(args or {})
        cwd = (args or {}).get("cwd")
        payload = {
            "approval_id": approval_id,
            "framework": "hermes",
            "tool_name": tool_name,
            "command": command,
            "argv": argv,
            "cwd": cwd if isinstance(cwd, str) else None,
            "session_key": cached_session_id,
            "agent_id": agent_profile_id or None,
            "security": "medium",
            "expires_at_ms": int(time.time() * 1000 + DEFAULT_TIMEOUT_S * 1000),
            "allowed_decisions": ["allow-once", "allow-always", "deny"],
        }
        logger.info(
            "[approvals] approval_requested id=%s tool=%s cmd=%r",
            approval_id[:16],
            tool_name,
            command[:80],
        )

        # 5. Schedule the broadcast onto the plugin's asyncio loop.
        # Bounded result wait so a stuck loop can't hang the agent.
        try:
            fut = asyncio.run_coroutine_threadsafe(
                _broadcast(config, cached_session_id, "approval_requested", payload),
                plugin_loop,
            )
            fut.result(timeout=3.0)
        except Exception as exc:
            logger.warning(
                "[approvals] broadcast scheduling failed (%s) — letting tool through to avoid deadlock",
                exc,
            )
            with _pending_lock:
                _pending.pop(approval_id, None)
            return None

        # 6. Block the agent thread until apply_decision fires the event,
        # or until the timeout expires.
        matched = event.wait(DEFAULT_TIMEOUT_S)
        with _pending_lock:
            popped = _pending.pop(approval_id, None)
        decision = popped.decision if popped else None

        # 7. Fire-and-forget the resolved broadcast so iOS dismisses the
        # bubble regardless of outcome. Don't await — we already have the
        # decision; the bubble update is best-effort.
        try:
            resolved_payload = {
                "approval_id": approval_id,
                "decision": decision or "deny",
            }
            if not matched:
                resolved_payload["reason"] = "timeout"
            asyncio.run_coroutine_threadsafe(
                _broadcast(config, cached_session_id, "approval_resolved", resolved_payload),
                plugin_loop,
            )
        except Exception as exc:
            logger.debug("[approvals] resolved-broadcast schedule failed: %s", exc)

        # 8. Return the block directive Hermes expects.
        if not matched:
            logger.info("[approvals] approval timeout id=%s — denying", approval_id[:16])
            return {"action": "block", "message": "Approval timed out (5 min)"}
        if decision == "deny":
            logger.info("[approvals] approval denied id=%s", approval_id[:16])
            return {"action": "block", "message": "Denied by user"}
        logger.info(
            "[approvals] approval granted id=%s decision=%s",
            approval_id[:16],
            decision,
        )
        return None  # allow-once / allow-always proceed

    return pre_tool_call_hook
