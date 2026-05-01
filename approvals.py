"""Approval forwarding bridge.

Hermes' EventBridge (hermes/mcp_serve.py:185) maintains an in-memory queue of
events including ``approval_requested`` and ``approval_resolved``. We import
the bridge module and subscribe via ``events_wait``; matching events get
re-broadcast on the iOS Supabase Realtime channel so the app can render
actionable approval bubbles. Decisions come back via ``submit_decision``,
which calls upstream ``permissions_respond``.

Kept byte-for-byte schema-aligned with the OpenClaw plugin's approvals.js so
iOS has one decoder.
"""
from __future__ import annotations

import asyncio
import logging
import os
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

ENABLED_FLAG_FILE = Path.home() / ".hermes" / "onepilot-approvals.enabled"


def is_approvals_forwarding_enabled() -> bool:
    """Default off. Flipped via ``approvals_cli enable`` / ``disable``,
    invoked from the iOS adapter (HermesAdapter.setApprovalsEnabled)."""
    return ENABLED_FLAG_FILE.exists()


def set_approvals_forwarding_enabled(enabled: bool) -> None:
    ENABLED_FLAG_FILE.parent.mkdir(parents=True, exist_ok=True)
    if enabled:
        ENABLED_FLAG_FILE.write_text(str(int(asyncio.get_event_loop().time() * 1000)))
    else:
        try:
            ENABLED_FLAG_FILE.unlink()
        except FileNotFoundError:
            pass


def _normalize_request(data: dict[str, Any]) -> dict[str, Any]:
    """Match the iOS schema. Mirror of approvals.js#normalizeRequest."""
    argv = data.get("argv") or []
    if not isinstance(argv, list):
        argv = []
    return {
        "approval_id": str(data.get("id") or data.get("approval_id") or ""),
        "framework": "hermes",
        "tool_name": data.get("tool_name") or data.get("tool") or "tool",
        "command": data.get("command") or (" ".join(map(str, argv)) if argv else ""),
        "argv": argv,
        "cwd": data.get("cwd"),
        "session_key": data.get("session_key"),
        "agent_id": data.get("agent_id"),
        "security": data.get("security") or data.get("ask_policy") or "medium",
        "expires_at_ms": data.get("expires_at_ms"),
    }


def _normalize_resolved(data: dict[str, Any]) -> dict[str, Any]:
    return {
        "approval_id": str(data.get("id") or data.get("approval_id") or ""),
        "framework": "hermes",
        "decision": data.get("decision") or "deny",
        "decided_at_ms": data.get("decided_at_ms"),
        "decided_by": data.get("decided_by"),
    }


async def approvals_loop(config: dict[str, Any], broadcast_fn) -> None:
    """Long-running task. Polls Hermes' EventBridge for approval events and
    broadcasts to the iOS realtime channel when the user has opted in. Backs
    off on EventBridge import failure so older Hermes versions still load
    the plugin without crashing.

    ``broadcast_fn`` is ``_broadcast(config, session_id, event, payload)``
    from the main plugin module — passed in to avoid a circular import.
    """
    try:
        # Lazy import — only available in Hermes runtimes that ship mcp_serve.
        # Older Hermes builds load the rest of the plugin fine; approvals
        # forwarding just stays inert.
        from hermes.mcp_serve import EventBridge  # type: ignore
    except Exception as exc:
        logger.info("[onepilot] approvals: EventBridge unavailable (%s) — feature inert", exc)
        return

    bridge = EventBridge()
    bridge.start()
    cursor = 0
    logger.info("[onepilot] approvals loop started (default OFF until enable)")

    try:
        while True:
            if not is_approvals_forwarding_enabled():
                await asyncio.sleep(2.0)
                continue
            try:
                # poll_events is sync; run in default executor to avoid
                # blocking the asyncio loop.
                result = await asyncio.get_event_loop().run_in_executor(
                    None,
                    lambda: bridge.poll_events(after_cursor=cursor, limit=20),
                )
            except Exception as exc:
                logger.warning("[onepilot] approvals poll error: %s", exc)
                await asyncio.sleep(2.0)
                continue

            events = result.get("events", []) if isinstance(result, dict) else []
            cursor = max(
                [cursor] + [int(e.get("cursor") or 0) for e in events if isinstance(e, dict)]
            )

            for ev in events:
                if not isinstance(ev, dict):
                    continue
                t = ev.get("type")
                if t not in ("approval_requested", "approval_resolved"):
                    continue
                data = ev.get("data") or {}
                session_id = ev.get("session_key") or data.get("session_key") or "main"
                payload = (
                    _normalize_resolved(data)
                    if t == "approval_resolved"
                    else _normalize_request(data)
                )
                try:
                    await broadcast_fn(config, session_id, t, payload)
                except Exception as exc:
                    logger.debug("[onepilot] approvals broadcast %s failed: %s", t, exc)

            if not events:
                await asyncio.sleep(0.5)
    finally:
        try:
            bridge.stop()
        except Exception:
            pass


# Decisions don't flow through this module any more — see approvals_cli.py
# header. iOS sends `/approve <id> <decision>` as a regular chat message
# and the host's auto-reply pipeline picks it up.
