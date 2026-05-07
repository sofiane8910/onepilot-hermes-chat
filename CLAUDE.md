# CLAUDE.md — internal best practices (not committed)

Keep two rules in mind on every change to this plugin. They both exist because of one structural fact: **iOS ships through App Store review (1–2 weeks); this plugin ships through `plugin_manifest` in 5 minutes.** Don't waste that asymmetry.

## 1. Plugin is the bridge — not the iOS adapter

Anything Hermes-specific lives **here**, not in the iOS Swift adapter.

- ✅ `hermes profile create`, `hermes -p <id> gateway run`, `hermes skills install`, flag spelling, config-yaml paths, cron-channel registration, plugin `config.json` schema → all of that lives inside the plugin (in `__init__.py` and `wrapper_api.py`).
- ❌ The iOS adapter calling `hermes <verb>` directly, hardcoding `--profile`, parsing `hermes auth list` output, writing the plugin's `config.json` itself. That's the trap that costs us a 1–2 week App Store cycle every time upstream renames a flag or moves a private symbol.

When Hermes upstream changes something:
1. Update this plugin to absorb the change. Bump `pyproject.toml` AND `plugin.yaml` (both — they must agree).
2. Cut a release (see README "Cutting a new version").
3. UPDATE `plugin_manifest` channel='hermes-stable' — the iOS app picks up the new tarball on the next `ensureSyncSetup`. Zero iOS rebuild.

Special case for Hermes: monkey-patching framework internals (e.g. `cron.scheduler._deliver_result`) is a **last resort**. Prefer a public API; if Hermes doesn't expose one, file the request in `UPSTREAM.md` and gate the patch path behind a `strict_no_patch: true` config knob for security-conscious deployments. The current cron-channel install uses this dual-path pattern — keep it that way.

The iOS app should only know:
- The Supabase manifest query keys (`channel="hermes-stable"`).
- The wrapper API surface (`/onepilot/v1/health|configure|account/rotate|account/revoke|plugin/uninstall`).
- The shape of the install script (curl + sha256 + tar -xzf, no register step — Hermes auto-discovers from `<baseDir>/plugins/<name>/`).

If you're tempted to add a new `executeCommand("hermes …")` call site to `HermesAdapter.swift`, **add a new wrapper endpoint here instead** and call that.

## 2. Security first — no path from "user edited the plugin" to "did something the plugin shouldn't"

Threat model: a leaked agent key (`oak_*`) or a tampered plugin running on a user's host must not be able to read or modify data outside the bound `(user_id, agent_profile_id)` pair.

Hard invariants:

- Every `/onepilot/v1/*` endpoint requires `Authorization: Bearer <agentKey>`. No public endpoints, no unauth probes.
- Bind on `127.0.0.1` only. Never `0.0.0.0` or any external interface — SSH tunnel is the only allowed transport boundary.
- Never accept a body field for `userId` or `agentProfileId` that overrides the auth-resolved binding. Server-side enforcement on every edge function (`mint-agent-key`, `agent-message-ingest`, `agent-stream-token`, `agent-message-history`, `revoke-agent-key`); see each function's `SCOPE.md` in the iOS app repo (`supabase/functions/<fn>/SCOPE.md`).
- Don't import new modules without thinking. `subprocess`, `eval`, `exec`, dynamic `__import__`, write-mode `open` outside the plugin dir — every new one of those is a tampering surface. The plugin runs in the Hermes gateway's asyncio event loop, so anything we import has full visibility into chat frames, tokens, and other plugins' state.
- Don't log full bearer tokens, user JWTs, or PII. Prefix-only (first 8 chars) for diagnostics.
- Don't write internal vendor names or backend project IDs into plugin source — this repo is public, vendor-neutral phrasing only. CI gates this in `ci/plugin/hermes-platform/snapshot-diff.sh` (recently retired but principle stands).

When a user fork-mods this plugin to behave differently — that's their host, their problem. But:
- **Their leaked agent key still can't reach another user's data**, because RLS + edge-function authz pin the bindings server-side. That's the line that must hold.
- See the iOS app repo's `docs/security/rls-agent-key.md` for the per-table RLS audit and `SECURITY_AUDIT.md` for deferred findings (assistant-reply forgery, peer-plugin sandbox gap, gateway-token shared memory). Don't introduce a fourth.

## What "good" looks like in a PR review

- New feature in iOS chat / debug surface? It should resolve to a new `/onepilot/v1/*` endpoint here, not a new `executeCommand("hermes …")` in Swift.
- New backend write path? Updated `SCOPE.md` for the edge function. Cross-tenancy test case added.
- New module import? Justified in the commit message; preferably a stdlib or already-present dep (`httpx`, `websockets`, `cron.scheduler`).
- Touching cron internals? Goes through `register_delivery_platform()` if available; falls back to the patch path with a deprecation warning, gated by `strict_no_patch`. Never patch silently.
- New release? Six-step runbook from README followed end-to-end. **Re-fetch sha256 after publish** (the documented footgun — GitHub repacks).
