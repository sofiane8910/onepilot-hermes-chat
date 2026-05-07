# Hermes upstream requests

## 1. `cron.scheduler.register_delivery_platform(name, fn)`

**Status:** required for v+1 plugin to drop its legacy monkey-patch fallback.

`onepilot-platform` registers `onepilot` as a cron delivery channel. Today it does this by mutating two private symbols on `cron.scheduler`:

- `_KNOWN_DELIVERY_PLATFORMS` (frozenset of legal `--deliver` prefixes)
- `_deliver_result` (the dispatch function — replaced with a wrapper that handles `onepilot:` and forwards everything else)

This is brittle — Hermes can rename either symbol with no warning — and it's the largest single tampering surface in the plugin (see `SECURITY_AUDIT.md` D2 + `__init__.py:_install_cron_channel`).

**Proposed public API:**

```python
# in cron/scheduler.py
def register_delivery_platform(
    name: str,
    deliver_fn: Callable[[dict, str, Any | None, Any | None], str | None],
) -> None:
    """Register a `<name>:` delivery channel.

    `deliver_fn(job, content, adapters=None, loop=None) -> error_str | None`
    is invoked synchronously when a cron job's `deliver` field includes
    `<name>` or `<name>:<key>`. Returning a non-empty string is logged as a
    failure; returning None signals success.
    """
```

Once available, `onepilot-platform` calls `register_delivery_platform("onepilot", deliver_fn)` and removes both the `_KNOWN_DELIVERY_PLATFORMS` mutation and the `_deliver_result` patch. The plugin already prefers this path (see `_install_cron_channel`); the fallback is gated on its absence and gated again by config `strict_no_patch: true`.

**Migration path on the plugin side:**

- Plugin v0.4.0 (this release): prefer public API, fall back with a deprecation warning. `strict_no_patch=true` opts out of fallback.
- Plugin v+2: remove the fallback entirely once min-supported Hermes exposes the public API.

## 2. (future) per-plugin scoped auth tokens

`SECURITY_AUDIT.md` D3 — request `api.scopedAuthToken` so plugins can self-call `/v1/chat/completions` without sharing the gateway-wide token in process memory. Not needed for v+1; documented here so it lands on the same upstream issue tracker.
