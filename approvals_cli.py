#!/usr/bin/env python3
"""CLI shim invoked by the iOS adapter (HermesAdapter) over SSH for the
on/off toggle. Decisions DON'T go through here — iOS sends
`/approve <id> <decision>` as a regular chat message and the
auto-reply pipeline handles it (mirrors the OpenClaw plugin).

Installed by the iOS deploy step to
~/.hermes/profiles/<agentId>/plugins/onepilot/ and invoked there as a
standalone script (no package install)."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from approvals import (  # noqa: E402
    is_approvals_forwarding_enabled,
    set_approvals_forwarding_enabled,
)


def fail(msg: str, code: int = 1) -> None:
    sys.stderr.write(f"approvals_cli: {msg}\n")
    sys.exit(code)


def main() -> None:
    args = sys.argv[1:]
    if not args:
        fail(f"usage: {sys.argv[0]} <enable|disable|status>")
    verb = args[0]

    if verb == "enable":
        set_approvals_forwarding_enabled(True)
        sys.stdout.write("approvals forwarding enabled\n")
    elif verb == "disable":
        set_approvals_forwarding_enabled(False)
        sys.stdout.write("approvals forwarding disabled\n")
    elif verb == "status":
        sys.stdout.write("enabled\n" if is_approvals_forwarding_enabled() else "disabled\n")
    else:
        fail(f'unknown verb "{verb}"')


if __name__ == "__main__":
    main()
