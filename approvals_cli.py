#!/usr/bin/env python3
"""Approvals CLI for the Onepilot Hermes plugin.

Mirrors `bin/approvals-cli.js` from the OpenClaw plugin. Wraps the flag
file used by `approvals.py`. Three verbs:

  status   — print 'enabled' or 'disabled', exit 0 always.
  enable   — create the flag file, exit 0.
  disable  — remove the flag file, exit 0.

`status` MUST exit 0 even if the flag file is unreachable / Hermes core
is unimportable (the iOS adapter uses status-zero as the alive probe;
see `ci/plugin/onepilot-hermes-chat/test.sh:105`).
"""

from __future__ import annotations

import argparse
import os
import sys


def _import_approvals():
    # Local import so a broken `approvals` module surfaces as a runtime
    # error message rather than an import-time crash that prevents
    # `status` from exiting 0.
    here = os.path.dirname(os.path.abspath(__file__))
    if here not in sys.path:
        sys.path.insert(0, here)
    import approvals  # noqa: WPS433 — intentional local import
    return approvals


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="approvals_cli.py",
        description="Toggle the Onepilot approval-forwarding flag.",
    )
    sub = parser.add_subparsers(dest="verb", required=True)
    sub.add_parser("status", help="Print enabled/disabled and exit 0.")
    sub.add_parser("enable", help="Enable approval forwarding.")
    sub.add_parser("disable", help="Disable approval forwarding.")
    args = parser.parse_args()

    if args.verb == "status":
        try:
            mod = _import_approvals()
            sys.stdout.write(
                "enabled\n" if mod.is_approvals_forwarding_enabled() else "disabled\n"
            )
        except Exception as exc:
            # Don't exit non-zero — the iOS adapter probes this as a
            # liveness check. Surface the diagnostic on stderr.
            sys.stderr.write(f"status probe failed: {exc}\n")
            sys.stdout.write("disabled\n")
        return 0

    if args.verb == "enable":
        try:
            _import_approvals().set_approvals_forwarding_enabled(True)
        except Exception as exc:
            sys.stderr.write(f"enable failed: {exc}\n")
            return 1
        sys.stdout.write("approvals forwarding enabled\n")
        return 0

    # disable
    try:
        _import_approvals().set_approvals_forwarding_enabled(False)
    except Exception as exc:
        sys.stderr.write(f"disable failed: {exc}\n")
        return 1
    sys.stdout.write("approvals forwarding disabled\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
