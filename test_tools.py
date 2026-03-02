#!/usr/bin/env python3
"""
Interactive Test Runner for the Trellix HX MCP Server
=====================================================
Exercises every MCP tool against your real HX appliance and prints results
in a colourful, easy-to-read format.

Prerequisites:
    1. Fill in your .env with real credentials
    2. Run:  python test_tools.py       (all read-only tools)
             python test_tools.py -i    (interactive pick-and-run)
"""

from __future__ import annotations

import argparse
import json
import sys
import os
import traceback

sys.path.insert(0, os.path.dirname(__file__))

import server  # noqa: E402

# ---------------------------------------------------------------------------
# Formatting
# ---------------------------------------------------------------------------
GREEN = "\033[92m"
RED = "\033[91m"
CYAN = "\033[96m"
YELLOW = "\033[93m"
MAGENTA = "\033[95m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"


# ---------------------------------------------------------------------------
# Pre-flight check
# ---------------------------------------------------------------------------
def _preflight():
    missing = []
    for var in ("HX_HOST", "HX_USER", "HX_PASS"):
        val = os.getenv(var, "")
        if not val or "example.com" in val or val.startswith("your_"):
            missing.append(var)
    if missing:
        print(f"{RED}{'='*60}")
        print(f"  ⚠  Missing or placeholder credentials in .env:")
        for m in missing:
            print(f"     • {m}")
        print(f"\n  Please edit .env with your real HX appliance details.")
        print(f"{'='*60}{RESET}\n")
        sys.exit(1)


# ---------------------------------------------------------------------------
# Tool registry
# ---------------------------------------------------------------------------
TOOLS: list[tuple[str, callable, dict]] = [
    # ── 1. System & Info ──
    ("get_version",               server.get_version,               {}),
    ("get_appliance_stats",       server.get_appliance_stats,       {}),
    # ── 2. Hosts & Groups ──
    ("resolve_hostname",          server.resolve_hostname,          {"hostname": "WORKSTATION-042"}),
    ("list_hosts",                server.list_hosts,                {"limit": 5}),
    ("get_host_details*",         server.get_host_details,          {"host_id": "__ASK__"}),
    ("list_host_sets",            server.list_host_sets,            {"limit": 5}),
    ("get_host_set_members",      server.get_host_set_members,      {"host_set_id": 1323, "limit": 3}),
    # ── 3. Alerts & Threats ──
    ("list_alerts",               server.list_alerts,               {"limit": 5}),
    ("get_alert_details*",        server.get_alert_details,         {"alert_id": "__ASK__"}),
    ("list_source_alerts (IOC)",  server.list_source_alerts,        {"source": "IOC", "limit": 5}),
    ("list_quarantined_files",    server.list_quarantined_files,    {"limit": 5}),
    ("list_containment_states",   server.list_containment_states,   {"limit": 5}),
    # ── 4. Intelligence & Indicators ──
    ("list_indicators (all)",     server.list_indicators,           {"limit": 5}),
    ("list_indicators (Custom)",  server.list_indicators,           {"category": "Custom", "limit": 5}),
    ("list_indicators (FireEye)", server.list_indicators,           {"category": "FireEye", "limit": 5}),
    ("get_indicator_details*",    server.get_indicator_details,     {"category": "__ASK__", "indicator_name": "__ASK__"}),
    ("list_indicator_categories", server.list_indicator_categories, {"limit": 5}),
    ("list_conditions",           server.list_conditions,           {"limit": 5}),
    # ── 5. Acquisitions & Triages ──
    ("list_file_acquisitions",    server.list_file_acquisitions,    {"limit": 5}),
    ("download_file_acquisition*", server.download_file_acquisition, {"acquisition_id": "__ASK__"}),
    ("list_triages",              server.list_triages,              {"limit": 5}),
    ("list_bulk_acquisitions",    server.list_bulk_acquisitions,    {"limit": 5}),
    # ── 6. Search & Policies ──
    ("list_searches",             server.list_searches,             {"limit": 5}),
    ("get_search_counts",         server.get_search_counts,         {}),
    ("list_policies",             server.list_policies,             {"limit": 5}),
    ("list_host_policies_channels", server.list_host_policies_channels, {"limit": 5}),
    # ── 7. Scripts ──
    ("list_scripts",              server.list_scripts,              {"limit": 5}),
    ("download_scripts_zip",      server.download_scripts_zip,      {}),
]

WRITE_TOOLS: list[tuple[str, callable, dict]] = [
    ("update_static_host_set*",   server.update_static_host_set,    {"host_set_id": "__ASK__", "add_ids": "__ASK__"}),
    ("manage_containment*",       server.manage_containment,        {"host_id": "__ASK__", "action": "contain"}),
    ("create_file_acquisition*",  server.create_file_acquisition,   {"agent_id": "__ASK__", "path": "__ASK__"}),
    ("trigger_triage*",           server.trigger_triage,            {"agent_id": "__ASK__"}),
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _pretty(obj, max_lines: int = 15) -> str:
    if isinstance(obj, str):
        return f"  {obj}"
    text = json.dumps(obj, indent=2, default=str)
    lines = text.splitlines()
    if len(lines) > max_lines:
        lines = lines[:max_lines] + [f"{DIM}  … ({len(lines) - max_lines} more lines){RESET}"]
    return "\n".join(f"  {l}" for l in lines)


def _resolve_args(name: str, kwargs: dict) -> dict | None:
    resolved = {}
    for key, val in kwargs.items():
        if val == "__ASK__":
            user_val = input(f"  {YELLOW}Enter {key} for {name}: {RESET}").strip()
            if not user_val:
                print(f"  {DIM}Skipped (no value provided){RESET}")
                return None
            try:
                resolved[key] = int(user_val)
            except ValueError:
                if "," in user_val:
                    resolved[key] = [v.strip() for v in user_val.split(",")]
                else:
                    resolved[key] = user_val
        else:
            resolved[key] = val
    return resolved


def run_tool(name: str, fn: callable, kwargs: dict, interactive: bool = False) -> bool:
    print(f"\n{BOLD}{CYAN}┌─ {name}{RESET}")

    if "__ASK__" in kwargs.values():
        if not interactive:
            print(f"  {DIM}⏭  Skipped (requires input — use -i mode){RESET}")
            return True
        kwargs = _resolve_args(name, kwargs)
        if kwargs is None:
            return True

    print(f"  {DIM}args: {kwargs}{RESET}")
    try:
        result = fn(**kwargs)
        print(f"  {GREEN}✅ SUCCESS{RESET}")
        print(_pretty(result))
        return True
    except Exception as exc:
        print(f"  {RED}❌ FAILED: {exc}{RESET}")
        if interactive:
            traceback.print_exc()
        return False


# ---------------------------------------------------------------------------
# Modes
# ---------------------------------------------------------------------------
def run_all():
    passed = failed = skipped = 0
    print(f"\n{BOLD}{'='*60}")
    print(f"  Trellix HX MCP – Full Test Suite  ({len(TOOLS)} tools)")
    print(f"{'='*60}{RESET}")
    print(f"  {DIM}Target: {server.HX_HOST}{RESET}")

    for name, fn, kwargs in TOOLS:
        if "__ASK__" in kwargs.values():
            print(f"\n{BOLD}{CYAN}┌─ {name}{RESET}")
            print(f"  {DIM}⏭  Skipped (requires input — use -i mode){RESET}")
            skipped += 1
            continue
        if run_tool(name, fn, kwargs):
            passed += 1
        else:
            failed += 1

    print(f"\n{BOLD}{'='*60}")
    colour = GREEN if failed == 0 else YELLOW
    print(f"  {colour}Results: {passed} passed, {failed} failed, {skipped} skipped{RESET}")
    print(f"{'='*60}\n")
    return failed == 0


def run_interactive():
    all_tools = TOOLS + WRITE_TOOLS

    print(f"\n{BOLD}{'='*60}")
    print(f"  Trellix HX MCP – Interactive Mode")
    print(f"{'='*60}{RESET}")
    print(f"  {DIM}Target: {server.HX_HOST}{RESET}")
    print(f"  {DIM}Tools marked with * will ask for input values{RESET}")
    print(f"  {MAGENTA}⚠  Write tools at the bottom require confirmation{RESET}")

    while True:
        print(f"\n{BOLD}Read-only tools:{RESET}")
        for i, (name, _, _) in enumerate(TOOLS, 1):
            print(f"  {CYAN}{i:3d}{RESET}. {name}")

        print(f"\n{BOLD}{MAGENTA}Write / destructive tools:{RESET}")
        base = len(TOOLS)
        for i, (name, _, _) in enumerate(WRITE_TOOLS, base + 1):
            print(f"  {MAGENTA}{i:3d}{RESET}. {name}")

        print(f"\n  {CYAN}  a{RESET}. Run ALL read-only tools")
        print(f"  {CYAN}  q{RESET}. Quit\n")

        choice = input(f"{BOLD}Pick a tool (number / a / q): {RESET}").strip().lower()

        if choice == "q":
            print("👋 Bye!")
            break
        if choice == "a":
            run_all()
            continue
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(all_tools):
                name, fn, kwargs = all_tools[idx]
                if idx >= len(TOOLS):
                    confirm = input(f"  {MAGENTA}⚠  This is a WRITE operation. Proceed? (y/N): {RESET}").strip().lower()
                    if confirm != "y":
                        print(f"  {DIM}Cancelled.{RESET}")
                        continue
                run_tool(name, fn, dict(kwargs), interactive=True)
            else:
                print(f"{RED}Invalid number.{RESET}")
        except ValueError:
            print(f"{RED}Invalid input.{RESET}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Test the Trellix HX MCP tools against your real appliance"
    )
    parser.add_argument(
        "-i", "--interactive",
        action="store_true",
        help="Interactive mode: pick tools, enter IDs, test write operations",
    )
    args = parser.parse_args()

    _preflight()

    if args.interactive:
        run_interactive()
    else:
        success = run_all()
        sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
