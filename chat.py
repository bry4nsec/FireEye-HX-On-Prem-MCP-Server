#!/usr/bin/env python3
"""
Trellix HX – Interactive LLM Chat
==================================
An interactive terminal chat that uses GPT with function calling to query
your real HX appliance via the MCP tools.

Usage:
    python chat.py

Environment (via .env):
    HX_HOST, HX_USER, HX_PASS  – HX appliance credentials
    LLM_API_KEY                 – VortexAI / Azure OpenAI API key
    LLM_ENDPOINT                – (optional) override base URL
    LLM_MODEL                   – (optional) override model name
"""

from __future__ import annotations

import json
import os
import sys
import inspect

sys.path.insert(0, os.path.dirname(__file__))

from dotenv import load_dotenv
from openai import OpenAI

import server  # our MCP server module

load_dotenv()

# ---------------------------------------------------------------------------
# LLM client setup
# ---------------------------------------------------------------------------
LLM_ENDPOINT = os.getenv(
    "LLM_ENDPOINT",
    "https://api.openai.com/v1",
)
LLM_MODEL = os.getenv("LLM_MODEL", "gpt-5.2")
LLM_API_KEY = os.getenv("LLM_API_KEY", "")

if not LLM_API_KEY:
    print("\033[91m⚠  LLM_API_KEY not set in .env — cannot start chat.\033[0m")
    sys.exit(1)

client = OpenAI(
    base_url=LLM_ENDPOINT,
    api_key=LLM_API_KEY,
)

# ---------------------------------------------------------------------------
# Map MCP tool functions → OpenAI function-calling schema
# ---------------------------------------------------------------------------
TOOL_FUNCTIONS: dict[str, callable] = {
    # System
    "get_version": server.get_version,
    "get_appliance_stats": server.get_appliance_stats,
    # Hosts
    "resolve_hostname": server.resolve_hostname,
    "list_hosts": server.list_hosts,
    "get_host_details": server.get_host_details,
    "list_host_sets": server.list_host_sets,
    "get_host_set_members": server.get_host_set_members,
    "update_static_host_set": server.update_static_host_set,
    # Alerts
    "list_alerts": server.list_alerts,
    "get_alert_details": server.get_alert_details,
    "list_source_alerts": server.list_source_alerts,
    "list_quarantined_files": server.list_quarantined_files,
    "list_containment_states": server.list_containment_states,
    "manage_containment": server.manage_containment,
    # Intelligence
    "list_indicators": server.list_indicators,
    "get_indicator_details": server.get_indicator_details,
    "list_indicator_categories": server.list_indicator_categories,
    "list_conditions": server.list_conditions,
    # Acquisitions
    "list_file_acquisitions": server.list_file_acquisitions,
    "create_file_acquisition": server.create_file_acquisition,
    "download_file_acquisition": server.download_file_acquisition,
    "list_triages": server.list_triages,
    "trigger_triage": server.trigger_triage,
    "list_bulk_acquisitions": server.list_bulk_acquisitions,
    # Search & Policies
    "list_searches": server.list_searches,
    "get_search_counts": server.get_search_counts,
    "list_policies": server.list_policies,
    "list_host_policies_channels": server.list_host_policies_channels,
    # Scripts
    "list_scripts": server.list_scripts,
    "download_scripts_zip": server.download_scripts_zip,
}


def _python_type_to_json(annotation) -> dict:
    """Convert a Python type hint to a JSON Schema type."""
    if annotation in (int,):
        return {"type": "integer"}
    if annotation in (str,):
        return {"type": "string"}
    if annotation in (bool,):
        return {"type": "boolean"}
    if annotation in (float,):
        return {"type": "number"}
    origin = getattr(annotation, "__origin__", None)
    if origin is list:
        return {"type": "array", "items": {"type": "string"}}
    # union types (Optional)
    args = getattr(annotation, "__args__", None)
    if args:
        non_none = [a for a in args if a is not type(None)]
        if non_none:
            return _python_type_to_json(non_none[0])
    return {"type": "string"}


def _build_tool_schemas() -> list[dict]:
    """Auto-generate OpenAI function schemas from our server functions."""
    schemas = []
    for name, fn in TOOL_FUNCTIONS.items():
        sig = inspect.signature(fn)
        doc = inspect.getdoc(fn) or ""

        # Build parameters
        properties = {}
        required = []
        for pname, param in sig.parameters.items():
            ann = param.annotation if param.annotation != inspect.Parameter.empty else str
            prop = _python_type_to_json(ann)
            if param.default != inspect.Parameter.empty:
                prop["default"] = param.default
            else:
                required.append(pname)
            properties[pname] = prop

        schema = {
            "type": "function",
            "function": {
                "name": name,
                "description": doc[:500],
                "parameters": {
                    "type": "object",
                    "properties": properties,
                    "required": required,
                },
            },
        }
        schemas.append(schema)
    return schemas


TOOL_SCHEMAS = _build_tool_schemas()

# ---------------------------------------------------------------------------
# System prompt
# ---------------------------------------------------------------------------
SYSTEM_PROMPT = """You are an expert Trellix HX Security Analyst assistant.

You have access to a live Trellix (FireEye) HX on-premises appliance and can query it using the tools provided. Use these tools to help the user investigate alerts, search for indicators, inspect hosts, manage containment, acquire forensic evidence, and more.

Guidelines:
- ALWAYS use resolve_hostname first to convert a hostname to an agent_id before calling host-scoped tools.
- The host_id / agent_id parameters always need the agent _id (e.g. "t4h86qYY1H1fJE09PmgcKK"), NOT the hostname.
- Use get_alert_details and get_indicator_details to drill into specific items.
- For containment and triage actions, always confirm with the user before proceeding.
- Present data in a clear, summarized format — don't dump raw JSON unless asked.
- When listing items, mention the total count and show key fields.
- Use your security expertise to interpret the data and provide actionable insights.
"""

# ---------------------------------------------------------------------------
# Formatting
# ---------------------------------------------------------------------------
GREEN = "\033[92m"
CYAN = "\033[96m"
YELLOW = "\033[93m"
MAGENTA = "\033[95m"
DIM = "\033[2m"
BOLD = "\033[1m"
RESET = "\033[0m"


# ---------------------------------------------------------------------------
# Chat loop
# ---------------------------------------------------------------------------
def execute_tool_call(name: str, arguments: dict) -> str:
    """Execute a tool and return the result as a string."""
    fn = TOOL_FUNCTIONS.get(name)
    if not fn:
        return json.dumps({"error": f"Unknown tool: {name}"})
    try:
        result = fn(**arguments)
        return json.dumps(result, default=str)
    except Exception as exc:
        return json.dumps({"error": str(exc)})


def chat():
    """Run the interactive chat loop."""
    messages = [{"role": "system", "content": SYSTEM_PROMPT}]

    print(f"""
{BOLD}╔══════════════════════════════════════════════════════════╗
║  {CYAN}Trellix HX – AI Security Analyst{RESET}{BOLD}                        ║
║  Powered by {MAGENTA}{LLM_MODEL}{RESET}{BOLD} + MCP Tools                         ║
╠══════════════════════════════════════════════════════════╣
║  {DIM}Target: {server.HX_HOST}{RESET}{BOLD}                                  ║
║  {DIM}Tools:  {len(TOOL_FUNCTIONS)} available{RESET}{BOLD}                                 ║
║  {DIM}Type 'quit' or 'exit' to leave{RESET}{BOLD}                           ║
╚══════════════════════════════════════════════════════════╝
{RESET}""")

    while True:
        try:
            user_input = input(f"{BOLD}{GREEN}You ▸ {RESET}").strip()
        except (KeyboardInterrupt, EOFError):
            print(f"\n{DIM}👋 Bye!{RESET}")
            break

        if not user_input:
            continue
        if user_input.lower() in ("quit", "exit", "q"):
            print(f"{DIM}👋 Bye!{RESET}")
            break

        messages.append({"role": "user", "content": user_input})

        # LLM loop (may need multiple rounds for tool calls)
        while True:
            try:
                response = client.chat.completions.create(
                    model=LLM_MODEL,
                    messages=messages,
                    tools=TOOL_SCHEMAS,
                    tool_choice="auto",
                    temperature=0.3,
                )
            except Exception as exc:
                print(f"\n{YELLOW}⚠ LLM error: {exc}{RESET}\n")
                messages.pop()  # remove failed user message
                break

            choice = response.choices[0]
            msg = choice.message

            # If the LLM wants to call tools
            if msg.tool_calls:
                messages.append(msg)
                for tc in msg.tool_calls:
                    fn_name = tc.function.name
                    try:
                        fn_args = json.loads(tc.function.arguments)
                    except json.JSONDecodeError:
                        fn_args = {}

                    print(f"  {DIM}🔧 Calling {CYAN}{fn_name}{RESET}{DIM}({json.dumps(fn_args, default=str)}){RESET}")

                    result_str = execute_tool_call(fn_name, fn_args)

                    messages.append({
                        "role": "tool",
                        "tool_call_id": tc.id,
                        "content": result_str,
                    })
                # Continue the loop so the LLM can process the tool results
                continue

            # Final text response
            assistant_text = msg.content or ""
            messages.append({"role": "assistant", "content": assistant_text})
            print(f"\n{BOLD}{MAGENTA}HX Analyst ▸{RESET} {assistant_text}\n")
            break


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    chat()
