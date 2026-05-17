"""Shared safety primitives used by every dynamic detector.

Dynamic detectors actually invoke tools on the target server, so a few
guard-rails are non-negotiable:

1. Tool classification        — never call a destructive tool.
2. Safe-input generation      — produce minimal valid arguments from a schema.
3. Probe injection            — swap one argument for a detector payload.
4. Response text extraction   — pull text out of a CallToolResult.
5. Rate-limited tool call     — bounded latency + courtesy delay.

Every dynamic detector composes these primitives instead of touching
session.call_tool() directly.
"""
import asyncio
from typing import Any

from mcp import ClientSession
from mcp.types import CallToolResult

from .models import ToolInfo


# --- 1. Tool classification -------------------------------------------------

_DEFAULT_TIMEOUT_SEC = 10.0

DESTRUCTIVE_KEYWORDS: tuple[str, ...] = (
    "delete", "remove", "drop", "destroy", "purge", "truncate",
    "send", "post", "publish", "broadcast", "tweet", "notify",
    "write", "update", "modify", "patch", "put", "insert",
    "create", "execute", "run", "eval", "exec",
    "transfer", "pay", "purchase", "checkout", "charge",
    "deploy", "restart", "shutdown", "kill", "terminate",
)


def classify_tool(tool: ToolInfo) -> str:
    """Return 'destructive' if any keyword matches name/description, else 'safe'.

    Conservative on purpose: a read-only tool like read_deleted_items will be
    flagged destructive because of the word 'delete'. Skipping a safe tool is
    cheaper than accidentally invoking a destructive one.
    """
    haystack = (tool.name + " " + (tool.description or "")).lower()
    for kw in DESTRUCTIVE_KEYWORDS:
        if kw in haystack:
            return "destructive"
    return "safe"


# --- 2. Safe-input generation ----------------------------------------------

_TYPE_DEFAULTS: dict[str, Any] = {
    "string": "test",
    "integer": 1,
    "number": 1.0,
    "boolean": True,
    "array": [],
    "object": {},
    "null": None,
}


def _value_for(pdef: dict[str, Any], depth: int = 0) -> Any:
    if "default" in pdef:
        return pdef["default"]
    enum = pdef.get("enum")
    if enum:
        return enum[0]
    ptype = pdef.get("type", "string")
    if ptype == "object" and depth < 1:
        nested = pdef.get("properties", {})
        return {
            k: _value_for(v, depth=depth + 1)
            for k, v in nested.items()
            if isinstance(v, dict)
        }
    return _TYPE_DEFAULTS.get(ptype, "test")


def generate_safe_inputs(tool: ToolInfo) -> dict[str, Any]:
    """Generate minimal valid arguments for *tool* from its input schema.

    Includes only the properties listed in `required`; if no required array
    is declared, includes all properties (some servers reject partial calls
    even on optional fields).
    """
    schema = tool.input_schema or {}
    props = schema.get("properties", {}) if isinstance(schema, dict) else {}
    required = schema.get("required") if isinstance(schema, dict) else None
    targets = required if required else list(props.keys())

    out: dict[str, Any] = {}
    for name in targets:
        pdef = props.get(name)
        if not isinstance(pdef, dict):
            continue
        out[name] = _value_for(pdef)
    return out


# --- 3. Probe injection ----------------------------------------------------

def inject_probe(
    tool: ToolInfo,
    base_inputs: dict[str, Any],
    probe_value: str,
    target_param_type: str = "string",
    name_filter: tuple[str, ...] | None = None,
) -> dict[str, Any] | None:
    """Return a copy of *base_inputs* with one matching param replaced.

    Picks the first parameter whose declared type equals *target_param_type*.
    When *name_filter* is provided, the candidate must also have a parameter
    name containing one of those substrings (case-insensitive). Returns None
    if nothing matches — the detector should then skip this tool.
    """
    props = (tool.input_schema or {}).get("properties", {}) if isinstance(tool.input_schema, dict) else {}

    for pname in base_inputs:
        pdef = props.get(pname)
        if not isinstance(pdef, dict):
            continue
        if pdef.get("type") != target_param_type:
            continue
        if name_filter and not any(f in pname.lower() for f in name_filter):
            continue
        modified = dict(base_inputs)
        modified[pname] = probe_value
        return modified
    return None


# --- 4. Response text extraction ------------------------------------------

def extract_response_text(result: CallToolResult | None) -> str:
    """Concatenate the text from every text block in *result*; '' if no text."""
    if result is None:
        return ""
    content = getattr(result, "content", None) or []
    chunks: list[str] = []
    for block in content:
        if getattr(block, "type", None) == "text":
            text = getattr(block, "text", "") or ""
            if text:
                chunks.append(text)
    return "".join(chunks)


# --- 5. Rate-limited, bounded-latency tool call ---------------------------


async def rate_limited_call(
    session: ClientSession,
    tool_name: str,
    arguments: dict[str, Any],
    delay: float = 0.5,
    timeout: float = _DEFAULT_TIMEOUT_SEC,
) -> CallToolResult | None:
    """Call session.call_tool() with a bounded latency and a courtesy delay.

    Returns None on timeout so the scan keeps moving instead of blocking on a
    misbehaving tool. The *delay* sleep runs after every call (success, fail,
    or timeout) to avoid hammering the server.
    """
    try:
        return await asyncio.wait_for(
            session.call_tool(tool_name, arguments),
            timeout=timeout,
        )
    except asyncio.TimeoutError:
        return None
    finally:
        await asyncio.sleep(delay)
