"""AGENTTAX MCP server — exposes classification as an MCP capability.

Two backends:

  * If the Cognis suite helper ``cognis_core.mcp`` is importable, it is used
    (matches the rest of the suite).
  * Otherwise a self-contained, standard-library JSON-RPC-over-stdio MCP
    server is used so the tool works anywhere with zero pip dependencies.

The server advertises two tools:
  * ``agenttax_classify``  — classify findings text / JSON into the taxonomy.
  * ``agenttax_taxonomy``  — return the full taxonomy + mitigations.
"""

from __future__ import annotations

import json
import sys
from typing import Any, Dict

from agenttax.core import (
    TOOL_NAME,
    TOOL_VERSION,
    classify_findings,
    findings_from_text,
    get_taxonomy,
    normalize_findings,
)


def _classify_payload(arguments: Dict[str, Any]) -> Dict[str, Any]:
    text = arguments.get("text")
    findings_arg = arguments.get("findings")

    raw_conf = arguments.get("min_confidence", 0.0)
    try:
        min_conf = float(raw_conf if raw_conf is not None else 0.0)
    except (TypeError, ValueError):
        return {"error": f"min_confidence must be a number, got {raw_conf!r}"}
    min_conf = max(0.0, min(1.0, min_conf))

    if text:
        findings = findings_from_text(str(text))
        source = "<text>"
    elif findings_arg is not None:
        try:
            findings = normalize_findings(findings_arg)
        except Exception as exc:
            return {"error": f"invalid findings: {exc}"}
        source = "<findings>"
    else:
        return {"error": "provide 'text' or 'findings'"}
    report = classify_findings(findings, source=source, min_confidence=min_conf)
    return report.to_dict()


_TOOLS = [
    {
        "name": "agenttax_classify",
        "description": "Classify security findings against Microsoft's AI-agent "
                       "threat taxonomy (7 categories) with confidence + mitigations.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "text": {"type": "string",
                         "description": "Free-text observation(s) to classify."},
                "findings": {"type": "array",
                             "description": "Findings array (objects or strings)."},
                "min_confidence": {"type": "number",
                                   "description": "Drop matches below this (0-1)."},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "agenttax_taxonomy",
        "description": "Return the full Microsoft AI-agent threat taxonomy with "
                       "per-category mitigations.",
        "inputSchema": {"type": "object", "properties": {},
                        "additionalProperties": False},
    },
]


def _dispatch(name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
    if name == "agenttax_classify":
        return _classify_payload(arguments or {})
    if name == "agenttax_taxonomy":
        return {"taxonomy": get_taxonomy()}
    return {"error": f"unknown tool: {name}"}


# --------------------------------------------------------------------------
# Stdlib JSON-RPC / MCP stdio loop (fallback backend).
# --------------------------------------------------------------------------
def _serve_stdio() -> None:
    def reply(rid: Any, result: Any) -> None:
        sys.stdout.write(json.dumps(
            {"jsonrpc": "2.0", "id": rid, "result": result}) + "\n")
        sys.stdout.flush()

    def err(rid: Any, code: int, message: str) -> None:
        sys.stdout.write(json.dumps(
            {"jsonrpc": "2.0", "id": rid,
             "error": {"code": code, "message": message}}) + "\n")
        sys.stdout.flush()

    try:
      for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            err(None, -32700, "parse error")
            continue

        if not isinstance(req, dict):
            err(None, -32600, "request must be a JSON object")
            continue

        method = req.get("method")
        rid = req.get("id")
        params = req.get("params") or {}

        if method == "initialize":
            reply(rid, {
                "protocolVersion": "2024-11-05",
                "serverInfo": {"name": TOOL_NAME, "version": TOOL_VERSION},
                "capabilities": {"tools": {}},
            })
        elif method == "tools/list":
            reply(rid, {"tools": _TOOLS})
        elif method == "tools/call":
            name = params.get("name", "")
            arguments = params.get("arguments") or {}
            try:
                result = _dispatch(name, arguments)
                reply(rid, {"content": [
                    {"type": "text",
                     "text": json.dumps(result, indent=2)}]})
            except Exception as exc:  # pragma: no cover - defensive
                err(rid, -32000, f"tool error: {exc}")
        elif method in ("notifications/initialized", "initialized"):
            continue  # notification, no response
        elif method == "ping":
            reply(rid, {})
        elif method == "shutdown":
            reply(rid, {})
            break
        else:
            if rid is not None:
                err(rid, -32601, f"method not found: {method}")
    except BrokenPipeError:
        pass  # client disconnected cleanly


def run_mcp_server() -> None:
    try:  # prefer the suite helper if present
        from cognis_core.mcp import build_mcp_server  # type: ignore

        from agenttax.core import scan
        build_mcp_server(
            tool_name=TOOL_NAME,
            description="Classify findings against Microsoft's AI-agent threat "
                        "taxonomy with mitigations",
            scan_fn=scan,
        )()
        return
    except Exception:
        pass
    _serve_stdio()


if __name__ == "__main__":
    run_mcp_server()
