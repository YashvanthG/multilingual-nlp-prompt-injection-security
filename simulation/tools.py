from __future__ import annotations

import ast
import operator
from typing import Any

from guardrails.config import ALLOWED_TOOLS, TOOL_QUERY_MAX_CHARS

def _safe_calculate(expression: str) -> float | int:
    """Evaluate a small arithmetic expression without eval/exec."""
    operators = {
        ast.Add: operator.add, ast.Sub: operator.sub,
        ast.Mult: operator.mul, ast.Div: operator.truediv,
        ast.Pow: operator.pow, ast.USub: operator.neg,
        ast.UAdd: operator.pos, ast.Mod: operator.mod,
    }
    def visit(node):
        if isinstance(node, ast.Expression):
            return visit(node.body)
        if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
            return node.value
        if isinstance(node, ast.UnaryOp) and type(node.op) in operators:
            return operators[type(node.op)](visit(node.operand))
        if isinstance(node, ast.BinOp) and type(node.op) in operators:
            left, right = visit(node.left), visit(node.right)
            if isinstance(node.op, ast.Pow) and abs(right) > 8:
                raise ValueError("Exponent too large for demo calculator.")
            return operators[type(node.op)](left, right)
        raise ValueError("Only basic arithmetic is supported.")
    if len(expression) > 120:
        raise ValueError("Expression is too long.")
    return visit(ast.parse(expression, mode="eval"))

def execute_tool(action: dict[str, Any]) -> dict[str, Any]:
    """Run allow-listed, local-only tools. No live network or account access."""
    if not isinstance(action, dict):
        raise ValueError("Action must be an object.")
    tool = action.get("tool")
    args = action.get("arguments") or {}
    if not isinstance(args, dict):
        raise ValueError("Tool arguments must be an object.")
    if tool not in ALLOWED_TOOLS:
        raise PermissionError(f"Tool is not allow-listed: {tool!r}")
    if tool == "get_weather":
        city = str(args.get("city", "Unknown")).strip()[:80]
        if not city:
            raise ValueError("A city is required for the weather demo.")
        return {"city": city, "temperature_c": 24, "condition": "synthetic demonstration data"}
    if tool == "calculator":
        expression = str(args.get("expression", "")).strip()
        if not expression:
            raise ValueError("A calculator expression is required.")
        return {"result": _safe_calculate(expression)}
    query = str(args.get("query", "")).strip()
    if not query:
        raise ValueError("A query is required for the simulated lookup.")
    # Documents are never passed to tools; document questions are answered locally (simulation/extraction.py).
    return {"query": query[:TOOL_QUERY_MAX_CHARS], "summary": "Simulated lookup only: no live web access is connected."}

def simulated_sensitive_output() -> dict[str, Any]:
    """A deliberately fake payload for testing output inspection; not real credentials."""
    return {"status": "demo", "api_key": "FAKE-DEMO-KEY-NOT-A-CREDENTIAL"}
