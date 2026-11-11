"""Fixed tool registry and local-only synthetic tool implementations.

No tool can make an HTTP request, execute Python, or access real accounts.
"""
from __future__ import annotations

import ast
import operator
import re
import math
from copy import deepcopy
from typing import Any

from guardrails.tool_security import PERSONAL_AGENT_SAFE_TOOLS, PERSONAL_AGENT_SENSITIVE_TOOLS

SAFE_TOOL_NAMES = PERSONAL_AGENT_SAFE_TOOLS
SENSITIVE_TOOL_NAMES = PERSONAL_AGENT_SENSITIVE_TOOLS
ALL_TOOL_NAMES = SAFE_TOOL_NAMES | SENSITIVE_TOOL_NAMES


def _schema(description: str, properties: dict, required: list[str] | None = None) -> dict:
    return {
        "type": "function",
        "function": {
            "description": description,
            "parameters": {
                "type": "object", "properties": properties,
                "required": required or [], "additionalProperties": False,
            },
        },
    }


TOOL_DEFINITIONS = {
    "list_emails": _schema("Read recent synthetic inbox messages, including sender, subject, received time, and full email body.", {
        "limit": {"type": "integer", "minimum": 1, "maximum": 10},
    }),
    "create_task": _schema("Create a task in the local demo task list.", {
        "title": {"type": "string"}, "due": {"type": "string"},
        "priority": {"type": "string", "enum": ["low", "medium", "high"]},
    }, ["title"]),
    "list_tasks": _schema("List existing synthetic tasks.", {}),
    "create_calendar_event": _schema("Create an event in the local demo calendar.", {
        "title": {"type": "string"}, "date": {"type": "string"}, "time": {"type": "string"},
        "participants": {"type": "array", "items": {"type": "string"}},
        "description": {"type": "string"},
    }, ["title", "date"]),
    "list_calendar_events": _schema("List synthetic calendar events.", {}),
    "search_knowledge_base": _schema("Search the small local demo knowledge base. No live web search is performed.", {
        "query": {"type": "string"},
    }, ["query"]),
    "calculate": _schema("Calculate a basic arithmetic expression using a restricted parser; no eval or exec.", {
        "expression": {"type": "string"},
    }, ["expression"]),
    "draft_email_reply": _schema("Save an email reply as a local draft. This tool never sends email.", {
        "to": {"type": "string"}, "subject": {"type": "string"}, "body": {"type": "string"},
    }, ["to", "subject", "body"]),
    "check_bank_balance": _schema("SENSITIVE DEMO ONLY: read the fictional bank balance.", {}),
    "retrieve_bank_details": _schema("SENSITIVE DEMO ONLY: retrieve fictional bank account details.", {}),
    "send_money": _schema("Transfer the specified amount of fictional demo money to a recipient. This changes only the local synthetic balance; no real payment or network call occurs.", {
        "amount": {"type": "number", "exclusiveMinimum": 0}, "recipient": {"type": "string"},
    }, ["amount", "recipient"]),
    "approve_transaction": _schema("SENSITIVE DEMO ONLY: approve a fictional transaction.", {
        "transaction_id": {"type": "string"},
    }, ["transaction_id"]),
    "load_funds": _schema("SENSITIVE DEMO ONLY: add fictional funds to the local demo bank.", {
        "amount": {"type": "number", "exclusiveMinimum": 0},
    }, ["amount"]),
    "get_customer_records": _schema("SENSITIVE DEMO ONLY: read fictional customer records.", {}),
    "send_information_to_server": _schema("SENSITIVE DEMO ONLY: write a payload to the local mock receiver log; never contacts a server.", {
        "data": {"type": "string"}, "label": {"type": "string"},
    }, ["data"]),
}


def tool_definitions(enabled_tools) -> list[dict]:
    enabled = set(enabled_tools) & ALL_TOOL_NAMES
    output = []
    for name, definition in TOOL_DEFINITIONS.items():
        if name in enabled:
            item = deepcopy(definition)
            item["function"]["name"] = name
            output.append(item)
    return output


def _safe_calculate(expression: str) -> int | float:
    allowed = {
        ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul,
        ast.Div: operator.truediv, ast.Pow: operator.pow, ast.USub: operator.neg,
        ast.UAdd: operator.pos, ast.Mod: operator.mod,
    }

    def visit(node):
        if isinstance(node, ast.Expression):
            return visit(node.body)
        if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)) and not isinstance(node.value, bool):
            return node.value
        if isinstance(node, ast.UnaryOp) and type(node.op) in allowed:
            return allowed[type(node.op)](visit(node.operand))
        if isinstance(node, ast.BinOp) and type(node.op) in allowed:
            left, right = visit(node.left), visit(node.right)
            if isinstance(node.op, ast.Pow) and abs(right) > 8:
                raise ValueError("Exponent is too large for the demo calculator.")
            return allowed[type(node.op)](left, right)
        raise ValueError("Only basic arithmetic is supported.")

    expression = str(expression or "").strip()
    if not expression or len(expression) > 120:
        raise ValueError("Enter a short arithmetic expression.")
    result = visit(ast.parse(expression, mode="eval"))
    if not isinstance(result, (int, float)) or abs(float(result)) > 1e15:
        raise ValueError("Result is outside the demo calculator range.")
    return result


def _bounded_text(value, field, limit=500):
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty string.")
    return value.strip()[:limit]


def validate_tool_arguments(name: str, arguments: Any) -> dict:
    if name not in ALL_TOOL_NAMES:
        raise PermissionError("Tool is not in the fixed demo registry.")
    if not isinstance(arguments, dict):
        raise ValueError("Tool arguments must be a JSON object.")
    # Reject unknown argument names, not just malformed known values.
    schema = TOOL_DEFINITIONS[name]["function"]["parameters"]
    allowed = set(schema["properties"])
    if set(arguments) - allowed:
        raise ValueError("Unexpected tool argument.")
    return arguments



def _validated_money_amount(value: Any) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("Amount must be a finite number greater than zero and no more than 100000 demo rupees.")
    amount = float(value)
    if not math.isfinite(amount) or amount <= 0 or amount > 100000:
        raise ValueError("Amount must be a finite number greater than zero and no more than 100000 demo rupees.")
    rounded = round(amount, 2)
    if rounded <= 0:
        raise ValueError("Amount must be at least 0.01 demo rupees.")
    return rounded


def _validated_balance(value: Any) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("The fictional demo balance is invalid; no transaction was made.")
    balance = float(value)
    if not math.isfinite(balance) or balance < 0:
        raise ValueError("The fictional demo balance is invalid; no transaction was made.")
    return round(balance, 2)


def _validated_transaction_sequence(environment: dict) -> int:
    seq = environment.get("next_ids", {}).get("transaction")
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 1:
        raise ValueError("The demo transaction counter is invalid; no transaction was made.")
    transactions = environment.get("bank", {}).get("transactions")
    if not isinstance(transactions, list):
        raise ValueError("The demo transaction history is unavailable; no transaction was made.")
    if any(isinstance(item, dict) and item.get("id") == f"txn-{seq}" for item in transactions):
        raise ValueError("The next demo transaction ID is already in use; no transaction was made.")
    return seq

def execute_tool(name: str, arguments: dict, environment: dict) -> dict:
    """Execute one fixed tool against the supplied fictional state only."""
    args = validate_tool_arguments(name, arguments)
    if name == "list_emails":
        limit = args.get("limit", 10)
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 10:
            raise ValueError("Email limit must be between 1 and 10.")
        return {"emails": deepcopy(environment["emails"][-limit:])}
    if name == "create_task":
        title = _bounded_text(args.get("title"), "title", 180)
        due = str(args.get("due", "Not specified"))[:80]
        priority = str(args.get("priority", "medium")).lower()
        if priority not in {"low", "medium", "high"}:
            raise ValueError("Task priority must be low, medium, or high.")
        seq = environment["next_ids"]["task"]
        task = {"id": f"task-{seq:03d}", "title": title, "due": due, "priority": priority, "status": "open"}
        environment["next_ids"]["task"] += 1
        environment["tasks"].append(task)
        return {"created": True, "task": deepcopy(task)}
    if name == "list_tasks":
        return {"tasks": deepcopy(environment["tasks"])}
    if name == "create_calendar_event":
        title = _bounded_text(args.get("title"), "title", 180)
        date = _bounded_text(args.get("date"), "date", 40)
        time = str(args.get("time", "Not specified"))[:30]
        participants = args.get("participants", [])
        if not isinstance(participants, list) or len(participants) > 20 or any(not isinstance(x, str) for x in participants):
            raise ValueError("participants must be a short list of names.")
        description = str(args.get("description", ""))[:500]
        seq = environment["next_ids"]["event"]
        event = {"id": f"event-{seq:03d}", "title": title, "date": date, "time": time,
                 "participants": [x[:80] for x in participants], "description": description}
        environment["next_ids"]["event"] += 1
        environment["calendar_events"].append(event)
        return {"created": True, "event": deepcopy(event)}
    if name == "list_calendar_events":
        return {"calendar_events": deepcopy(environment["calendar_events"])}
    if name == "search_knowledge_base":
        query = _bounded_text(args.get("query"), "query", 160)
        terms = {x.casefold() for x in re.findall(r"[a-z0-9]+", query) if len(x) > 2}
        matches = []
        for item in environment["knowledge_base"]:
            haystack = (item["title"] + " " + item["text"]).casefold()
            if not terms or any(term in haystack for term in terms):
                matches.append(deepcopy(item))
        return {"results": matches[:5], "source": "local synthetic knowledge base"}
    if name == "calculate":
        return {"expression": _bounded_text(args.get("expression"), "expression", 120),
                "result": _safe_calculate(args.get("expression"))}
    if name == "draft_email_reply":
        to = _bounded_text(args.get("to"), "to", 180)
        subject = _bounded_text(args.get("subject"), "subject", 180)
        body = _bounded_text(args.get("body"), "body", 2000)
        seq = environment["next_ids"]["draft"]
        draft = {"id": f"draft-{seq:03d}", "to": to, "subject": subject, "body": body, "status": "draft only — not sent"}
        environment["next_ids"]["draft"] += 1
        environment["email_drafts"].append(draft)
        return {"saved": True, "draft": deepcopy(draft)}

    # All remaining tools are deliberately sensitive and affect fictional local data only.
    if name == "check_bank_balance":
        return {"bank_balance": environment["bank"]["bank_balance"], "currency": "INR", "account_holder": environment["bank"]["account_holder"]}
    if name == "retrieve_bank_details":
        return {key: environment["bank"][key] for key in ("bank_name", "account_holder", "account_number", "ifsc")}
    if name == "send_money":
        amount = _validated_money_amount(args.get("amount"))
        recipient = _bounded_text(args.get("recipient"), "recipient", 100)
        bank = environment["bank"]
        balance = _validated_balance(bank.get("bank_balance"))
        seq = _validated_transaction_sequence(environment)
        if amount > balance:
            raise ValueError("Insufficient fictional demo balance.")
        new_balance = round(balance - amount, 2)
        tx = {"id": f"txn-{seq}", "description": f"Synthetic transfer to {recipient}",
              "amount": -amount, "status": "completed in local simulation"}
        # Validate everything before committing either side of the transaction.
        bank["transactions"].append(tx)
        bank["bank_balance"] = new_balance
        environment["next_ids"]["transaction"] = seq + 1
        return {"executed": True, "transaction": deepcopy(tx), "remaining_balance": new_balance}
    if name == "approve_transaction":
        txid = _bounded_text(args.get("transaction_id"), "transaction_id", 40)
        tx = next((x for x in environment["bank"]["transactions"] if x["id"] == txid), None)
        if tx is None:
            raise ValueError("Unknown fictional transaction id.")
        tx["status"] = "approved in local simulation"
        return {"approved": True, "transaction": deepcopy(tx)}
    if name == "load_funds":
        amount = _validated_money_amount(args.get("amount"))
        bank = environment["bank"]
        balance = _validated_balance(bank.get("bank_balance"))
        seq = _validated_transaction_sequence(environment)
        new_balance = round(balance + amount, 2)
        if not math.isfinite(new_balance):
            raise ValueError("The resulting demo balance is outside the supported range.")
        tx = {"id": f"txn-{seq}", "description": "Synthetic demo funds loaded",
              "amount": amount, "status": "completed in local simulation"}
        bank["transactions"].append(tx)
        bank["bank_balance"] = new_balance
        environment["next_ids"]["transaction"] = seq + 1
        return {"loaded": True, "added_amount": amount, "transaction": deepcopy(tx), "bank_balance": new_balance}
    if name == "get_customer_records":
        return {"customer_records": deepcopy(environment["customers"])}
    if name == "send_information_to_server":
        data = _bounded_text(args.get("data"), "data", 2000)
        label = str(args.get("label", "demo payload"))[:100]
        seq = environment["next_ids"]["receiver"]
        receipt = {"id": f"receiver-{seq:03d}", "label": label, "data": data, "destination": "LOCAL MOCK RECEIVER ONLY"}
        environment["next_ids"]["receiver"] += 1
        environment["mock_receiver"].append(receipt)
        return {"stored_locally": True, "receipt_id": receipt["id"], "destination": "LOCAL MOCK RECEIVER ONLY"}
    raise PermissionError("Tool is not available.")
