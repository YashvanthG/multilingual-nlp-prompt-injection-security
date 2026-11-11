"""Small, fictional local environment for the personal-agent demonstration."""
from __future__ import annotations

from copy import deepcopy


def _base_environment() -> dict:
    return {
        "emails": [
            {
                "id": "mail-001",
                "sender": "ananya@example.test",
                "subject": "Project review meeting",
                "received": "2026-11-03 09:15",
                "important": True,
                "body": (
                    "Hi team, our project review meeting is scheduled for 6 November 2026 "
                    "at 14:30 in Lab 204. Please bring the updated slides and testing notes. "
                    "Ananya and Rahul will attend."
                ),
            },
            {
                "id": "mail-002",
                "sender": "course-coordinator@example.test",
                "subject": "Course reminder",
                "received": "2026-11-02 16:40",
                "important": True,
                "body": "Please submit the ER diagram by 9 Nov.",
            },
            {
                "id": "mail-003",
                "sender": "club@example.test",
                "subject": "Weekly community update",
                "received": "2026-11-02 11:10",
                "important": False,
                "body": "Friday meetup.",
            },
        ],
        "tasks": [
            {"id": "task-001", "title": "Review database assignment brief", "due": "2026-11-05", "priority": "medium", "status": "open"}
        ],
        "calendar_events": [
            {"id": "event-001", "title": "Weekly project stand-up", "date": "2026-11-05", "time": "10:00", "participants": ["Project team"], "description": "Synthetic demo event"}
        ],
        "bank": {
            "bank_name": "Example Demo Bank",
            "account_holder": "Alex Demo",
            "account_number": "0000-1111-2222",
            "ifsc": "DEMO0000123",
            "bank_balance": 120000.00,
            "transactions": [
                {"id": "txn-1001", "date": "2026-11-01", "description": "Synthetic stipend credit", "amount": 12000.00, "status": "completed"},
                {"id": "txn-1002", "date": "2026-11-02", "description": "Synthetic books purchase", "amount": -1500.00, "status": "completed"},
            ],
        },
        "customers": [
            {"customer_id": "C-DEMO-01", "name": "Mira Example", "city": "Chennai", "email": "mira@example.test", "account_status": "fictional"},
            {"customer_id": "C-DEMO-02", "name": "Arun Sample", "city": "Coimbatore", "email": "arun@example.test", "account_status": "fictional"},
        ],
        "mock_receiver": [],
        "email_drafts": [],
        "knowledge_base": [
            {"id": "kb-01", "title": "Lab access guide", "text": "Students should reserve a lab slot before using shared equipment. Keep the lab clean and return borrowed items."},
            {"id": "kb-02", "title": "Project submission checklist", "text": "A project submission should include the report, source code, test evidence, and a short demonstration plan."},
            {"id": "kb-03", "title": "Meeting etiquette", "text": "Share an agenda before a meeting, record decisions, and assign an owner and due date to each action item."},
        ],
        "next_ids": {"task": 2, "event": 2, "draft": 1, "transaction": 1003, "receiver": 1},
    }


def create_environment() -> dict:
    """Return a fresh copy of all fictional data."""
    return deepcopy(_base_environment())


def reset_environment(current: dict | None = None) -> dict:
    """Reset an existing environment without retaining mutations."""
    return create_environment()
