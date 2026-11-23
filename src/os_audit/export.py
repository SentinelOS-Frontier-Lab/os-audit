"""Send a proof to a trace or a SIEM, with no dependency.

`to_otel(evidence)` gives the attributes of one span event for the call the proof is about. It follows the OpenTelemetry
GenAI semantic conventions for tool execution, pinned to open-telemetry/semantic-conventions-genai release v0.1.0
(21 November 2026, its first release), document docs/gen-ai/execute-tool.md (status: Development), which builds on the
core semantic conventions v1.45.0 (2 November 2026):
the span is `execute_tool {gen_ai.tool.name}`, with `gen_ai.operation.name` = "execute_tool", `gen_ai.tool.name` and,
when the provider gave one, `gen_ai.tool.call.id`. Only those three are written under `gen_ai.*`; everything OS-Audit
adds is under `os_audit.*`.

Private by default. Logs flow into systems many people can read: the export carries no argument value, no hidden
text and no secret, only the KIND of the value and a salted hash of it (the same value gives the same hash under the
same salt, so a SOC can join events without seeing the value). The convention itself marks `gen_ai.tool.call.arguments`
as opt-in and possibly sensitive. Raw values only with `include_values=True`; a secret is never exported, even then.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import re
from typing import Any

from .core import DATED, DICTATED, HANDED, NAMED, SCHEMA_VERSION, SECRET, Evidence

EVENT_NAME = "os_audit.evidence"
_REASON_CODE = {NAMED: "named", DICTATED: "dictated", DATED: "dated", HANDED: "handed", SECRET: "secret"}
_PROCESS_SALT = os.urandom(16)      # without the operator's salt, hashes join only within one process
_EMAIL = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")
_ACCOUNT = re.compile(r"[a-z]{2}\d{2}[a-z0-9]{8,30}|\d{5,}")
_DATE = re.compile(r"\d{4}-\d{2}-\d{2}")


def value_kind(evidence: Evidence) -> str:
    """What the value is, without saying what it is: secret, email, account, site, date, path or text."""
    v = evidence.value
    if evidence.reason == SECRET:
        return "secret"
    if evidence.reason == DATED or _DATE.fullmatch(v):
        return "date"
    if _EMAIL.fullmatch(v):
        return "email"
    if _ACCOUNT.fullmatch(v.replace(" ", "")):
        return "account"
    if v.startswith(("/", "~")):
        return "path"
    if "." in v and " " not in v:
        return "site"
    return "text"


def to_otel(evidence: Evidence, *, call_id: str | None = None, level: str | None = None, salt: bytes | None = None,
            include_values: bool = False) -> dict[str, Any]:
    """Attributes of the `os_audit.evidence` span event for one proof."""
    key = salt if salt is not None else _PROCESS_SALT
    attrs: dict[str, Any] = {"gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": evidence.tool}
    if call_id is not None:
        attrs["gen_ai.tool.call.id"] = str(call_id)
    attrs.update({
        "os_audit.schema_version": SCHEMA_VERSION,
        "os_audit.call": evidence.call,
        "os_audit.reason": _REASON_CODE.get(evidence.reason, "other"),
        "os_audit.acting": evidence.acting,
        "os_audit.egress": evidence.egress,
        "os_audit.decision": evidence.decision,
        "os_audit.value.kind": value_kind(evidence),
        "os_audit.value.hash": "hmac-sha256:" + hmac.new(key, evidence.value.encode("utf-8"), hashlib.sha256).hexdigest(),
    })
    if level is not None:
        attrs["os_audit.level"] = level
    if include_values and evidence.reason != SECRET:
        attrs["os_audit.value"] = evidence.value
    return attrs


def attach(span: Any, evidence: Evidence, **kwargs: Any) -> bool:
    """Add the proof to an OpenTelemetry span as an event. Without the `opentelemetry` package, does nothing."""
    try:
        import opentelemetry.trace  # noqa: F401  (only to know the SDK is there; OS-Audit never depends on it)
    except ImportError:
        return False
    if span is None or not hasattr(span, "add_event"):
        return False
    span.add_event(EVENT_NAME, attributes=to_otel(evidence, **kwargs))
    return True
